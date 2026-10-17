"""Safe runtime metadata for SecBox-managed network interfaces."""

import json
import os
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from secbox.modules.network.models import (
    InterfaceRole,
    IPv4Method,
    NetworkConfig,
)
from secbox.modules.network.state import NetworkInterfaceState


DEFAULT_RUNTIME_PATH = Path("/var/lib/secbox/network-runtime.json")


class NetworkRuntimeError(RuntimeError):
    """Raised when network runtime metadata cannot be read or written."""


class NetworkManagedInterface(BaseModel):
    """Safe persisted metadata for one SecBox-managed interface."""

    model_config = ConfigDict(extra="forbid")

    name: str
    role: InterfaceRole
    ipv4_method: IPv4Method


class NetworkRuntimeMetadata(BaseModel):
    """Persisted non-secret network metadata."""

    model_config = ConfigDict(extra="forbid")

    interfaces: list[NetworkManagedInterface] = Field(default_factory=list)


class NetworkInterfaceStatus(BaseModel):
    """Current status of one SecBox-managed interface."""

    model_config = ConfigDict(extra="forbid")

    name: str
    role: InterfaceRole
    ipv4_method: IPv4Method
    configured: bool
    operstate: str
    addresses: list[str] = Field(default_factory=list)


class NetworkStatus(BaseModel):
    """Current status of all SecBox-managed interfaces."""

    model_config = ConfigDict(extra="forbid")

    interfaces: list[NetworkInterfaceStatus] = Field(default_factory=list)


def metadata_from_config(
    config: NetworkConfig,
) -> NetworkRuntimeMetadata:
    """Build safe persisted metadata from network configuration."""

    return NetworkRuntimeMetadata(
        interfaces=[
            NetworkManagedInterface(
                name=interface.name,
                role=interface.role,
                ipv4_method=interface.ipv4_method,
            )
            for interface in config.interfaces
        ]
    )


def build_network_status(
    metadata: NetworkRuntimeMetadata,
    runtime_interfaces: list[NetworkInterfaceState],
) -> NetworkStatus:
    """Merge configured interface roles with live kernel state."""

    runtime_by_name = {
        interface.name: interface
        for interface in runtime_interfaces
    }

    statuses: list[NetworkInterfaceStatus] = []

    for managed in metadata.interfaces:
        runtime = runtime_by_name.get(managed.name)

        if runtime is None:
            statuses.append(
                NetworkInterfaceStatus(
                    name=managed.name,
                    role=managed.role,
                    ipv4_method=managed.ipv4_method,
                    configured=managed.ipv4_method != "disabled",
                    operstate="MISSING",
                    addresses=[],
                )
            )
            continue

        addresses = [
            f"{address.address}/{address.prefixlen}"
            for address in runtime.addresses
            if address.family == "inet"
        ]

        statuses.append(
            NetworkInterfaceStatus(
                name=managed.name,
                role=managed.role,
                ipv4_method=managed.ipv4_method,
                configured=managed.ipv4_method != "disabled",
                operstate=runtime.operstate,
                addresses=addresses,
            )
        )

    return NetworkStatus(interfaces=statuses)


class NetworkRuntimeStore:
    """Persist safe network metadata atomically."""

    def __init__(
        self,
        path: Path = DEFAULT_RUNTIME_PATH,
    ) -> None:
        self.path = path

    def load(self) -> NetworkRuntimeMetadata | None:
        if not self.path.exists():
            return None

        try:
            raw = json.loads(
                self.path.read_text(encoding="utf-8")
            )
            return NetworkRuntimeMetadata.model_validate(raw)
        except (OSError, json.JSONDecodeError, ValueError) as error:
            raise NetworkRuntimeError(
                f"failed to read network runtime metadata: {error}"
            ) from error

    def save(
        self,
        metadata: NetworkRuntimeMetadata,
    ) -> None:
        try:
            self.path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            temporary = self.path.with_name(
                f".{self.path.name}.{os.getpid()}.tmp"
            )

            temporary.write_text(
                metadata.model_dump_json(indent=2) + "\n",
                encoding="utf-8",
            )

            # SECBOX_WEB_READABLE_RUNTIME
            Path(temporary).chmod(0o644)
            os.replace(
                temporary,
                self.path,
            )
            Path(self.path).chmod(0o644)
        except OSError as error:
            raise NetworkRuntimeError(
                f"failed to write network runtime metadata: {error}"
            ) from error
