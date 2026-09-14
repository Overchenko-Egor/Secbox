"""Persistent observable runtime state for the VPN pool."""

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field

from secbox.modules.vpn.controller import ControllerResult


DEFAULT_RUNTIME_PATH = Path(
    "/var/lib/secbox/vpn-runtime.json"
)
DEFAULT_EVENTS_PATH = Path(
    "/var/lib/secbox/vpn-events.jsonl"
)


class VpnRuntimeError(RuntimeError):
    """Raised when VPN observable runtime state cannot be handled."""


class VpnTunnelRuntime(BaseModel):
    name: str
    interface: str
    status: str
    peer_present: bool
    handshake_age_seconds: float | None = None
    rx_bytes: int = 0
    tx_bytes: int = 0
    probe_ok: bool | None = None
    latency_ms: float | None = None
    reason: str


class VpnRuntimeState(BaseModel):
    observed_at: datetime
    active_interface: str | None
    reason: str
    tunnels: list[VpnTunnelRuntime] = Field(
        default_factory=list
    )


class VpnSwitchEvent(BaseModel):
    occurred_at: datetime
    from_interface: str | None
    to_interface: str | None
    reason: str


def runtime_from_result(
    result: ControllerResult,
    *,
    observed_at: datetime | None = None,
) -> VpnRuntimeState:
    """Build observable runtime state from one controller cycle."""

    timestamp = observed_at or datetime.now(UTC)

    tunnels = [
        VpnTunnelRuntime(
            name=snapshot.name,
            interface=snapshot.interface,
            status=snapshot.status.value,
            peer_present=snapshot.peer_present,
            handshake_age_seconds=(
                snapshot.handshake_age_seconds
            ),
            rx_bytes=snapshot.rx_bytes,
            tx_bytes=snapshot.tx_bytes,
            probe_ok=snapshot.probe_ok,
            latency_ms=snapshot.latency_ms,
            reason=snapshot.reason,
        )
        for snapshot in result.health.values()
    ]

    tunnels.sort(
        key=lambda tunnel: tunnel.interface
    )

    return VpnRuntimeState(
        observed_at=timestamp,
        active_interface=result.active_after,
        reason=result.reason,
        tunnels=tunnels,
    )


class VpnRuntimeStore:
    """Load and atomically save observable VPN runtime state."""

    def __init__(
        self,
        path: Path = DEFAULT_RUNTIME_PATH,
    ) -> None:
        self.path = path

    def load(self) -> VpnRuntimeState | None:
        if not self.path.exists():
            return None

        try:
            data = json.loads(
                self.path.read_text()
            )
            return VpnRuntimeState.model_validate(
                data
            )
        except (
            OSError,
            json.JSONDecodeError,
            ValueError,
        ) as error:
            raise VpnRuntimeError(
                f"failed to load VPN runtime state: {error}"
            ) from error

    def save(
        self,
        state: VpnRuntimeState,
    ) -> None:
        try:
            self.path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            temporary = self.path.with_name(
                f".{self.path.name}.{os.getpid()}.tmp"
            )

            payload = state.model_dump_json(
                indent=2
            ) + "\n"

            temporary.write_text(
                payload
            )

            os.replace(
                temporary,
                self.path,
            )

        except OSError as error:
            raise VpnRuntimeError(
                f"failed to save VPN runtime state: {error}"
            ) from error


class VpnEventStore:
    """Append and read VPN switch events."""

    def __init__(
        self,
        path: Path = DEFAULT_EVENTS_PATH,
    ) -> None:
        self.path = path

    def append(
        self,
        event: VpnSwitchEvent,
    ) -> None:
        try:
            self.path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            with self.path.open(
                "a",
                encoding="utf-8",
            ) as stream:
                stream.write(
                    event.model_dump_json()
                    + "\n"
                )

        except OSError as error:
            raise VpnRuntimeError(
                f"failed to append VPN event: {error}"
            ) from error

    def load_recent(
        self,
        limit: int = 50,
    ) -> list[VpnSwitchEvent]:
        if limit < 1 or limit > 500:
            raise ValueError(
                "VPN event limit must be between 1 and 500"
            )

        if not self.path.exists():
            return []

        try:
            lines = self.path.read_text(
                encoding="utf-8"
            ).splitlines()
        except OSError as error:
            raise VpnRuntimeError(
                f"failed to load VPN events: {error}"
            ) from error

        events: list[VpnSwitchEvent] = []

        try:
            for line in lines[-limit:]:
                if not line.strip():
                    continue

                events.append(
                    VpnSwitchEvent.model_validate_json(
                        line
                    )
                )
        except ValueError as error:
            raise VpnRuntimeError(
                f"failed to parse VPN events: {error}"
            ) from error

        events.reverse()

        return events


def switch_event_from_result(
    result: ControllerResult,
    *,
    occurred_at: datetime | None = None,
) -> VpnSwitchEvent:
    """Build an event for a real controller switch."""

    if not result.switched:
        raise ValueError(
            "controller result does not contain a VPN switch"
        )

    return VpnSwitchEvent(
        occurred_at=occurred_at or datetime.now(UTC),
        from_interface=result.active_before,
        to_interface=result.active_after,
        reason=result.reason,
    )
