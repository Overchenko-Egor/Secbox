"""Discovery of Linux network interfaces."""

import json
import subprocess
from typing import Any

from secbox.modules.network.state import (
    NetworkAddress,
    NetworkInterfaceState,
)


class NetworkDiscoveryError(Exception):
    """Raised when network interface discovery fails."""


def discover_interfaces() -> list[NetworkInterfaceState]:
    """Return the current state of all Linux network interfaces."""

    try:
        result = subprocess.run(
            ["ip", "-json", "address", "show"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise NetworkDiscoveryError(
            f"failed to discover network interfaces: {error}"
        ) from error

    try:
        raw_interfaces = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise NetworkDiscoveryError(
            f"invalid JSON returned by iproute2: {error}"
        ) from error

    if not isinstance(raw_interfaces, list):
        raise NetworkDiscoveryError("unexpected iproute2 JSON structure")

    interfaces: list[NetworkInterfaceState] = []

    for raw_interface in raw_interfaces:
        if not isinstance(raw_interface, dict):
            continue

        interfaces.append(_parse_interface(raw_interface))

    return interfaces


def discover_manageable_interfaces() -> list[NetworkInterfaceState]:
    """Return interfaces that may be managed by SecBox."""

    return [
        interface
        for interface in discover_interfaces()
        if not interface.is_loopback
    ]


def _parse_interface(
    raw_interface: dict[str, Any],
) -> NetworkInterfaceState:
    addresses: list[NetworkAddress] = []

    raw_addresses = raw_interface.get("addr_info", [])

    if isinstance(raw_addresses, list):
        for raw_address in raw_addresses:
            if not isinstance(raw_address, dict):
                continue

            family = raw_address.get("family")
            local = raw_address.get("local")
            prefixlen = raw_address.get("prefixlen")

            if not isinstance(family, str):
                continue

            if not isinstance(local, str):
                continue

            if not isinstance(prefixlen, int):
                continue

            scope = raw_address.get("scope")

            addresses.append(
                NetworkAddress(
                    family=family,
                    address=local,
                    prefixlen=prefixlen,
                    scope=scope if isinstance(scope, str) else None,
                )
            )

    flags_raw = raw_interface.get("flags", [])

    flags = [
        flag
        for flag in flags_raw
        if isinstance(flag, str)
    ] if isinstance(flags_raw, list) else []

    name = raw_interface.get("ifname")

    if not isinstance(name, str):
        raise NetworkDiscoveryError(
            "interface entry does not contain a valid ifname"
        )

    mtu = raw_interface.get("mtu")

    if not isinstance(mtu, int):
        raise NetworkDiscoveryError(
            f"interface {name} does not contain a valid MTU"
        )

    operstate = raw_interface.get("operstate")

    if not isinstance(operstate, str):
        operstate = "UNKNOWN"

    mac_raw = raw_interface.get("address")

    mac = mac_raw if isinstance(mac_raw, str) else None

    return NetworkInterfaceState(
        name=name,
        mac=mac,
        mtu=mtu,
        operstate=operstate,
        flags=flags,
        addresses=addresses,
        is_loopback="LOOPBACK" in flags or name == "lo",
    )
