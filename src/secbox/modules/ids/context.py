"""Build IDS network context from SecBox configuration and runtime state."""

import ipaddress

from secbox.core.models import SecBoxConfig
from secbox.modules.ids.classification import (
    IdsNetworkContext,
)
from secbox.modules.network.state import (
    NetworkInterfaceState,
)


class IdsContextError(Exception):
    """Raised when IDS network context cannot be built."""


def find_interface_by_role(
    config: SecBoxConfig,
    role: str,
) -> str:
    """Return the unique interface configured for a role."""

    matching_interfaces = [
        interface.name
        for interface in config.network.interfaces
        if interface.role == role
    ]

    if not matching_interfaces:
        raise IdsContextError(
            f"no {role} interface is configured"
        )

    if len(matching_interfaces) > 1:
        raise IdsContextError(
            f"multiple {role} interfaces are not "
            "supported by IDS yet"
        )

    return matching_interfaces[0]


def find_runtime_interface(
    interfaces: list[NetworkInterfaceState],
    name: str,
) -> NetworkInterfaceState:
    """Return runtime state for an interface."""

    for interface in interfaces:
        if interface.name == name:
            return interface

    raise IdsContextError(
        f"configured interface is missing "
        f"from runtime state: {name}"
    )


def get_runtime_ipv4_addresses(
    interface: NetworkInterfaceState,
) -> tuple[ipaddress.IPv4Address, ...]:
    """Return global IPv4 addresses observed on an interface."""

    addresses: list[ipaddress.IPv4Address] = []

    for address in interface.addresses:
        if address.family != "inet":
            continue

        try:
            parsed = ipaddress.ip_address(
                address.address
            )
        except ValueError as error:
            raise IdsContextError(
                "invalid runtime IPv4 address "
                f"on {interface.name}: "
                f"{address.address}"
            ) from error

        if not isinstance(
            parsed,
            ipaddress.IPv4Address,
        ):
            continue

        addresses.append(parsed)

    return tuple(addresses)


def get_lan_ipv4_networks(
    config: SecBoxConfig,
    lan_interface: str,
) -> tuple[ipaddress.IPv4Network, ...]:
    """Return IPv4 networks configured on the LAN interface."""

    networks: list[ipaddress.IPv4Network] = []

    for interface in config.network.interfaces:
        if interface.name != lan_interface:
            continue

        if interface.ipv4_method != "static":
            raise IdsContextError(
                "IDS currently requires a static "
                f"LAN IPv4 configuration: {lan_interface}"
            )

        if interface.ipv4_address is None:
            raise IdsContextError(
                f"LAN interface has no IPv4 address: "
                f"{lan_interface}"
            )

        networks.append(
            interface.ipv4_address.network
        )

    if not networks:
        raise IdsContextError(
            f"no IPv4 network found for LAN "
            f"interface: {lan_interface}"
        )

    return tuple(networks)


def build_ids_network_context(
    config: SecBoxConfig,
    runtime_interfaces: list[
        NetworkInterfaceState
    ],
) -> IdsNetworkContext:
    """Build IDS context from config and runtime network state."""

    wan_interface = find_interface_by_role(
        config,
        "wan",
    )

    lan_interface = find_interface_by_role(
        config,
        "lan",
    )

    runtime_wan = find_runtime_interface(
        runtime_interfaces,
        wan_interface,
    )

    find_runtime_interface(
        runtime_interfaces,
        lan_interface,
    )

    wan_ipv4_addresses = (
        get_runtime_ipv4_addresses(
            runtime_wan
        )
    )

    if not wan_ipv4_addresses:
        raise IdsContextError(
            f"WAN interface has no runtime IPv4 "
            f"address: {wan_interface}"
        )

    lan_ipv4_networks = (
        get_lan_ipv4_networks(
            config,
            lan_interface,
        )
    )

    return IdsNetworkContext(
        wan_interface=wan_interface,
        lan_interface=lan_interface,
        wan_ipv4_addresses=wan_ipv4_addresses,
        lan_ipv4_networks=lan_ipv4_networks,
    )
