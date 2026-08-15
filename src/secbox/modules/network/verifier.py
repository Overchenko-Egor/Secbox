"""Verification of applied network configuration."""

from ipaddress import IPv4Interface

from secbox.modules.network.models import (
    NetworkConfig,
    NetworkInterfaceConfig,
)
from secbox.modules.network.state import NetworkInterfaceState
from secbox.modules.network.routes import NetworkRoute

class NetworkVerificationError(Exception):
    """Raised when runtime network state does not match configuration."""


def verify_network_config(
    config: NetworkConfig,
    runtime_interfaces: list[NetworkInterfaceState],
    runtime_routes: list[NetworkRoute] | None = None,
) -> None:
    """Verify that runtime interface state matches desired configuration."""

    runtime_by_name = {
        interface.name: interface
        for interface in runtime_interfaces
    }

    for configured_interface in config.interfaces:
        runtime_interface = runtime_by_name.get(
            configured_interface.name
        )

        if runtime_interface is None:
            raise NetworkVerificationError(
                f"interface disappeared after apply: "
                f"{configured_interface.name}"
            )

        _verify_interface(
            configured_interface,
            runtime_interface,
        )
    if runtime_routes is not None:
        _verify_routing(
            config,
            runtime_routes,
        )

def _verify_interface(
    configured: NetworkInterfaceConfig,
    runtime: NetworkInterfaceState,
) -> None:
    """Verify one configured interface."""

    if configured.ipv4_method == "static":
        _verify_static_ipv4(
            configured,
            runtime,
        )

    elif configured.ipv4_method == "dhcp":
        _verify_dhcp_ipv4(
            configured,
            runtime,
        )

    elif configured.ipv4_method == "disabled":
        _verify_disabled_ipv4(
            configured,
            runtime,
        )


def _runtime_ipv4_addresses(
    interface: NetworkInterfaceState,
) -> list[IPv4Interface]:
    """Return runtime IPv4 addresses."""

    addresses: list[IPv4Interface] = []

    for address in interface.addresses:
        if address.family != "inet":
            continue

        addresses.append(
            IPv4Interface(
                f"{address.address}/{address.prefixlen}"
            )
        )

    return addresses


def _verify_static_ipv4(
    configured: NetworkInterfaceConfig,
    runtime: NetworkInterfaceState,
) -> None:
    """Verify static IPv4 address."""

    expected = configured.ipv4_address

    if expected is None:
        raise NetworkVerificationError(
            f"static interface has no expected address: {configured.name}"
        )

    runtime_addresses = _runtime_ipv4_addresses(runtime)

    if expected not in runtime_addresses:
        actual = ", ".join(
            str(address)
            for address in runtime_addresses
        ) or "none"

        raise NetworkVerificationError(
            f"interface {configured.name} does not have expected "
            f"IPv4 address {expected}; actual: {actual}"
        )


def _verify_dhcp_ipv4(
    configured: NetworkInterfaceConfig,
    runtime: NetworkInterfaceState,
) -> None:
    """Verify that DHCP produced at least one IPv4 address."""

    runtime_addresses = _runtime_ipv4_addresses(runtime)

    if not runtime_addresses:
        raise NetworkVerificationError(
            f"DHCP interface {configured.name} has no IPv4 address"
        )


def _verify_disabled_ipv4(
    configured: NetworkInterfaceConfig,
    runtime: NetworkInterfaceState,
) -> None:
    """Verify that an IPv4-disabled interface has no IPv4 addresses."""

    runtime_addresses = _runtime_ipv4_addresses(runtime)

    if runtime_addresses:
        actual = ", ".join(
            str(address)
            for address in runtime_addresses
        )

        raise NetworkVerificationError(
            f"disabled interface {configured.name} still has IPv4 "
            f"addresses: {actual}"
        )

def _verify_routing(
    config: NetworkConfig,
    routes: list[NetworkRoute],
) -> None:
    """Verify role-specific IPv4 routing requirements."""

    for interface in config.interfaces:
        if interface.role == "wan":
            _verify_wan_route(
                interface,
                routes,
            )


def _verify_wan_route(
    interface: NetworkInterfaceConfig,
    routes: list[NetworkRoute],
) -> None:
    """Require a default IPv4 route through the configured WAN table."""

    if interface.ipv4_method == "disabled":
        return

    default_routes = [
        route
        for route in routes
        if (
            route.destination == "default"
            and route.interface == interface.name
        )
    ]

    if interface.routing_table is not None:
        default_routes = [
            route
            for route in default_routes
            if route.table == interface.routing_table
        ]

    if not default_routes:
        if interface.routing_table is not None:
            raise NetworkVerificationError(
                f"WAN interface {interface.name} has no default IPv4 "
                f"route in table {interface.routing_table}"
            )

        raise NetworkVerificationError(
            f"WAN interface {interface.name} has no default IPv4 route"
        )

    if not any(route.gateway is not None for route in default_routes):
        raise NetworkVerificationError(
            f"WAN interface {interface.name} default route has no gateway"
        )
