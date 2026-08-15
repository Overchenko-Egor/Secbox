"""Validation of desired network configuration against runtime state."""

from ipaddress import IPv4Interface, IPv4Network

from secbox.modules.network.models import (
    NetworkConfig,
    NetworkInterfaceConfig,
)
from secbox.modules.network.state import NetworkInterfaceState


class NetworkPreflightError(Exception):
    """Raised when a network configuration cannot safely be applied."""


def validate_network_preflight(
    config: NetworkConfig,
    runtime_interfaces: list[NetworkInterfaceState],
) -> None:
    """Validate desired configuration against currently detected interfaces."""

    runtime_names = {
        interface.name
        for interface in runtime_interfaces
        if not interface.is_loopback
    }

    configured_names = {
        interface.name
        for interface in config.interfaces
    }

    missing = configured_names - runtime_names

    if missing:
        missing_names = ", ".join(sorted(missing))
        raise NetworkPreflightError(
            f"configured network interfaces do not exist: {missing_names}"
        )

    _validate_unique_roles(config)
    _validate_static_networks(config)


def _validate_unique_roles(config: NetworkConfig) -> None:
    """Prevent ambiguous singleton interface roles."""

    singleton_roles = {
        "wan",
        "mgmt",
    }

    for role in singleton_roles:
        matching = [
            interface
            for interface in config.interfaces
            if interface.role == role
        ]

        if len(matching) > 1:
            raise NetworkPreflightError(
                f"only one interface may use role '{role}'"
            )


def _validate_static_networks(config: NetworkConfig) -> None:
    """Reject overlapping statically configured IPv4 networks."""

    static_interfaces: list[
        tuple[NetworkInterfaceConfig, IPv4Interface]
    ] = []

    for interface in config.interfaces:
        if (
            interface.ipv4_method == "static"
            and interface.ipv4_address is not None
        ):
            static_interfaces.append(
                (
                    interface,
                    interface.ipv4_address,
                )
            )

    for index, (left_interface, left_address) in enumerate(
        static_interfaces
    ):
        left_network: IPv4Network = left_address.network

        for right_interface, right_address in static_interfaces[index + 1 :]:
            right_network: IPv4Network = right_address.network

            if left_network.overlaps(right_network):
                raise NetworkPreflightError(
                    "static IPv4 networks overlap: "
                    f"{left_interface.name}={left_network} and "
                    f"{right_interface.name}={right_network}"
                )






def validate_management_interface(
    config: NetworkConfig,
    runtime_interfaces: list[NetworkInterfaceState],
) -> None:
    """Ensure configured management interface exists and remains usable."""

    management = [
        interface
        for interface in config.interfaces
        if interface.role == "mgmt"
    ]

    if not management:
        return

    management_config = management[0]

    runtime = next(
        (
            interface
            for interface in runtime_interfaces
            if interface.name == management_config.name
        ),
        None,
    )

    if runtime is None:
        raise NetworkPreflightError(
            f"management interface does not exist: "
            f"{management_config.name}"
        )

    if management_config.ipv4_method == "disabled":
        raise NetworkPreflightError(
            "management interface IPv4 cannot be disabled"
        )
