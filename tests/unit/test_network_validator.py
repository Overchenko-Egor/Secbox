import pytest

from secbox.modules.network.models import (
    NetworkConfig,
    NetworkInterfaceConfig,
)
from secbox.modules.network.state import NetworkInterfaceState
from secbox.modules.network.validator import (
    NetworkPreflightError,
    validate_management_interface,
    validate_network_preflight,
)


def runtime_interface(
    name: str,
) -> NetworkInterfaceState:
    return NetworkInterfaceState(
        name=name,
        mac="00:11:22:33:44:55",
        mtu=1500,
        operstate="UP",
        flags=[
            "BROADCAST",
            "MULTICAST",
            "UP",
            "LOWER_UP",
        ],
        addresses=[],
        is_loopback=False,
    )


def test_existing_interfaces_pass() -> None:
    config = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens33",
                role="wan",
                ipv4_method="dhcp",
            ),
            NetworkInterfaceConfig(
                name="ens36",
                role="lan",
                ipv4_method="static",
                ipv4_address="192.168.50.1/24",
            ),
        ]
    )

    validate_network_preflight(
        config,
        [
            runtime_interface("ens33"),
            runtime_interface("ens36"),
        ],
    )


def test_missing_interface_is_rejected() -> None:
    config = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens99",
                role="wan",
                ipv4_method="dhcp",
            ),
        ]
    )

    with pytest.raises(
        NetworkPreflightError,
        match="do not exist",
    ):
        validate_network_preflight(
            config,
            [runtime_interface("ens33")],
        )


def test_multiple_wan_interfaces_are_rejected() -> None:
    config = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens33",
                role="wan",
                ipv4_method="dhcp",
            ),
            NetworkInterfaceConfig(
                name="ens36",
                role="wan",
                ipv4_method="dhcp",
            ),
        ]
    )

    with pytest.raises(
        NetworkPreflightError,
        match="only one interface",
    ):
        validate_network_preflight(
            config,
            [
                runtime_interface("ens33"),
                runtime_interface("ens36"),
            ],
        )


def test_overlapping_static_networks_are_rejected() -> None:
    config = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens36",
                role="lan",
                ipv4_method="static",
                ipv4_address="192.168.50.1/24",
            ),
            NetworkInterfaceConfig(
                name="ens37",
                role="dmz",
                ipv4_method="static",
                ipv4_address="192.168.50.200/25",
            ),
        ]
    )

    with pytest.raises(
        NetworkPreflightError,
        match="overlap",
    ):
        validate_network_preflight(
            config,
            [
                runtime_interface("ens36"),
                runtime_interface("ens37"),
            ],
        )


def test_disabled_management_ipv4_is_rejected() -> None:
    config = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens38",
                role="mgmt",
                ipv4_method="disabled",
            ),
        ]
    )

    with pytest.raises(
        NetworkPreflightError,
        match="management interface IPv4 cannot be disabled",
    ):
        validate_management_interface(
            config,
            [runtime_interface("ens38")],
        )


def test_management_dhcp_is_valid() -> None:
    config = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens38",
                role="mgmt",
                ipv4_method="dhcp",
            ),
        ]
    )

    validate_management_interface(
        config,
        [runtime_interface("ens38")],
    )
