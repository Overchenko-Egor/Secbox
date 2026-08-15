import pytest

from secbox.modules.network.models import (
    NetworkConfig,
    NetworkInterfaceConfig,
)
from secbox.modules.network.state import (
    NetworkAddress,
    NetworkInterfaceState,
)
from secbox.modules.network.verifier import (
    NetworkVerificationError,
    verify_network_config,
)
from secbox.modules.network.routes import NetworkRoute


def runtime_interface(
    name: str,
    ipv4: str | None = None,
    prefixlen: int = 24,
) -> NetworkInterfaceState:
    addresses: list[NetworkAddress] = []

    if ipv4 is not None:
        addresses.append(
            NetworkAddress(
                family="inet",
                address=ipv4,
                prefixlen=prefixlen,
                scope="global",
            )
        )

    return NetworkInterfaceState(
        name=name,
        mac="00:11:22:33:44:55",
        mtu=1500,
        operstate="UP",
        flags=["UP", "LOWER_UP"],
        addresses=addresses,
        is_loopback=False,
    )


def test_static_address_matches() -> None:
    config = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens36",
                role="lan",
                ipv4_method="static",
                ipv4_address="192.168.50.1/24",
            )
        ]
    )

    verify_network_config(
        config,
        [
            runtime_interface(
                "ens36",
                "192.168.50.1",
            )
        ],
    )


def test_static_address_mismatch_is_rejected() -> None:
    config = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens36",
                role="lan",
                ipv4_method="static",
                ipv4_address="192.168.50.1/24",
            )
        ]
    )

    with pytest.raises(
        NetworkVerificationError,
        match="does not have expected",
    ):
        verify_network_config(
            config,
            [
                runtime_interface(
                    "ens36",
                    "192.168.60.1",
                )
            ],
        )


def test_dhcp_requires_ipv4_address() -> None:
    config = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens33",
                role="wan",
                ipv4_method="dhcp",
            )
        ]
    )

    with pytest.raises(
        NetworkVerificationError,
        match="has no IPv4 address",
    ):
        verify_network_config(
            config,
            [runtime_interface("ens33")],
        )


def test_dhcp_with_ipv4_passes() -> None:
    config = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens33",
                role="wan",
                ipv4_method="dhcp",
            )
        ]
    )

    verify_network_config(
        config,
        [
            runtime_interface(
                "ens33",
                "192.168.1.63",
            )
        ],
    )


def test_disabled_interface_rejects_ipv4() -> None:
    config = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens37",
                role="unused",
                ipv4_method="disabled",
            )
        ]
    )

    with pytest.raises(
        NetworkVerificationError,
        match="still has IPv4",
    ):
        verify_network_config(
            config,
            [
                runtime_interface(
                    "ens37",
                    "192.168.10.20",
                )
            ],
        )


def test_missing_interface_is_rejected() -> None:
    config = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens33",
                role="wan",
                ipv4_method="dhcp",
            )
        ]
    )

    with pytest.raises(
        NetworkVerificationError,
        match="disappeared",
    ):
        verify_network_config(
            config,
            [],
        )

def test_wan_with_default_route_passes() -> None:
    config = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens33",
                role="wan",
                ipv4_method="dhcp",
            )
        ]
    )

    verify_network_config(
        config,
        [
            runtime_interface(
                "ens33",
                "192.168.1.63",
            )
        ],
        [
            NetworkRoute(
                destination="default",
                gateway="192.168.1.1",
                interface="ens33",
                source="192.168.1.63",
                protocol="dhcp",
                metric=1024,
            )
        ],
    )


def test_wan_without_default_route_is_rejected() -> None:
    config = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens33",
                role="wan",
                ipv4_method="dhcp",
            )
        ]
    )

    with pytest.raises(
        NetworkVerificationError,
        match="has no default IPv4 route",
    ):
        verify_network_config(
            config,
            [
                runtime_interface(
                    "ens33",
                    "192.168.1.63",
                )
            ],
            [],
        )


def test_default_route_on_wrong_interface_is_rejected() -> None:
    config = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens33",
                role="wan",
                ipv4_method="dhcp",
            )
        ]
    )

    with pytest.raises(
        NetworkVerificationError,
        match="has no default IPv4 route",
    ):
        verify_network_config(
            config,
            [
                runtime_interface(
                    "ens33",
                    "192.168.1.63",
                )
            ],
            [
                NetworkRoute(
                    destination="default",
                    gateway="192.168.1.1",
                    interface="ens38",
                )
            ],
        )
