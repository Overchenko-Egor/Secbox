"""Tests for IDS runtime configuration."""

import ipaddress

from secbox.modules.ids.runtime import (
    build_runtime_local_networks,
)
from secbox.modules.network.state import (
    NetworkAddress,
    NetworkInterfaceState,
)


def make_interface(
    name: str,
    address: str,
    *,
    is_loopback: bool = False,
) -> NetworkInterfaceState:
    """Create runtime interface with one IPv4 address."""

    return NetworkInterfaceState(
        name=name,
        mac=None,
        mtu=1500,
        operstate="UP",
        flags=[
            "UP",
        ],
        addresses=[
            NetworkAddress(
                family="inet",
                address=address,
                prefixlen=24,
                scope="global",
            ),
        ],
        is_loopback=is_loopback,
    )


def test_runtime_local_addresses_become_host_networks() -> None:
    """Protect every IPv4 address owned by SecBox."""

    interfaces = [
        make_interface(
            "ens33",
            "192.168.1.63",
        ),
        make_interface(
            "ens36",
            "192.168.50.1",
        ),
        make_interface(
            "ens38",
            "192.168.100.2",
        ),
    ]

    networks = (
        build_runtime_local_networks(
            interfaces
        )
    )

    assert networks == (
        ipaddress.IPv4Network(
            "192.168.1.63/32"
        ),
        ipaddress.IPv4Network(
            "192.168.50.1/32"
        ),
        ipaddress.IPv4Network(
            "192.168.100.2/32"
        ),
    )


def test_runtime_interface_prefix_is_not_protected() -> None:
    """Protect only the appliance address, not its whole subnet."""

    interfaces = [
        make_interface(
            "ens33",
            "192.168.1.63",
        ),
    ]

    networks = (
        build_runtime_local_networks(
            interfaces
        )
    )

    assert (
        ipaddress.IPv4Address(
            "192.168.1.63"
        )
        in networks[0]
    )

    assert (
        ipaddress.IPv4Address(
            "192.168.1.64"
        )
        not in networks[0]
    )


def test_all_local_roles_are_protected() -> None:
    """WAN, LAN and management addresses are all protected."""

    interfaces = [
        make_interface(
            "wan0",
            "10.0.0.2",
        ),
        make_interface(
            "lan0",
            "10.10.0.1",
        ),
        make_interface(
            "mgmt0",
            "172.16.100.1",
        ),
    ]

    networks = (
        build_runtime_local_networks(
            interfaces
        )
    )

    protected_addresses = {
        network.network_address
        for network in networks
    }

    assert protected_addresses == {
        ipaddress.IPv4Address(
            "10.0.0.2"
        ),
        ipaddress.IPv4Address(
            "10.10.0.1"
        ),
        ipaddress.IPv4Address(
            "172.16.100.1"
        ),
    }


def test_non_ipv4_addresses_are_ignored() -> None:
    """IPv6 is not added to the current IPv4 blacklist protection."""

    interface = NetworkInterfaceState(
        name="ens33",
        mac=None,
        mtu=1500,
        operstate="UP",
        flags=[
            "UP",
        ],
        addresses=[
            NetworkAddress(
                family="inet6",
                address="2001:db8::1",
                prefixlen=64,
                scope="global",
            ),
        ],
        is_loopback=False,
    )

    assert (
        build_runtime_local_networks(
            [interface]
        )
        == ()
    )


def test_multiple_ipv4_addresses_on_interface_are_protected() -> None:
    """Protect every IPv4 address assigned to one interface."""

    interface = NetworkInterfaceState(
        name="ens33",
        mac=None,
        mtu=1500,
        operstate="UP",
        flags=[
            "UP",
        ],
        addresses=[
            NetworkAddress(
                family="inet",
                address="192.168.1.63",
                prefixlen=24,
                scope="global",
            ),
            NetworkAddress(
                family="inet",
                address="192.168.1.64",
                prefixlen=24,
                scope="global",
            ),
        ],
        is_loopback=False,
    )

    networks = (
        build_runtime_local_networks(
            [interface]
        )
    )

    assert networks == (
        ipaddress.IPv4Network(
            "192.168.1.63/32"
        ),
        ipaddress.IPv4Network(
            "192.168.1.64/32"
        ),
    )
