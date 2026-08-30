"""Tests for IDS network context builder."""

import ipaddress

import pytest

from secbox.core.models import SecBoxConfig
from secbox.modules.ids.context import (
    IdsContextError,
    build_ids_network_context,
)
from secbox.modules.network.state import (
    NetworkAddress,
    NetworkInterfaceState,
)


def make_config() -> SecBoxConfig:
    """Create SecBox configuration for IDS tests."""

    return SecBoxConfig.model_validate(
        {
            "schema_version": 1,
            "system": {
                "hostname": "secbox",
            },
            "network": {
                "interfaces": [
                    {
                        "name": "mgmt0",
                        "role": "mgmt",
                        "ipv4_method": "static",
                        "ipv4_address": (
                            "192.168.100.2/24"
                        ),
                    },
                    {
                        "name": "wan0",
                        "role": "wan",
                        "ipv4_method": "dhcp",
                    },
                    {
                        "name": "lan0",
                        "role": "lan",
                        "ipv4_method": "static",
                        "ipv4_address": (
                            "192.168.50.1/24"
                        ),
                    },
                ],
            },
        }
    )


def make_interface(
    name: str,
    addresses: list[NetworkAddress],
) -> NetworkInterfaceState:
    """Create runtime interface state."""

    return NetworkInterfaceState(
        name=name,
        mac="00:11:22:33:44:55",
        mtu=1500,
        operstate="UP",
        flags=[
            "BROADCAST",
            "MULTICAST",
            "UP",
        ],
        addresses=addresses,
        is_loopback=False,
    )


def make_runtime_interfaces() -> list[
    NetworkInterfaceState
]:
    """Create runtime network state."""

    return [
        make_interface(
            "wan0",
            [
                NetworkAddress(
                    family="inet",
                    address="192.168.1.63",
                    prefixlen=24,
                    scope="global",
                ),
                NetworkAddress(
                    family="inet6",
                    address="fe80::1",
                    prefixlen=64,
                    scope="link",
                ),
            ],
        ),
        make_interface(
            "lan0",
            [
                NetworkAddress(
                    family="inet",
                    address="192.168.50.1",
                    prefixlen=24,
                    scope="global",
                ),
            ],
        ),
        make_interface(
            "mgmt0",
            [
                NetworkAddress(
                    family="inet",
                    address="192.168.100.2",
                    prefixlen=24,
                    scope="global",
                ),
            ],
        ),
    ]


def test_build_ids_network_context() -> None:
    """Build IDS context from config and runtime state."""

    context = build_ids_network_context(
        make_config(),
        make_runtime_interfaces(),
    )

    assert context.wan_interface == "wan0"
    assert context.lan_interface == "lan0"

    assert context.wan_ipv4_addresses == (
        ipaddress.IPv4Address(
            "192.168.1.63"
        ),
    )

    assert context.lan_ipv4_networks == (
        ipaddress.IPv4Network(
            "192.168.50.0/24"
        ),
    )


def test_ignore_runtime_ipv6_address() -> None:
    """Do not include IPv6 in the IPv4 IDS context."""

    context = build_ids_network_context(
        make_config(),
        make_runtime_interfaces(),
    )

    assert len(
        context.wan_ipv4_addresses
    ) == 1


def test_missing_runtime_wan_fails() -> None:
    """Reject missing configured WAN interface."""

    runtime = [
        interface
        for interface in make_runtime_interfaces()
        if interface.name != "wan0"
    ]

    with pytest.raises(
        IdsContextError,
        match="configured interface is missing",
    ):
        build_ids_network_context(
            make_config(),
            runtime,
        )


def test_wan_without_ipv4_fails() -> None:
    """Reject WAN without an active IPv4 address."""

    runtime = make_runtime_interfaces()

    runtime[0] = make_interface(
        "wan0",
        [
            NetworkAddress(
                family="inet6",
                address="fe80::1",
                prefixlen=64,
                scope="link",
            ),
        ],
    )

    with pytest.raises(
        IdsContextError,
        match="WAN interface has no runtime IPv4",
    ):
        build_ids_network_context(
            make_config(),
            runtime,
        )


def test_multiple_wan_interfaces_fail() -> None:
    """Reject ambiguous multiple WAN configuration."""

    raw = make_config().model_dump(
        mode="json"
    )

    raw["network"]["interfaces"].append(
        {
            "name": "wan1",
            "role": "wan",
            "ipv4_method": "dhcp",
            "ipv4_address": None,
            "routing_table": None,
        }
    )

    config = SecBoxConfig.model_validate(
        raw
    )

    with pytest.raises(
        IdsContextError,
        match="multiple wan interfaces",
    ):
        build_ids_network_context(
            config,
            make_runtime_interfaces(),
        )
