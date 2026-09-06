"""Tests for live IDS runtime network refresh."""

import ipaddress

from secbox.core.models import SecBoxConfig
from secbox.modules.ids.response import (
    IdsResponseHandler,
)
from secbox.modules.ids.runtime import (
    refresh_ids_runtime_state,
)
from secbox.modules.ids.worker import (
    StreamingIdsWorker,
)
from secbox.modules.network.state import (
    NetworkAddress,
    NetworkInterfaceState,
)


def make_config() -> SecBoxConfig:
    """Create minimal SecBox configuration for runtime refresh."""

    return SecBoxConfig.model_validate(
        {
            "schema_version": 1,
            "system": {
                "hostname": "secbox",
            },
            "network": {
                "interfaces": [
                    {
                        "name": "ens38",
                        "role": "mgmt",
                        "ipv4_method": "static",
                        "ipv4_address": (
                            "192.168.100.2/24"
                        ),
                    },
                    {
                        "name": "ens33",
                        "role": "wan",
                        "ipv4_method": "dhcp",
                    },
                    {
                        "name": "ens36",
                        "role": "lan",
                        "ipv4_method": "static",
                        "ipv4_address": (
                            "192.168.50.1/24"
                        ),
                    },
                ],
            },
            "firewall": {
                "enabled": True,
                "wan_interface": "ens33",
                "lan_interface": "ens36",
                "management_interface": "ens38",
                "management_tcp_ports": [
                    22,
                ],
                "allow_lan_to_wan": True,
                "allow_icmp_input": True,
                "allow_dhcp_server": True,
                "enable_ipv4_forwarding": True,
                "enable_nat": True,
                "log_dropped_input": True,
                "log_dropped_forward": True,
                "log_rate": "10/second",
                "log_burst": 20,
                "dynamic_blacklist_enabled": True,
                "dynamic_blacklist_timeout": "1h",
                "dynamic_blacklist_protected_networks": [
                    "192.168.100.0/24",
                ],
                "input_policy": "drop",
                "forward_policy": "drop",
                "output_policy": "accept",
            },
            "ids": {
                "enabled": True,
                "eve_path": (
                    "/var/log/suricata/eve.json"
                ),
                "nat_correlation_window_ms": 10,
                "aggregation_window_seconds": 30,
                "policy": {
                    "minimum_alert_count": 2,
                    "minimum_block_count": 5,
                    "maximum_alert_severity": 2,
                    "maximum_block_severity": 1,
                },
                "automatic_blackhole": {
                    "enabled": False,
                    "timeout": "15m",
                },
            },
        }
    )


def make_interface(
    name: str,
    address: str,
    prefixlen: int,
) -> NetworkInterfaceState:
    """Create one runtime interface."""

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
                prefixlen=prefixlen,
                scope="global",
            ),
        ],
        is_loopback=False,
    )


def make_runtime_interfaces(
    wan_address: str,
) -> list[NetworkInterfaceState]:
    """Create current SecBox runtime interface state."""

    return [
        NetworkInterfaceState(
            name="lo",
            mac=None,
            mtu=65536,
            operstate="UNKNOWN",
            flags=[
                "LOOPBACK",
                "UP",
            ],
            addresses=[
                NetworkAddress(
                    family="inet",
                    address="127.0.0.1",
                    prefixlen=8,
                    scope="host",
                ),
            ],
            is_loopback=True,
        ),
        make_interface(
            "ens33",
            wan_address,
            24,
        ),
        make_interface(
            "ens36",
            "192.168.50.1",
            24,
        ),
        make_interface(
            "ens38",
            "192.168.100.2",
            24,
        ),
    ]


def test_worker_refresh_replaces_wan_address() -> None:
    """Worker context must use the current DHCP WAN address."""

    config = make_config()

    worker = StreamingIdsWorker(
        config,
        make_runtime_interfaces(
            "192.168.1.63"
        ),
    )

    assert worker.network_context.wan_ipv4_addresses == (
        ipaddress.IPv4Address(
            "192.168.1.63"
        ),
    )

    worker.refresh_runtime(
        make_runtime_interfaces(
            "192.168.1.80"
        )
    )

    assert worker.network_context.wan_ipv4_addresses == (
        ipaddress.IPv4Address(
            "192.168.1.80"
        ),
    )


def test_worker_policy_protection_follows_wan_change() -> None:
    """Worker policy must stop protecting stale WAN address."""

    config = make_config()

    worker = StreamingIdsWorker(
        config,
        make_runtime_interfaces(
            "192.168.1.63"
        ),
    )

    before = {
        str(network)
        for network
        in worker.policy_config.protected_networks
    }

    assert "192.168.1.63/32" in before
    assert "192.168.1.80/32" not in before

    worker.refresh_runtime(
        make_runtime_interfaces(
            "192.168.1.80"
        )
    )

    after = {
        str(network)
        for network
        in worker.policy_config.protected_networks
    }

    assert "192.168.1.63/32" not in after
    assert "192.168.1.80/32" in after

    # Other appliance addresses remain protected.
    assert "127.0.0.1/32" in after
    assert "192.168.50.1/32" in after
    assert "192.168.100.2/32" in after

    # Explicit configured management network remains protected.
    assert "192.168.100.0/24" in after


def test_full_runtime_refresh_updates_worker_and_response() -> None:
    """One refresh must update policy and response protection."""

    config = make_config()

    original = make_runtime_interfaces(
        "192.168.1.63"
    )

    worker = StreamingIdsWorker(
        config,
        original,
    )

    response_handler = IdsResponseHandler(
        automatic_blackhole_enabled=False,
        automatic_blackhole_timeout="15m",
        protected_networks=(
            "192.168.100.0/24",
            "127.0.0.1/32",
            "192.168.1.63/32",
            "192.168.50.1/32",
            "192.168.100.2/32",
        ),
    )

    refreshed = make_runtime_interfaces(
        "192.168.1.80"
    )

    refresh_ids_runtime_state(
        config,
        refreshed,
        worker,
        response_handler,
    )

    worker_protected = {
        str(network)
        for network
        in worker.policy_config.protected_networks
    }

    response_protected = set(
        response_handler.protected_networks
    )

    assert "192.168.1.63/32" not in worker_protected
    assert "192.168.1.63/32" not in response_protected

    assert "192.168.1.80/32" in worker_protected
    assert "192.168.1.80/32" in response_protected

    expected_common = {
        "192.168.100.0/24",
        "127.0.0.1/32",
        "192.168.50.1/32",
        "192.168.100.2/32",
    }

    assert expected_common <= worker_protected
    assert expected_common <= response_protected


def test_failed_worker_refresh_preserves_previous_state() -> None:
    """Invalid refresh must not destroy last valid worker state."""

    config = make_config()

    worker = StreamingIdsWorker(
        config,
        make_runtime_interfaces(
            "192.168.1.63"
        ),
    )

    original_context = (
        worker.network_context
    )

    original_policy = (
        worker.policy_config
    )

    # WAN exists but temporarily has no IPv4 address.
    broken_interfaces = (
        make_runtime_interfaces(
            "192.168.1.80"
        )
    )

    for index, interface in enumerate(
        broken_interfaces
    ):
        if interface.name == "ens33":
            broken_interfaces[index] = (
                interface.model_copy(
                    update={
                        "addresses": [],
                    }
                )
            )

    from secbox.modules.ids.worker import (
        IdsWorkerError,
    )

    import pytest

    with pytest.raises(
        IdsWorkerError,
        match="failed to refresh IDS runtime state",
    ):
        worker.refresh_runtime(
            broken_interfaces
        )

    assert (
        worker.network_context
        is original_context
    )

    assert (
        worker.policy_config
        is original_policy
    )

    assert worker.network_context.wan_ipv4_addresses == (
        ipaddress.IPv4Address(
            "192.168.1.63"
        ),
    )
