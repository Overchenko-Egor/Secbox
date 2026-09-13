from ipaddress import ip_interface, ip_network
from pathlib import Path

from secbox.modules.vpn.health import (
    VpnHealthStatus,
    VpnTunnelHealth,
)
from secbox.modules.vpn.models import (
    WireGuardPeerConfig,
    WireGuardTunnelConfig,
)
from secbox.modules.vpn.selector import select_best_tunnel


def make_tunnel(name, interface, priority):
    return WireGuardTunnelConfig(
        name=name,
        interface=interface,
        address=ip_interface("10.200.0.2/30"),
        private_key_file=Path(f"/etc/secbox/vpn/{interface}.key"),
        priority=priority,
        routing_table=200 + priority,
        source_networks=[ip_network("192.168.50.0/24")],
        peer=WireGuardPeerConfig(
            public_key=f"{interface}-peer",
            endpoint="192.168.1.108:51820",
            allowed_ips=[ip_network("0.0.0.0/0")],
        ),
    )


def make_health(interface, status):
    return VpnTunnelHealth(
        name=interface,
        interface=interface,
        status=status,
        peer_present=True,
        handshake_age_seconds=10,
        rx_bytes=100,
        tx_bytes=100,
        probe_ok=True,
        latency_ms=10.0,
        reason="test",
    )


def test_selects_highest_priority_healthy_tunnel():
    primary = make_tunnel("primary", "wg0", 100)
    backup = make_tunnel("backup", "wg1", 200)

    result = select_best_tunnel(
        [primary, backup],
        {
            "wg0": make_health(
                "wg0",
                VpnHealthStatus.HEALTHY,
            ),
            "wg1": make_health(
                "wg1",
                VpnHealthStatus.HEALTHY,
            ),
        },
    )

    assert result.tunnel == primary


def test_fails_over_when_primary_is_down():
    primary = make_tunnel("primary", "wg0", 100)
    backup = make_tunnel("backup", "wg1", 200)

    result = select_best_tunnel(
        [primary, backup],
        {
            "wg0": make_health(
                "wg0",
                VpnHealthStatus.DOWN,
            ),
            "wg1": make_health(
                "wg1",
                VpnHealthStatus.HEALTHY,
            ),
        },
    )

    assert result.tunnel == backup


def test_healthy_beats_degraded_even_with_lower_preference():
    primary = make_tunnel("primary", "wg0", 100)
    backup = make_tunnel("backup", "wg1", 200)

    result = select_best_tunnel(
        [primary, backup],
        {
            "wg0": make_health(
                "wg0",
                VpnHealthStatus.DEGRADED,
            ),
            "wg1": make_health(
                "wg1",
                VpnHealthStatus.HEALTHY,
            ),
        },
    )

    assert result.tunnel == backup


def test_degraded_is_used_when_nothing_healthy_exists():
    primary = make_tunnel("primary", "wg0", 100)

    result = select_best_tunnel(
        [primary],
        {
            "wg0": make_health(
                "wg0",
                VpnHealthStatus.DEGRADED,
            ),
        },
    )

    assert result.tunnel == primary


def test_returns_none_when_every_tunnel_is_down():
    primary = make_tunnel("primary", "wg0", 100)

    result = select_best_tunnel(
        [primary],
        {
            "wg0": make_health(
                "wg0",
                VpnHealthStatus.DOWN,
            ),
        },
    )

    assert result.tunnel is None
