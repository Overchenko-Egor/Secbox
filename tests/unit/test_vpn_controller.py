from ipaddress import ip_interface, ip_network
from pathlib import Path

import secbox.modules.vpn.controller as controller
from secbox.modules.vpn.health import (
    VpnHealthStatus,
    VpnTunnelHealth,
)
from secbox.modules.vpn.models import (
    VpnConfig,
    WireGuardPeerConfig,
    WireGuardTunnelConfig,
)


def tunnel(name, interface, priority):
    return WireGuardTunnelConfig(
        name=name,
        interface=interface,
        address=ip_interface("10.200.0.2/30"),
        private_key_file=Path("/key"),
        priority=priority,
        routing_table=200 + priority,
        source_networks=[],
        peer=WireGuardPeerConfig(
            public_key=f"{interface}-peer",
            endpoint="192.168.1.108:51820",
            allowed_ips=[ip_network("0.0.0.0/0")],
        ),
    )


def snapshot(interface, status):
    return VpnTunnelHealth(
        name=interface,
        interface=interface,
        status=status,
        peer_present=True,
        handshake_age_seconds=10,
        rx_bytes=100,
        tx_bytes=100,
        probe_ok=status == VpnHealthStatus.HEALTHY,
        latency_ms=1.0,
        reason="test",
    )


def test_failover_requires_three_failures(
    monkeypatch,
    tmp_path,
):
    primary = tunnel("primary", "wg0", 100)
    backup = tunnel("backup", "wg1", 200)

    vpn = VpnConfig(
        enabled=True,
        tunnels=[primary, backup],
    )

    active = {"interface": "wg0"}

    def fake_activate(selected):
        active["interface"] = selected.interface

    monkeypatch.setattr(
        controller,
        "get_active_interface",
        lambda: active["interface"],
    )
    monkeypatch.setattr(
        controller,
        "activate_tunnel",
        fake_activate,
    )

    health = {
        "wg0": VpnHealthStatus.DEGRADED,
        "wg1": VpnHealthStatus.HEALTHY,
    }

    monkeypatch.setattr(
        controller,
        "get_tunnel_health",
        lambda t: snapshot(
            t.interface,
            health[t.interface],
        ),
    )

    state_path = tmp_path / "state.json"

    controller.evaluate_once(vpn, state_path=state_path)
    assert active["interface"] == "wg0"

    controller.evaluate_once(vpn, state_path=state_path)
    assert active["interface"] == "wg0"

    result = controller.evaluate_once(
        vpn,
        state_path=state_path,
    )

    assert result.switched is True
    assert active["interface"] == "wg1"
