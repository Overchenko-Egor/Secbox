from ipaddress import ip_interface, ip_network
from pathlib import Path

import secbox.modules.vpn.routing as routing
from secbox.modules.vpn.models import (
    WireGuardPeerConfig,
    WireGuardTunnelConfig,
)


def make_tunnel(
    *,
    interface="wg0",
    table=200,
    priority=100,
    sources=None,
):
    if sources is None:
        sources = [ip_network("192.168.50.0/24")]

    return WireGuardTunnelConfig(
        name=interface,
        interface=interface,
        address=ip_interface("10.200.0.2/30"),
        private_key_file=Path("/key"),
        priority=priority,
        routing_table=table,
        source_networks=sources,
        peer=WireGuardPeerConfig(
            public_key="peer",
            endpoint="192.168.1.108:51820",
            allowed_ips=[ip_network("0.0.0.0/0")],
        ),
    )


def test_tunnel_has_own_default_route(monkeypatch):
    calls = []

    def fake_run_ip(*arguments, check=True):
        calls.append((arguments, check))
        return None

    monkeypatch.setattr(
        routing,
        "_run_ip",
        fake_run_ip,
    )

    tunnel = make_tunnel(
        interface="wg0",
        table=200,
    )

    routing.configure_tunnel_route(tunnel)

    assert (
        (
            "route",
            "replace",
            "default",
            "dev",
            "wg0",
            "table",
            "200",
        ),
        True,
    ) in calls


def test_pool_policy_uses_active_table(monkeypatch):
    calls = []

    def fake_run_ip(*arguments, check=True):
        calls.append((arguments, check))
        return None

    monkeypatch.setattr(
        routing,
        "_run_ip",
        fake_run_ip,
    )

    primary = make_tunnel(
        interface="wg0",
        table=200,
        sources=[ip_network("192.168.50.0/24")],
    )

    backup = make_tunnel(
        interface="wg1",
        table=201,
        priority=200,
        sources=[],
    )

    routing.configure_pool_policy(
        [primary, backup]
    )

    assert (
        (
            "rule",
            "add",
            "from",
            "192.168.50.0/24",
            "priority",
            "99",
            "table",
            "main",
            "suppress_prefixlength",
            "0",
        ),
        True,
    ) in calls

    assert (
        (
            "rule",
            "add",
            "from",
            "192.168.50.0/24",
            "priority",
            "100",
            "table",
            "250",
        ),
        True,
    ) in calls


def test_pool_policy_deduplicates_source_networks(monkeypatch):
    calls = []

    def fake_run_ip(*arguments, check=True):
        calls.append((arguments, check))
        return None

    monkeypatch.setattr(
        routing,
        "_run_ip",
        fake_run_ip,
    )

    source = ip_network("192.168.50.0/24")

    primary = make_tunnel(
        interface="wg0",
        table=200,
        sources=[source],
    )

    backup = make_tunnel(
        interface="wg1",
        table=201,
        priority=200,
        sources=[source],
    )

    routing.configure_pool_policy(
        [primary, backup]
    )

    active_rules = [
        call
        for call in calls
        if call[0] == (
            "rule",
            "add",
            "from",
            "192.168.50.0/24",
            "priority",
            "100",
            "table",
            "250",
        )
    ]

    assert len(active_rules) == 1
