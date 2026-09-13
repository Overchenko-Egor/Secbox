from ipaddress import ip_interface, ip_network
from pathlib import Path

import secbox.modules.vpn.routing as routing
from secbox.modules.vpn.models import (
    WireGuardPeerConfig,
    WireGuardTunnelConfig,
)


def make_tunnel():
    return WireGuardTunnelConfig(
        name="primary",
        interface="wg0",
        address=ip_interface("10.200.0.2/30"),
        private_key_file=Path("/etc/secbox/vpn/wg0.key"),
        priority=100,
        routing_table=200,
        source_networks=[
            ip_network("192.168.50.0/24"),
        ],
        peer=WireGuardPeerConfig(
            public_key="test-public-key",
            endpoint="192.168.1.108:51820",
            allowed_ips=[
                ip_network("0.0.0.0/0"),
            ],
        ),
    )


def test_policy_routing_preserves_main_non_default_routes(
    monkeypatch,
):
    calls = []

    def fake_run_ip(*arguments, check=True):
        calls.append((arguments, check))
        return None

    monkeypatch.setattr(
        routing,
        "_run_ip",
        fake_run_ip,
    )

    routing.configure_policy_routing(make_tunnel())

    commands = [
        arguments
        for arguments, _ in calls
    ]

    assert (
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
    ) in commands

    assert (
        "rule",
        "add",
        "from",
        "192.168.50.0/24",
        "priority",
        "100",
        "table",
        "200",
    ) in commands


def test_policy_routing_has_vpn_default_route(
    monkeypatch,
):
    calls = []

    def fake_run_ip(*arguments, check=True):
        calls.append(arguments)
        return None

    monkeypatch.setattr(
        routing,
        "_run_ip",
        fake_run_ip,
    )

    routing.configure_policy_routing(make_tunnel())

    assert (
        "route",
        "replace",
        "default",
        "dev",
        "wg0",
        "table",
        "200",
    ) in calls
