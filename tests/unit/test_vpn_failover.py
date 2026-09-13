import subprocess
from ipaddress import ip_interface, ip_network
from pathlib import Path

import secbox.modules.vpn.failover as failover
from secbox.modules.vpn.models import (
    WireGuardPeerConfig,
    WireGuardTunnelConfig,
)


def tunnel(interface="wg1"):
    return WireGuardTunnelConfig(
        name="backup",
        interface=interface,
        address=ip_interface("10.201.0.2/30"),
        private_key_file=Path("/key"),
        priority=200,
        routing_table=201,
        source_networks=[],
        peer=WireGuardPeerConfig(
            public_key="peer",
            endpoint="192.168.1.108:51821",
            allowed_ips=[ip_network("0.0.0.0/0")],
        ),
    )


def test_activate_replaces_active_default(monkeypatch):
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(
            command, 0, "", ""
        )

    monkeypatch.setattr(
        failover.subprocess,
        "run",
        fake_run,
    )

    failover.activate_tunnel(tunnel())

    assert commands == [[
        "/usr/sbin/ip",
        "route",
        "replace",
        "default",
        "dev",
        "wg1",
        "table",
        "250",
    ]]


def test_get_active_interface(monkeypatch):
    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            "default dev wg0\n",
            "",
        )

    monkeypatch.setattr(
        failover.subprocess,
        "run",
        fake_run,
    )

    assert failover.get_active_interface() == "wg0"
