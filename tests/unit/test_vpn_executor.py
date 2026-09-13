import subprocess
from ipaddress import ip_interface, ip_network
from pathlib import Path

import secbox.modules.vpn.executor as executor
from secbox.modules.vpn.models import (
    WireGuardPeerConfig,
    WireGuardTunnelConfig,
)


DESIRED_KEY = "desired-peer-key"
STALE_KEY = "stale-peer-key"


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
            public_key=DESIRED_KEY,
            endpoint="192.168.1.108:51820",
            allowed_ips=[
                ip_network("0.0.0.0/0"),
            ],
        ),
    )


def test_apply_removes_stale_wireguard_peer(
    monkeypatch,
):
    calls = []

    def fake_run(command, *, input_text=None):
        calls.append(command)

        if command == [
            "/usr/bin/wg",
            "show",
            "wg0",
            "peers",
        ]:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=f"{STALE_KEY}\n{DESIRED_KEY}\n",
                stderr="",
            )

        return subprocess.CompletedProcess(
            command,
            0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        executor,
        "_interface_exists",
        lambda interface: True,
    )
    monkeypatch.setattr(
        executor,
        "_run",
        fake_run,
    )
    monkeypatch.setattr(
        executor,
        "configure_policy_routing",
        lambda tunnel: None,
    )

    executor.apply_wireguard_tunnel(make_tunnel())

    assert [
        "/usr/bin/wg",
        "set",
        "wg0",
        "peer",
        STALE_KEY,
        "remove",
    ] in calls

    assert [
        "/usr/bin/wg",
        "set",
        "wg0",
        "peer",
        DESIRED_KEY,
        "remove",
    ] not in calls


def test_new_peer_is_configured_before_stale_peer_removed(
    monkeypatch,
):
    calls = []

    def fake_run(command, *, input_text=None):
        calls.append(command)

        if command == [
            "/usr/bin/wg",
            "show",
            "wg0",
            "peers",
        ]:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=f"{STALE_KEY}\n{DESIRED_KEY}\n",
                stderr="",
            )

        return subprocess.CompletedProcess(
            command,
            0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        executor,
        "_interface_exists",
        lambda interface: True,
    )
    monkeypatch.setattr(
        executor,
        "_run",
        fake_run,
    )
    monkeypatch.setattr(
        executor,
        "configure_policy_routing",
        lambda tunnel: None,
    )

    executor.apply_wireguard_tunnel(make_tunnel())

    configure_index = next(
        index
        for index, command in enumerate(calls)
        if command[:4] == [
            "/usr/bin/wg",
            "set",
            "wg0",
            "private-key",
        ]
    )

    remove_index = calls.index(
        [
            "/usr/bin/wg",
            "set",
            "wg0",
            "peer",
            STALE_KEY,
            "remove",
        ]
    )

    assert configure_index < remove_index
