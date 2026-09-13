import subprocess
from ipaddress import ip_address, ip_interface, ip_network
from pathlib import Path

import secbox.modules.vpn.health as health
from secbox.modules.vpn.models import (
    WireGuardPeerConfig,
    WireGuardTunnelConfig,
)


KEY = "peer-key"


def tunnel():
    return WireGuardTunnelConfig(
        name="primary",
        interface="wg0",
        address=ip_interface("10.200.0.2/30"),
        private_key_file=Path("/key"),
        routing_table=200,
        source_networks=[ip_network("192.168.50.0/24")],
        health_probe=ip_address("10.200.0.1"),
        peer=WireGuardPeerConfig(
            public_key=KEY,
            endpoint="192.168.1.108:51820",
            allowed_ips=[ip_network("0.0.0.0/0")],
        ),
    )


def test_health_is_healthy(monkeypatch):
    def fake_run(command, **kwargs):
        if command[1:4] == ["show", "wg0", "dump"]:
            dump = (
                "priv\tpub\t51820\toff\n"
                f"{KEY}\tpsk\tendpoint\t0.0.0.0/0\t"
                "990\t1000\t2000\t25\n"
            )
            return subprocess.CompletedProcess(
                command, 0, dump, ""
            )

        return subprocess.CompletedProcess(
            command, 0,
            "64 bytes: time=12.5 ms\n", ""
        )

    monkeypatch.setattr(health.subprocess, "run", fake_run)

    result = health.get_tunnel_health(
        tunnel(),
        now=1000,
    )

    assert result.status == health.VpnHealthStatus.HEALTHY
    assert result.handshake_age_seconds == 10
    assert result.rx_bytes == 1000
    assert result.tx_bytes == 2000
    assert result.probe_ok is True
    assert result.latency_ms == 12.5


def test_health_is_degraded_when_probe_fails(monkeypatch):
    def fake_run(command, **kwargs):
        if command[0] == "/usr/bin/wg":
            dump = (
                "priv\tpub\t51820\toff\n"
                f"{KEY}\tpsk\tendpoint\t0.0.0.0/0\t"
                "990\t1000\t2000\t25\n"
            )
            return subprocess.CompletedProcess(
                command, 0, dump, ""
            )

        return subprocess.CompletedProcess(
            command, 1, "", ""
        )

    monkeypatch.setattr(health.subprocess, "run", fake_run)

    result = health.get_tunnel_health(
        tunnel(),
        now=1000,
    )

    assert result.status == health.VpnHealthStatus.DEGRADED
    assert result.probe_ok is False


def test_health_is_down_with_stale_handshake(monkeypatch):
    def fake_run(command, **kwargs):
        if command[0] == "/usr/bin/wg":
            dump = (
                "priv\tpub\t51820\toff\n"
                f"{KEY}\tpsk\tendpoint\t0.0.0.0/0\t"
                "700\t1000\t2000\t25\n"
            )
            return subprocess.CompletedProcess(
                command, 0, dump, ""
            )

        return subprocess.CompletedProcess(
            command, 1, "", ""
        )

    monkeypatch.setattr(health.subprocess, "run", fake_run)

    result = health.get_tunnel_health(
        tunnel(),
        now=1000,
    )

    assert result.status == health.VpnHealthStatus.DOWN
