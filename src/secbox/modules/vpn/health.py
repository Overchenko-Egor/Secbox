"""Health monitoring for SecBox VPN tunnels."""

import re
import subprocess
import time
from dataclasses import dataclass
from enum import StrEnum

from secbox.modules.vpn.models import WireGuardTunnelConfig


class VpnHealthStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DOWN = "down"


@dataclass(frozen=True)
class VpnTunnelHealth:
    name: str
    interface: str
    status: VpnHealthStatus
    peer_present: bool
    handshake_age_seconds: int | None
    rx_bytes: int
    tx_bytes: int
    probe_ok: bool | None
    latency_ms: float | None
    reason: str


def _read_peer_dump(
    tunnel: WireGuardTunnelConfig,
) -> tuple[int, int, int] | None:
    result = subprocess.run(
        ["/usr/bin/wg", "show", tunnel.interface, "dump"],
        check=False,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        return None

    lines = result.stdout.splitlines()

    for line in lines[1:]:
        fields = line.split("\t")

        if len(fields) < 8:
            continue

        if fields[0] != tunnel.peer.public_key:
            continue

        return (
            int(fields[4]),
            int(fields[5]),
            int(fields[6]),
        )

    return None


def _probe(
    tunnel: WireGuardTunnelConfig,
) -> tuple[bool | None, float | None]:
    if tunnel.health_probe is None:
        return None, None

    result = subprocess.run(
        [
            "/usr/bin/ping",
            "-n",
            "-c",
            "1",
            "-W",
            "1",
            "-I",
            tunnel.interface,
            str(tunnel.health_probe),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        return False, None

    match = re.search(r"time[=<]([\d.]+)\s*ms", result.stdout)

    latency = float(match.group(1)) if match else None
    return True, latency


def get_tunnel_health(
    tunnel: WireGuardTunnelConfig,
    *,
    now: int | None = None,
) -> VpnTunnelHealth:
    current_time = int(time.time()) if now is None else now

    peer = _read_peer_dump(tunnel)

    if peer is None:
        return VpnTunnelHealth(
            tunnel.name,
            tunnel.interface,
            VpnHealthStatus.DOWN,
            False,
            None,
            0,
            0,
            None,
            None,
            "WireGuard peer is not active",
        )

    handshake, rx_bytes, tx_bytes = peer

    if handshake == 0:
        age = None
    else:
        age = max(0, current_time - handshake)

    probe_ok, latency = _probe(tunnel)

    if handshake == 0 or (age is not None and age > 180):
        status = VpnHealthStatus.DOWN
        reason = "WireGuard handshake is missing or stale"
    elif probe_ok is False or (age is not None and age > 90):
        status = VpnHealthStatus.DEGRADED
        reason = "VPN connectivity is degraded"
    else:
        status = VpnHealthStatus.HEALTHY
        reason = "VPN tunnel is healthy"

    return VpnTunnelHealth(
        tunnel.name,
        tunnel.interface,
        status,
        True,
        age,
        rx_bytes,
        tx_bytes,
        probe_ok,
        latency,
        reason,
    )
