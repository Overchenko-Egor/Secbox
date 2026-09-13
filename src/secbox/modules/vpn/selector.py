"""VPN tunnel selection logic."""

from dataclasses import dataclass

from secbox.modules.vpn.health import (
    VpnHealthStatus,
    VpnTunnelHealth,
)
from secbox.modules.vpn.models import WireGuardTunnelConfig


@dataclass(frozen=True)
class VpnSelection:
    tunnel: WireGuardTunnelConfig | None
    health: VpnTunnelHealth | None
    reason: str


def select_best_tunnel(
    tunnels: list[WireGuardTunnelConfig],
    health_by_interface: dict[str, VpnTunnelHealth],
) -> VpnSelection:
    """Select the best usable VPN tunnel."""

    candidates = []

    for tunnel in tunnels:
        if not tunnel.enabled:
            continue

        health = health_by_interface.get(tunnel.interface)

        if health is None:
            continue

        if health.status == VpnHealthStatus.DOWN:
            continue

        candidates.append((tunnel, health))

    if not candidates:
        return VpnSelection(
            tunnel=None,
            health=None,
            reason="No usable VPN tunnel is available",
        )

    healthy = [
        candidate
        for candidate in candidates
        if candidate[1].status == VpnHealthStatus.HEALTHY
    ]

    pool = healthy or candidates

    tunnel, health = min(
        pool,
        key=lambda candidate: candidate[0].priority,
    )

    return VpnSelection(
        tunnel=tunnel,
        health=health,
        reason=(
            f"Selected {tunnel.name} "
            f"with priority {tunnel.priority}"
        ),
    )
