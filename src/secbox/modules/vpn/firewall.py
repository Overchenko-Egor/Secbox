"""Firewall integration helpers for SecBox VPN."""

from secbox.modules.vpn.models import VpnConfig


def get_vpn_firewall_interfaces(
    vpn: VpnConfig | None,
) -> list[str]:
    """Return enabled VPN interfaces used for LAN egress."""

    if vpn is None or not vpn.enabled:
        return []

    return sorted(
        {
            tunnel.interface
            for tunnel in vpn.tunnels
            if tunnel.enabled
        }
    )
