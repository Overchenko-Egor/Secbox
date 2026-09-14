"""High-level VPN pool application service."""

from dataclasses import dataclass

from secbox.core.models import SecBoxConfig
from secbox.modules.vpn.executor import apply_wireguard_tunnel
from secbox.modules.vpn.failover import activate_tunnel
from secbox.modules.vpn.models import WireGuardTunnelConfig
from secbox.modules.vpn.routing import configure_pool_policy
from secbox.modules.vpn.validator import (
    validate_vpn_config,
    validate_vpn_key_paths,
)


class VpnServiceError(RuntimeError):
    """Raised when VPN configuration cannot be applied."""


@dataclass(frozen=True)
class VpnApplyResult:
    """Summary of a successfully applied VPN pool."""

    applied_tunnels: int
    active_name: str
    active_interface: str


def get_enabled_tunnels(
    config: SecBoxConfig,
) -> list[WireGuardTunnelConfig]:
    """Return enabled tunnels after validating VPN availability."""

    if config.vpn is None:
        raise VpnServiceError(
            "VPN configuration is not defined"
        )

    if not config.vpn.enabled:
        raise VpnServiceError(
            "VPN is disabled"
        )

    enabled_tunnels = [
        tunnel
        for tunnel in config.vpn.tunnels
        if tunnel.enabled
    ]

    if not enabled_tunnels:
        raise VpnServiceError(
            "VPN has no enabled tunnels"
        )

    return enabled_tunnels


def apply_vpn_config(
    config: SecBoxConfig,
    *,
    validate_keys: bool = True,
) -> VpnApplyResult:
    """Validate and apply the complete enabled VPN pool."""

    validate_vpn_config(config)

    if validate_keys:
        validate_vpn_key_paths(config)

    enabled_tunnels = get_enabled_tunnels(config)

    for tunnel in enabled_tunnels:
        apply_wireguard_tunnel(tunnel)

    configure_pool_policy(enabled_tunnels)

    initial_tunnel = min(
        enabled_tunnels,
        key=lambda tunnel: tunnel.priority,
    )

    activate_tunnel(initial_tunnel)

    return VpnApplyResult(
        applied_tunnels=len(enabled_tunnels),
        active_name=initial_tunnel.name,
        active_interface=initial_tunnel.interface,
    )
