"""High-level VPN pool application and reconciliation service."""

from dataclasses import dataclass

from secbox.core.models import SecBoxConfig
from secbox.modules.vpn.executor import (
    apply_wireguard_tunnel,
    remove_wireguard_tunnel,
)
from secbox.modules.vpn.failover import (
    activate_tunnel,
)
from secbox.modules.vpn.models import (
    WireGuardTunnelConfig,
)
from secbox.modules.vpn.routing import (
    configure_pool_policy,
    flush_active_table,
    reconcile_pool_policy,
    remove_tunnel_route,
)
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


@dataclass(frozen=True)
class VpnTransitionResult:
    """Summary of a VPN desired-state transition."""

    applied_tunnels: int
    removed_tunnels: int
    active_name: str | None
    active_interface: str | None


def _enabled_tunnels(
    config: SecBoxConfig,
) -> list[WireGuardTunnelConfig]:
    if (
        config.vpn is None
        or not config.vpn.enabled
    ):
        return []

    return [
        tunnel
        for tunnel in config.vpn.tunnels
        if tunnel.enabled
    ]


def get_enabled_tunnels(
    config: SecBoxConfig,
) -> list[WireGuardTunnelConfig]:
    """Return enabled tunnels for an enabled VPN configuration."""

    if config.vpn is None:
        raise VpnServiceError(
            "VPN configuration is not defined"
        )

    if not config.vpn.enabled:
        raise VpnServiceError(
            "VPN is disabled"
        )

    enabled_tunnels = _enabled_tunnels(
        config
    )

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

    validate_vpn_config(
        config
    )

    if validate_keys:
        validate_vpn_key_paths(
            config
        )

    enabled_tunnels = get_enabled_tunnels(
        config
    )

    for tunnel in enabled_tunnels:
        apply_wireguard_tunnel(
            tunnel
        )

    configure_pool_policy(
        enabled_tunnels
    )

    initial_tunnel = min(
        enabled_tunnels,
        key=lambda tunnel: tunnel.priority,
    )

    activate_tunnel(
        initial_tunnel
    )

    return VpnApplyResult(
        applied_tunnels=len(
            enabled_tunnels
        ),
        active_name=initial_tunnel.name,
        active_interface=initial_tunnel.interface,
    )


def reconcile_vpn_config(
    previous_config: SecBoxConfig,
    desired_config: SecBoxConfig,
    *,
    validate_keys: bool = True,
) -> VpnTransitionResult:
    """Move VPN runtime from previous configuration to desired state."""

    validate_vpn_config(
        desired_config
    )

    desired_tunnels = _enabled_tunnels(
        desired_config
    )

    previous_tunnels = _enabled_tunnels(
        previous_config
    )

    if desired_tunnels and validate_keys:
        validate_vpn_key_paths(
            desired_config
        )

    previous_by_interface = {
        tunnel.interface: tunnel
        for tunnel in previous_tunnels
    }

    desired_by_interface = {
        tunnel.interface: tunnel
        for tunnel in desired_tunnels
    }

    #
    # First create/update desired tunnels.
    # Existing working tunnels remain available while the new desired
    # state is being prepared.
    #
    for tunnel in desired_tunnels:
        apply_wireguard_tunnel(
            tunnel
        )

    #
    # Select the desired active path before removing old interfaces.
    #
    active_tunnel: WireGuardTunnelConfig | None = None

    if desired_tunnels:
        active_tunnel = min(
            desired_tunnels,
            key=lambda tunnel: tunnel.priority,
        )

        activate_tunnel(
            active_tunnel
        )

    #
    # Replace source policy rules using both old and new state so stale
    # source-network rules are removed as well.
    #
    reconcile_pool_policy(
        previous_tunnels,
        desired_tunnels,
    )

    stale_interfaces = (
        set(previous_by_interface)
        - set(desired_by_interface)
    )

    desired_tables = {
        tunnel.routing_table
        for tunnel in desired_tunnels
    }

    removed_tunnels = 0

    #
    # Delete interfaces which no longer exist in desired state.
    #
    for interface in sorted(
        stale_interfaces
    ):
        tunnel = previous_by_interface[
            interface
        ]

        remove_wireguard_tunnel(
            tunnel,
            remove_route=(
                tunnel.routing_table
                not in desired_tables
            ),
        )

        removed_tunnels += 1

    #
    # A tunnel can keep the same interface but move to another table.
    # Clean old tables which are no longer referenced by desired state.
    #
    cleaned_tables: set[int] = set()

    for tunnel in previous_tunnels:
        if (
            tunnel.routing_table
            in desired_tables
        ):
            continue

        if (
            tunnel.routing_table
            in cleaned_tables
        ):
            continue

        remove_tunnel_route(
            tunnel
        )

        cleaned_tables.add(
            tunnel.routing_table
        )

    #
    # If VPN was disabled completely there must be no active default
    # route left in table 250.
    #
    if not desired_tunnels:
        flush_active_table()

    return VpnTransitionResult(
        applied_tunnels=len(
            desired_tunnels
        ),
        removed_tunnels=removed_tunnels,
        active_name=(
            active_tunnel.name
            if active_tunnel is not None
            else None
        ),
        active_interface=(
            active_tunnel.interface
            if active_tunnel is not None
            else None
        ),
    )
