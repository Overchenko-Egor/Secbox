"""Runtime construction helpers for the IDS subsystem."""

import ipaddress
from datetime import timedelta

from secbox.core.models import SecBoxConfig
from secbox.modules.ids.config import (
    IdsConfig,
)
from secbox.modules.ids.policy import (
    IdsPolicyConfig,
)


class IdsRuntimeConfigError(Exception):
    """Raised when IDS runtime configuration is invalid."""


def build_protected_networks(
    config: SecBoxConfig,
) -> tuple[ipaddress.IPv4Network, ...]:
    """Build IDS protected networks from SecBox configuration."""

    if config.firewall is None:
        return ()

    networks: list[
        ipaddress.IPv4Network
    ] = []

    for network_text in (
        config.firewall
        .dynamic_blacklist_protected_networks
    ):
        try:
            network = ipaddress.ip_network(
                network_text,
                strict=False,
            )
        except ValueError as error:
            raise IdsRuntimeConfigError(
                "invalid protected network: "
                f"{network_text}"
            ) from error

        if not isinstance(
            network,
            ipaddress.IPv4Network,
        ):
            raise IdsRuntimeConfigError(
                "only IPv4 protected networks "
                "are currently supported: "
                f"{network_text}"
            )

        networks.append(network)

    return tuple(networks)


def build_ids_policy_config(
    config: SecBoxConfig,
) -> IdsPolicyConfig:
    """Create runtime Policy Engine configuration."""

    settings = config.ids.policy

    return IdsPolicyConfig(
        minimum_alert_count=(
            settings.minimum_alert_count
        ),
        minimum_block_count=(
            settings.minimum_block_count
        ),
        maximum_alert_severity=(
            settings.maximum_alert_severity
        ),
        maximum_block_severity=(
            settings.maximum_block_severity
        ),
        protected_networks=(
            build_protected_networks(config)
        ),
    )


def get_nat_correlation_window(
    config: IdsConfig,
) -> timedelta:
    """Return configured NAT correlation window."""

    return timedelta(
        milliseconds=(
            config.nat_correlation_window_ms
        )
    )


def get_aggregation_window(
    config: IdsConfig,
) -> timedelta:
    """Return configured IDS aggregation window."""

    return timedelta(
        seconds=(
            config.aggregation_window_seconds
        )
    )
