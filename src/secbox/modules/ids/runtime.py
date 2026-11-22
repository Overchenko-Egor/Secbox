"""Runtime construction helpers for the IDS subsystem."""

from typing import TYPE_CHECKING

import ipaddress
from datetime import timedelta
from secbox.modules.ids.response import IdsResponseHandler
from secbox.core.models import SecBoxConfig
from secbox.modules.ids.config import (
    IdsConfig,
)
from secbox.modules.ids.policy import (
    IdsPolicyConfig,
)
from secbox.modules.network.state import (
    NetworkInterfaceState,
)


if TYPE_CHECKING:
    from secbox.modules.ids.worker import (
        StreamingIdsWorker,
    )


class IdsRuntimeConfigError(Exception):
    """Raised when IDS runtime configuration is invalid."""


def build_configured_protected_networks(
    config: SecBoxConfig,
) -> tuple[ipaddress.IPv4Network, ...]:
    """Build explicitly configured IDS protected networks."""

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


def build_runtime_local_networks(
    runtime_interfaces: list[
        NetworkInterfaceState
    ],
) -> tuple[ipaddress.IPv4Network, ...]:
    """Build /32 networks for all local SecBox IPv4 addresses."""

    networks: list[
        ipaddress.IPv4Network
    ] = []

    for interface in runtime_interfaces:
        for address in interface.addresses:
            if address.family != "inet":
                continue

            try:
                parsed = ipaddress.ip_address(
                    address.address
                )
            except ValueError as error:
                raise IdsRuntimeConfigError(
                    "invalid runtime IPv4 address "
                    f"on {interface.name}: "
                    f"{address.address}"
                ) from error

            if not isinstance(
                parsed,
                ipaddress.IPv4Address,
            ):
                continue

            networks.append(
                ipaddress.IPv4Network(
                    f"{parsed}/32"
                )
            )

    return tuple(networks)


def build_protected_networks(
    config: SecBoxConfig,
    runtime_interfaces: list[
        NetworkInterfaceState
    ],
) -> tuple[ipaddress.IPv4Network, ...]:
    """Build effective networks protected from IDS blocking."""

    configured = (
        build_configured_protected_networks(
            config
        )
    )

    runtime_local = (
        build_runtime_local_networks(
            runtime_interfaces
        )
    )

    networks: list[
        ipaddress.IPv4Network
    ] = []

    seen: set[
        ipaddress.IPv4Network
    ] = set()

    for network in (
        *configured,
        *runtime_local,
    ):
        if network in seen:
            continue

        seen.add(network)
        networks.append(network)

    return tuple(networks)


def build_ids_policy_config(
    config: SecBoxConfig,
    runtime_interfaces: list[
        NetworkInterfaceState
    ],
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
            build_protected_networks(
                config,
                runtime_interfaces,
            )
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


def build_ids_response_handler(
    config: SecBoxConfig,
    runtime_interfaces: list[
        NetworkInterfaceState
    ],
) -> IdsResponseHandler:
    """Create the automatic IDS response handler."""

    return IdsResponseHandler(
        automatic_blackhole_enabled=(
            config.ids
            .automatic_blackhole
            .enabled
        ),
        automatic_blackhole_timeout=(
            config.ids
            .automatic_blackhole
            .timeout
        ),
        automatic_deception_enabled=(
            config.ids
            .automatic_deception
            .enabled
        ),
        protected_networks=tuple(
            str(network)
            for network in build_protected_networks(
                config,
                runtime_interfaces,
            )
        ),
    )

def refresh_ids_runtime_state(
    config: SecBoxConfig,
    runtime_interfaces: list[
        NetworkInterfaceState
    ],
    worker: "StreamingIdsWorker",
    response_handler: IdsResponseHandler,
) -> None:
    """Refresh worker and response runtime state."""

    protected_networks = tuple(
        str(network)
        for network in build_protected_networks(
            config,
            runtime_interfaces,
        )
    )

    worker.refresh_runtime(
        runtime_interfaces
    )

    response_handler.refresh_protected_networks(
        protected_networks
    )

