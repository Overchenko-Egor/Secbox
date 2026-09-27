"""Privileged transactional Network + DHCP configuration action."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from secbox.core.config_store import ConfigStore
from secbox.modules.content_filter.validator import (
    validate_content_filter_config,
)
from secbox.modules.dhcp.executor import apply_dnsmasq_config
from secbox.modules.dhcp.models import DhcpServerConfig
from secbox.modules.dhcp.renderer import render_dnsmasq_config
from secbox.modules.dhcp.validator import validate_dhcp_preflight
from secbox.modules.network.discovery import (
    discover_manageable_interfaces,
)
from secbox.modules.network.executor import apply_networkd_config
from secbox.modules.network.models import NetworkConfig
from secbox.modules.network.runtime import (
    NetworkRuntimeStore,
    metadata_from_config,
)
from secbox.modules.network.validator import (
    validate_management_interface,
    validate_network_preflight,
)
from secbox.modules.vpn.validator import validate_l2_access_ports


CONFIG_PATH = Path("/etc/secbox/config.yml")

NETWORK_STAGE = Path("/run/secbox/network-stage")
NETWORK_TARGET = Path("/etc/systemd/network")
NETWORK_BACKUP = Path("/var/lib/secbox/network-backup")

DHCP_RENDERED = Path("/run/secbox/secbox-dhcp.conf")
DHCP_TARGET = Path("/etc/dnsmasq.d/secbox-dhcp.conf")
DHCP_BACKUP = Path("/var/lib/secbox/dhcp/secbox-dhcp.conf.bak")


class NetworkDhcpActionError(RuntimeError):
    """Raised when Network/DHCP transaction cannot complete."""


@dataclass(frozen=True)
class NetworkDhcpActionResult:
    interfaces: int
    dhcp_scopes: int
    enabled_dhcp_scopes: int


def _validate_candidate(candidate) -> None:
    runtime_interfaces = discover_manageable_interfaces()

    validate_network_preflight(
        candidate.network,
        runtime_interfaces,
    )

    validate_management_interface(
        candidate.network,
        runtime_interfaces,
    )

    validate_dhcp_preflight(
        candidate.dhcp,
        candidate.network,
        candidate.vpn,
    )

    validate_content_filter_config(candidate)

    if candidate.vpn is not None:
        validate_l2_access_ports(candidate)


def _apply_network(network: NetworkConfig) -> None:
    apply_networkd_config(
        config=network,
        staging_dir=NETWORK_STAGE,
        target_dir=NETWORK_TARGET,
        backup_dir=NETWORK_BACKUP,
    )


def _apply_dhcp(candidate) -> None:
    render_dnsmasq_config(
        candidate.dhcp,
        DHCP_RENDERED,
        content_filter=candidate.content_filter,
    )

    apply_dnsmasq_config(
        rendered_file=DHCP_RENDERED,
        target_file=DHCP_TARGET,
        backup_file=DHCP_BACKUP,
    )


def _restore_runtime(previous) -> list[str]:
    errors: list[str] = []

    try:
        _apply_network(previous.network)
    except Exception as error:
        errors.append(
            f"network runtime rollback failed: {error}"
        )

    try:
        _apply_dhcp(previous)
    except Exception as error:
        errors.append(
            f"DHCP runtime rollback failed: {error}"
        )

    try:
        NetworkRuntimeStore().save(
            metadata_from_config(previous.network)
        )
    except Exception as error:
        errors.append(
            f"network metadata rollback failed: {error}"
        )

    return errors


def get_network_dhcp_action(
    *,
    store: ConfigStore | None = None,
) -> tuple[NetworkConfig, list[DhcpServerConfig]]:
    store = store or ConfigStore(CONFIG_PATH)
    config = store.load()

    return config.network, config.dhcp


def apply_network_dhcp_action(
    network: NetworkConfig,
    dhcp: list[DhcpServerConfig],
    *,
    store: ConfigStore | None = None,
) -> NetworkDhcpActionResult:
    """Validate, persist and activate Network + DHCP as one transaction."""

    store = store or ConfigStore(CONFIG_PATH)

    previous = store.load()

    candidate = previous.model_copy(
        update={
            "network": network,
            "dhcp": dhcp,
        }
    )

    # Revalidate complete SecBox model rather than trusting model_copy.
    candidate = type(previous).model_validate(
        candidate.model_dump(mode="json")
    )

    try:
        _validate_candidate(candidate)
    except Exception as error:
        raise NetworkDhcpActionError(
            f"Network/DHCP validation failed: {error}"
        ) from error

    config_saved = False
    network_applied = False

    try:
        # Persist desired state before runtime activation.
        # ConfigStore writes atomically and keeps its normal .bak.
        store.save(candidate)
        config_saved = True

        _apply_network(candidate.network)
        network_applied = True

        _apply_dhcp(candidate)

        NetworkRuntimeStore().save(
            metadata_from_config(candidate.network)
        )

    except Exception as apply_error:
        rollback_errors: list[str] = []

        if config_saved:
            try:
                store.save(previous)
            except Exception as error:
                rollback_errors.append(
                    f"configuration rollback failed: {error}"
                )

        # Network executor performs its own rollback if network apply itself
        # fails. If network was already activated and DHCP then failed,
        # explicitly restore the complete previous runtime.
        if network_applied:
            rollback_errors.extend(
                _restore_runtime(previous)
            )

        detail = (
            "; ".join(rollback_errors)
            if rollback_errors
            else "previous configuration restored"
        )

        raise NetworkDhcpActionError(
            f"Network/DHCP apply failed: {apply_error}; {detail}"
        ) from apply_error

    return NetworkDhcpActionResult(
        interfaces=len(candidate.network.interfaces),
        dhcp_scopes=len(candidate.dhcp),
        enabled_dhcp_scopes=sum(
            1 for scope in candidate.dhcp if scope.enabled
        ),
    )
