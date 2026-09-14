"""Privileged VPN configuration action."""

import subprocess
from pathlib import Path
from dataclasses import dataclass

from secbox.core.config_store import ConfigStore
from secbox.core.transactions.vpn import (
    VpnTransactionError,
    VpnTransactionResult,
    apply_vpn_transaction,
)
from secbox.modules.vpn.models import VpnConfig
from secbox.modules.vpn.service import (
    reconcile_vpn_config,
)


CONFIG_PATH = "/etc/secbox/config.yml"
VPN_SERVICE = "secbox-vpn.service"


class VpnActionError(RuntimeError):
    """Raised when privileged VPN action cannot complete."""


@dataclass(frozen=True)
class VpnActionResult:
    """Public result of a successful VPN configuration action."""

    applied_tunnels: int
    removed_tunnels: int
    active_name: str | None
    active_interface: str | None


def _restart_vpn_service() -> None:
    result = subprocess.run(
        [
            "/usr/bin/systemctl",
            "restart",
            VPN_SERVICE,
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise VpnActionError(
            "VPN service restart failed"
        )


def apply_vpn_action(
    vpn: VpnConfig,
    *,
    store: ConfigStore | None = None,
) -> VpnActionResult:
    """Apply VPN configuration and restart the failover daemon."""

    store = (
        store
        if store is not None
        else ConfigStore(
            Path(CONFIG_PATH)
        )
    )

    previous_config = store.load()

    try:
        transaction_result: VpnTransactionResult = (
            apply_vpn_transaction(
                store,
                vpn,
            )
        )

    except VpnTransactionError as error:
        raise VpnActionError(
            "VPN configuration transaction failed"
        ) from error

    try:
        _restart_vpn_service()

    except Exception as restart_error:
        rollback_errors: list[str] = []

        desired_config = (
            transaction_result.config
        )

        try:
            restored_config = (
                store.rollback()
            )

        except Exception as error:
            rollback_errors.append(
                "configuration rollback failed"
            )
            restored_config = (
                previous_config
            )

        try:
            reconcile_vpn_config(
                desired_config,
                restored_config,
            )
        except Exception:
            rollback_errors.append(
                "VPN runtime rollback failed"
            )

        try:
            _restart_vpn_service()
        except Exception:
            rollback_errors.append(
                "VPN service rollback restart failed"
            )

        detail = (
            "; ".join(
                rollback_errors
            )
            if rollback_errors
            else "previous VPN configuration restored"
        )

        raise VpnActionError(
            f"VPN service activation failed; {detail}"
        ) from restart_error

    applied = (
        transaction_result.apply_result
    )

    return VpnActionResult(
        applied_tunnels=applied.applied_tunnels,
        removed_tunnels=applied.removed_tunnels,
        active_name=applied.active_name,
        active_interface=applied.active_interface,
    )



def get_vpn_action(
    *,
    store: ConfigStore | None = None,
) -> VpnConfig:
    """Return VPN configuration without reading secret key contents."""

    store = (
        store
        if store is not None
        else ConfigStore(
            Path(CONFIG_PATH)
        )
    )

    config = store.load()

    if config.vpn is None:
        return VpnConfig(
            enabled=False,
            tunnels=[],
        )

    return config.vpn
