"""Transactional VPN configuration updates."""

from dataclasses import dataclass

from secbox.core.config_store import (
    ConfigStore,
    ConfigStoreError,
)
from secbox.core.models import SecBoxConfig
from secbox.modules.vpn.models import VpnConfig
from secbox.modules.vpn.service import (
    VpnTransitionResult,
    reconcile_vpn_config,
)
from secbox.modules.vpn.validator import (
    validate_vpn_config,
    validate_vpn_key_paths,
)


class VpnTransactionError(RuntimeError):
    """Raised when a VPN configuration transaction fails."""


@dataclass(frozen=True)
class VpnTransactionResult:
    """Result of a committed VPN configuration transaction."""

    config: SecBoxConfig
    apply_result: VpnTransitionResult


def build_vpn_candidate(
    current_config: SecBoxConfig,
    vpn: VpnConfig,
) -> SecBoxConfig:
    """Build and fully validate SecBox config with a new VPN section."""

    raw = current_config.model_dump(
        mode="python"
    )

    raw["vpn"] = vpn.model_dump(
        mode="python"
    )

    candidate = SecBoxConfig.model_validate(
        raw
    )

    validate_vpn_config(
        candidate
    )

    return candidate


def apply_vpn_transaction(
    store: ConfigStore,
    vpn: VpnConfig,
) -> VpnTransactionResult:
    """Persist and reconcile VPN desired state transactionally."""

    try:
        current_config = store.load()

        candidate = build_vpn_candidate(
            current_config,
            vpn,
        )

        if (
            candidate.vpn is not None
            and candidate.vpn.enabled
        ):
            validate_vpn_key_paths(
                candidate
            )

    except Exception as error:
        raise VpnTransactionError(
            f"VPN transaction validation failed: {error}"
        ) from error

    try:
        store.save(
            candidate
        )

    except ConfigStoreError as error:
        raise VpnTransactionError(
            f"VPN configuration could not be saved: {error}"
        ) from error

    try:
        result = reconcile_vpn_config(
            current_config,
            candidate,
            validate_keys=False,
        )

    except Exception as apply_error:
        rollback_errors: list[str] = []

        try:
            restored_config = store.rollback()

        except Exception as error:
            rollback_errors.append(
                f"configuration rollback failed: {error}"
            )

            restored_config = current_config

        try:
            reconcile_vpn_config(
                candidate,
                restored_config,
            )

        except Exception as error:
            rollback_errors.append(
                "previous VPN runtime could not be restored: "
                f"{error}"
            )

        detail = (
            "; ".join(
                rollback_errors
            )
            if rollback_errors
            else "previous configuration and VPN runtime restored"
        )

        raise VpnTransactionError(
            f"VPN apply failed: {apply_error}; {detail}"
        ) from apply_error

    return VpnTransactionResult(
        config=candidate,
        apply_result=result,
    )
