"""Transactional VPN configuration updates."""

from dataclasses import dataclass

from secbox.core.config_store import (
    ConfigStore,
    ConfigStoreError,
)
from secbox.core.models import SecBoxConfig
from secbox.modules.vpn.models import VpnConfig
from secbox.modules.vpn.service import (
    VpnApplyResult,
    apply_vpn_config,
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
    apply_result: VpnApplyResult


def build_vpn_candidate(
    current_config: SecBoxConfig,
    vpn: VpnConfig,
) -> SecBoxConfig:
    """Build and fully validate a SecBox config with a new VPN section."""

    candidate = SecBoxConfig.model_validate(
        {
            **current_config.model_dump(
                mode="python"
            ),
            "vpn": vpn.model_dump(
                mode="python"
            ),
        }
    )

    validate_vpn_config(candidate)

    return candidate


def apply_vpn_transaction(
    store: ConfigStore,
    vpn: VpnConfig,
) -> VpnTransactionResult:
    """Persist and apply VPN config, restoring the previous config on failure.

    The previous persistent configuration is restored if applying the new VPN
    pool fails. An attempt is then made to re-apply the previous VPN runtime.
    """

    try:
        current_config = store.load()
        candidate = build_vpn_candidate(
            current_config,
            vpn,
        )

        validate_vpn_key_paths(candidate)

    except Exception as error:
        raise VpnTransactionError(
            f"VPN transaction validation failed: {error}"
        ) from error

    try:
        store.save(candidate)
    except ConfigStoreError as error:
        raise VpnTransactionError(
            f"VPN configuration could not be saved: {error}"
        ) from error

    try:
        result = apply_vpn_config(
            candidate,
            validate_keys=False,
        )

    except Exception as apply_error:
        rollback_errors: list[str] = []

        try:
            restored = store.rollback()
        except Exception as error:
            rollback_errors.append(
                f"configuration rollback failed: {error}"
            )
            restored = current_config

        if (
            restored.vpn is not None
            and restored.vpn.enabled
        ):
            try:
                apply_vpn_config(restored)
            except Exception as error:
                rollback_errors.append(
                    f"previous VPN runtime could not be restored: {error}"
                )

        detail = (
            "; ".join(rollback_errors)
            if rollback_errors
            else "previous configuration restored"
        )

        raise VpnTransactionError(
            f"VPN apply failed: {apply_error}; {detail}"
        ) from apply_error

    return VpnTransactionResult(
        config=candidate,
        apply_result=result,
    )
