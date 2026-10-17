"""Privileged transactional Firewall configuration action."""

from dataclasses import dataclass
from pathlib import Path
import subprocess

from secbox.core.config_store import ConfigStore
from secbox.modules.content_filter.validator import (
    validate_content_filter_config,
)
from secbox.modules.firewall.models import FirewallConfig
from secbox.modules.firewall.validator import (
    validate_firewall_preflight,
)


CONFIG_PATH = Path("/etc/secbox/config.yml")
FIREWALL_SERVICE = "secbox-firewall.service"


class FirewallActionError(RuntimeError):
    """Firewall transaction failed."""


@dataclass(frozen=True)
class FirewallActionResult:
    enabled: bool
    wan_interface: str
    lan_interface: str
    management_interface: str
    nat_enabled: bool
    dynamic_blacklist_enabled: bool


def _restart_firewall() -> None:
    result = subprocess.run(
        [
            "/usr/bin/systemctl",
            "restart",
            FIREWALL_SERVICE,
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        message = (
            result.stderr.strip()
            or result.stdout.strip()
            or f"exit code {result.returncode}"
        )

        raise FirewallActionError(
            f"firewall service restart failed: {message}"
        )


def get_firewall_action(
    *,
    store: ConfigStore | None = None,
) -> FirewallConfig | None:
    store = store or ConfigStore(CONFIG_PATH)
    return store.load().firewall


def apply_firewall_action(
    firewall: FirewallConfig,
    *,
    store: ConfigStore | None = None,
) -> FirewallActionResult:
    store = store or ConfigStore(CONFIG_PATH)
    previous = store.load()

    if not firewall.enabled:
        raise FirewallActionError(
            "disabling the firewall is not supported by runtime apply"
        )

    candidate = previous.model_copy(
        update={
            "firewall": firewall,
        }
    )

    candidate = type(previous).model_validate(
        candidate.model_dump(mode="json")
    )

    try:
        validate_firewall_preflight(
            candidate.firewall,
            candidate.network,
        )

        validate_content_filter_config(candidate)

    except Exception as error:
        raise FirewallActionError(
            f"Firewall validation failed: {error}"
        ) from error

    try:
        store.save(candidate)
        _restart_firewall()

    except Exception as error:
        rollback_errors: list[str] = []

        try:
            store.save(previous)
        except Exception as rollback_error:
            rollback_errors.append(
                f"configuration rollback failed: {rollback_error}"
            )

        try:
            _restart_firewall()
        except Exception as rollback_error:
            rollback_errors.append(
                f"runtime rollback failed: {rollback_error}"
            )

        detail = (
            "; ".join(rollback_errors)
            if rollback_errors
            else "previous configuration restored"
        )

        raise FirewallActionError(
            f"Firewall apply failed: {error}; {detail}"
        ) from error

    return FirewallActionResult(
        enabled=firewall.enabled,
        wan_interface=firewall.wan_interface,
        lan_interface=firewall.lan_interface,
        management_interface=firewall.management_interface,
        nat_enabled=firewall.enable_nat,
        dynamic_blacklist_enabled=(
            firewall.dynamic_blacklist_enabled
        ),
    )
