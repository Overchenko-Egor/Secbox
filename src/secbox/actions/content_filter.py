"""Privileged transactional Content Filter configuration action."""

from dataclasses import dataclass
from pathlib import Path
import subprocess

from secbox.core.config_store import ConfigStore
from secbox.modules.content_filter.models import ContentFilterConfig
from secbox.modules.content_filter.validator import validate_content_filter_config
from secbox.modules.dhcp.executor import apply_dnsmasq_config
from secbox.modules.dhcp.renderer import render_dnsmasq_config


CONFIG_PATH = Path("/etc/secbox/config.yml")

DHCP_RENDERED = Path("/run/secbox/secbox-dhcp.conf")
DHCP_TARGET = Path("/etc/dnsmasq.d/secbox-dhcp.conf")
DHCP_BACKUP = Path("/var/lib/secbox/dhcp/secbox-dhcp.conf.bak")


class ContentFilterActionError(RuntimeError):
    """Content Filter transaction failed."""


@dataclass(frozen=True)
class ContentFilterActionResult:
    enabled: bool
    blocked_domains: int
    doh_enabled: bool
    managed_feed_enabled: bool


def _apply_dns(config) -> None:
    render_dnsmasq_config(
        config.dhcp,
        DHCP_RENDERED,
        content_filter=config.content_filter,
    )

    apply_dnsmasq_config(
        rendered_file=DHCP_RENDERED,
        target_file=DHCP_TARGET,
        backup_file=DHCP_BACKUP,
    )


def _systemctl(action: str, unit: str) -> None:
    result = subprocess.run(
        ["/usr/bin/systemctl", action, unit],
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

        raise ContentFilterActionError(
            f"{action} {unit} failed: {message}"
        )


def get_content_filter_action(
    *,
    store: ConfigStore | None = None,
) -> ContentFilterConfig | None:
    store = store or ConfigStore(CONFIG_PATH)
    return store.load().content_filter


def apply_content_filter_action(
    content_filter: ContentFilterConfig,
    *,
    store: ConfigStore | None = None,
) -> ContentFilterActionResult:
    store = store or ConfigStore(CONFIG_PATH)
    previous = store.load()

    candidate = previous.model_copy(
        update={"content_filter": content_filter}
    )

    candidate = type(previous).model_validate(
        candidate.model_dump(mode="json")
    )

    try:
        validate_content_filter_config(candidate)
    except Exception as error:
        raise ContentFilterActionError(
            f"Content Filter validation failed: {error}"
        ) from error

    try:
        store.save(candidate)

        _apply_dns(candidate)

        _systemctl(
            "restart",
            "secbox-firewall.service",
        )

        doh = candidate.content_filter.encrypted_dns.doh

        if (
            candidate.content_filter.enabled
            and doh.enabled
            and doh.managed_feed_enabled
        ):
            _systemctl(
                "start",
                "secbox-doh-feed.service",
            )

    except Exception as error:
        rollback_errors = []

        try:
            store.save(previous)
        except Exception as rollback_error:
            rollback_errors.append(
                f"config rollback: {rollback_error}"
            )

        try:
            _apply_dns(previous)
        except Exception as rollback_error:
            rollback_errors.append(
                f"DNS rollback: {rollback_error}"
            )

        try:
            _systemctl(
                "restart",
                "secbox-firewall.service",
            )
        except Exception as rollback_error:
            rollback_errors.append(
                f"firewall rollback: {rollback_error}"
            )

        detail = (
            "; ".join(rollback_errors)
            if rollback_errors
            else "previous configuration restored"
        )

        raise ContentFilterActionError(
            f"Content Filter apply failed: {error}; {detail}"
        ) from error

    return ContentFilterActionResult(
        enabled=content_filter.enabled,
        blocked_domains=len(
            content_filter.policy.blocked_domains
        ),
        doh_enabled=content_filter.encrypted_dns.doh.enabled,
        managed_feed_enabled=(
            content_filter.encrypted_dns.doh.managed_feed_enabled
        ),
    )
