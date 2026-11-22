"""Privileged transactional Content Filter configuration action."""

from dataclasses import dataclass
from pathlib import Path
import subprocess

from secbox.core.config_store import ConfigStore
from secbox.modules.content_filter.models import ContentFilterConfig
from secbox.modules.content_filter.validator import validate_content_filter_config
from secbox.modules.dhcp.executor import apply_dnsmasq_config
from secbox.modules.dhcp.renderer import render_dnsmasq_config
from secbox.modules.content_filter.doh_feed.models import (
    DohFeedState,
)
from secbox.modules.content_filter.doh_feed.store import (
    DohFeedStore,
    DohFeedStoreError,
)


CONFIG_PATH = Path("/etc/secbox/config.yml")

DHCP_RENDERED = Path("/run/secbox/secbox-dhcp.conf")
DHCP_TARGET = Path("/etc/dnsmasq.d/secbox-dhcp.conf")
DHCP_BACKUP = Path("/var/lib/secbox/dhcp/secbox-dhcp.conf.bak")


class ContentFilterActionError(RuntimeError):
    """Content Filter transaction failed."""


@dataclass(frozen=True)
class ContentFilterActionResult:
    enabled: bool
    default_action: str
    blocked_domains: int
    allowed_domains: int
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


def _managed_feed_active(config) -> bool:
    """Return whether managed DoH must be active."""

    content_filter = config.content_filter

    if content_filter is None:
        return False

    doh = content_filter.encrypted_dns.doh

    return bool(
        content_filter.enabled
        and doh.enabled
        and doh.managed_feed_enabled
    )


def _restore_feed_units(
    *,
    active: bool,
) -> None:
    """Restore timer lifecycle without forcing a feed refresh."""

    if active:
        _systemctl(
            "enable",
            "secbox-doh-feed.timer",
        )
        _systemctl(
            "start",
            "secbox-doh-feed.timer",
        )
        return

    _systemctl(
        "stop",
        "secbox-doh-feed.service",
    )
    _systemctl(
        "stop",
        "secbox-doh-feed.timer",
    )
    _systemctl(
        "disable",
        "secbox-doh-feed.timer",
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

    doh_store = DohFeedStore()

    try:
        previous_doh_state = doh_store.load()

    except DohFeedStoreError as error:
        raise ContentFilterActionError(
            "failed to load previous managed DoH state: "
            f"{error}"
        ) from error

    previous_feed_active = (
        _managed_feed_active(previous)
    )

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

    candidate_feed_active = (
        _managed_feed_active(candidate)
    )

    previous_doh = (
        previous.content_filter.encrypted_dns.doh
        if (
            previous.content_filter is not None
        )
        else None
    )

    candidate_doh = (
        candidate.content_filter.encrypted_dns.doh
        if (
            candidate.content_filter is not None
        )
        else None
    )

    feed_configuration_changed = (
        previous_doh != candidate_doh
    )

    try:
        store.save(candidate)

        _apply_dns(candidate)

        if not candidate_feed_active:
            # Stop every producer before clearing its state.
            _systemctl(
                "stop",
                "secbox-doh-feed.service",
            )
            _systemctl(
                "stop",
                "secbox-doh-feed.timer",
            )
            _systemctl(
                "disable",
                "secbox-doh-feed.timer",
            )

            doh_store.save(
                DohFeedState()
            )

        elif not previous_feed_active:
            # Legacy/stale managed state must never be reused when
            # the feed is enabled again. Start from static resolvers
            # and require a fresh successful download.
            doh_store.save(
                DohFeedState()
            )

        # Firewall reads the candidate configuration and current
        # managed state, therefore this establishes the exact
        # effective static + managed DoH set.
        _systemctl(
            "restart",
            "secbox-firewall.service",
        )

        if candidate_feed_active:
            _systemctl(
                "enable",
                "secbox-doh-feed.timer",
            )
            _systemctl(
                "start",
                "secbox-doh-feed.timer",
            )

            if (
                not previous_feed_active
                or feed_configuration_changed
            ):
                # Immediate refresh when enabling the feed or
                # changing its source/settings.
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
            doh_store.save(
                previous_doh_state
            )

        except Exception as rollback_error:
            rollback_errors.append(
                "DoH state rollback: "
                f"{rollback_error}"
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

        try:
            _restore_feed_units(
                active=previous_feed_active,
            )

        except Exception as rollback_error:
            rollback_errors.append(
                "DoH unit rollback: "
                f"{rollback_error}"
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
        default_action=(
            content_filter.policy.default_action
        ),
        blocked_domains=len(
            content_filter.policy.blocked_domains
        ),
        allowed_domains=len(
            content_filter.policy.allowed_domains
        ),
        doh_enabled=(
            content_filter.encrypted_dns.doh.enabled
        ),
        managed_feed_enabled=(
            content_filter.encrypted_dns.doh.managed_feed_enabled
        ),
    )
