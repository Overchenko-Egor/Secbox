"""Privileged Dynamic Blackhole actions."""

from __future__ import annotations

import os

from datetime import UTC, datetime
from pathlib import Path

from secbox.core.config_store import (
    ConfigStore,
    ConfigStoreError,
)
from secbox.modules.blacklist.service import (
    BlacklistError,
    add_blacklist_entry,
    delete_blacklist_entry,
    list_blacklist_entries,
    list_blacklist_state,
    parse_timeout,
    reconcile_blacklist,
    validate_ipv4_address,
)
from secbox.modules.network.discovery import (
    discover_interfaces,
)


CONFIG_PATH = Path(
    os.environ.get(
        "SECBOX_CONFIG_PATH",
        "/etc/secbox/config.yml",
    )
)


class BlackholeActionError(RuntimeError):
    """Privileged blackhole operation failed."""


def _load_config(
    store: ConfigStore | None = None,
):
    store = store or ConfigStore(
        CONFIG_PATH
    )

    try:
        return store.load()

    except ConfigStoreError as error:
        raise BlackholeActionError(
            f"failed to load SecBox configuration: {error}"
        ) from error


def _firewall(config):
    firewall = config.firewall

    if (
        firewall is None
        or not firewall.enabled
    ):
        raise BlackholeActionError(
            "firewall is disabled"
        )

    if not firewall.dynamic_blacklist_enabled:
        raise BlackholeActionError(
            "dynamic blacklist is disabled"
        )

    return firewall


def _protected_networks(
    firewall,
) -> list[str]:
    protected = set(
        str(item)
        for item in (
            firewall
            .dynamic_blacklist_protected_networks
        )
    )

    try:
        interfaces = discover_interfaces()

    except Exception as error:
        raise BlackholeActionError(
            "failed to discover local interfaces: "
            f"{error}"
        ) from error

    for interface in interfaces:
        for address in interface.addresses:
            if address.family != "inet":
                continue

            if not address.address:
                continue

            protected.add(
                f"{address.address}/32"
            )

    return sorted(protected)


def _manual_reason(
    value: str,
) -> str:
    reason = value.strip()

    if not reason:
        reason = "manual"

    if len(reason) > 160:
        raise BlackholeActionError(
            "reason is too long"
        )

    if not reason.isprintable():
        raise BlackholeActionError(
            "reason contains control characters"
        )

    return reason


def get_blackhole_runtime_action(
    *,
    store: ConfigStore | None = None,
) -> dict[str, object]:
    """Return sanitized blacklist configuration and runtime state."""

    config = _load_config(
        store
    )

    firewall = config.firewall

    enabled = bool(
        firewall is not None
        and firewall.enabled
        and firewall.dynamic_blacklist_enabled
    )

    default_timeout = (
        firewall.dynamic_blacklist_timeout
        if firewall is not None
        else None
    )

    protected_networks = (
        _protected_networks(
            firewall
        )
        if firewall is not None
        else []
    )

    try:
        persistent = (
            list_blacklist_state()
        )

        runtime = (
            set(
                list_blacklist_entries()
            )
            if enabled
            else set()
        )

    except BlacklistError as error:
        raise BlackholeActionError(
            str(error)
        ) from error

    now = datetime.now(UTC)

    entries = []

    persistent_addresses = set()

    for entry in persistent:
        persistent_addresses.add(
            entry.address
        )

        remaining = max(
            0,
            int(
                (
                    entry.expires_at
                    - now
                ).total_seconds()
            ),
        )

        entries.append(
            {
                "address":
                    entry.address,
                "reason":
                    entry.reason,
                "source":
                    entry.source,
                "created_at":
                    entry.created_at.isoformat(),
                "expires_at":
                    entry.expires_at.isoformat(),
                "remaining_seconds":
                    remaining,
                "runtime_present":
                    entry.address in runtime,
            }
        )

    entries.sort(
        key=lambda item: (
            item["expires_at"],
            item["address"],
        )
    )

    runtime_only = sorted(
        runtime
        - persistent_addresses
    )

    persistent_only = sorted(
        persistent_addresses
        - runtime
    )

    consistent = (
        not runtime_only
        and not persistent_only
    )

    return {
        "enabled":
            enabled,
        "default_timeout":
            default_timeout,
        "protected_networks":
            protected_networks,
        "persistent_count":
            len(persistent_addresses),
        "runtime_count":
            len(runtime),
        "consistent":
            consistent,
        "runtime_only":
            runtime_only,
        "persistent_only":
            persistent_only,
        "entries":
            entries,
    }


def add_blackhole_action(
    *,
    address: str,
    timeout: str,
    reason: str,
    store: ConfigStore | None = None,
) -> dict[str, object]:
    """Add one manually requested blackhole entry."""

    config = _load_config(
        store
    )

    firewall = _firewall(
        config
    )

    try:
        normalized = (
            validate_ipv4_address(
                address
            )
        )

        effective_timeout = (
            timeout.strip()
            or firewall.dynamic_blacklist_timeout
        )

        parse_timeout(
            effective_timeout
        )

        effective_reason = (
            _manual_reason(
                reason
            )
        )

        protected = (
            _protected_networks(
                firewall
            )
        )

        add_blacklist_entry(
            address=normalized,
            timeout=effective_timeout,
            reason=effective_reason,
            source="web",
            protected_networks=protected,
        )

    except BlacklistError as error:
        raise BlackholeActionError(
            str(error)
        ) from error

    return {
        "address":
            normalized,
        "timeout":
            effective_timeout,
        "reason":
            effective_reason,
        "source":
            "web",
    }


def delete_blackhole_action(
    *,
    address: str,
) -> dict[str, object]:
    """Remove one blacklist entry."""

    try:
        normalized = (
            validate_ipv4_address(
                address
            )
        )

        delete_blacklist_entry(
            normalized
        )

    except BlacklistError as error:
        raise BlackholeActionError(
            str(error)
        ) from error

    return {
        "address":
            normalized,
        "removed":
            True,
    }


def reconcile_blackhole_action(
) -> dict[str, object]:
    """Reconcile persistent blacklist state with nftables."""

    try:
        restored, expired = (
            reconcile_blacklist()
        )

    except BlacklistError as error:
        raise BlackholeActionError(
            str(error)
        ) from error

    return {
        "restored":
            restored,
        "expired_removed":
            expired,
    }
