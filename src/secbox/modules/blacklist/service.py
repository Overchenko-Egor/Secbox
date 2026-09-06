"""Dynamic nftables blacklist management."""

import math
import ipaddress
import json
import subprocess
from datetime import UTC, datetime, timedelta

from secbox.modules.blacklist.models import BlacklistEntry
from secbox.modules.blacklist.lock import (
    BlacklistLockError,
    blacklist_lock,
)
from secbox.modules.blacklist.store import (
    BlacklistStore,
    BlacklistStoreError,
)


NFT_BIN = "/usr/sbin/nft"

NFT_FAMILY = "inet"
NFT_TABLE = "secbox_filter"
NFT_SET = "blacklist_v4"


class BlacklistError(Exception):
    """Raised when dynamic blacklist operation fails."""


def locked_blacklist_operation():
    """Return blacklist operation lock with normalized errors."""

    return blacklist_lock()


def load_store_entries(
    store: BlacklistStore,
) -> list[BlacklistEntry]:
    """Load blacklist state and normalize storage errors."""

    try:
        return store.load()
    except BlacklistStoreError as error:
        raise BlacklistError(
            f"blacklist storage error: {error}"
        ) from error


def save_store_entries(
    store: BlacklistStore,
    entries: list[BlacklistEntry],
) -> None:
    """Save blacklist state and normalize storage errors."""

    try:
        store.save(entries)
    except BlacklistStoreError as error:
        raise BlacklistError(
            f"blacklist storage error: {error}"
        ) from error


def validate_ipv4_address(address: str) -> str:
    """Validate and normalize an IPv4 address."""

    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as error:
        raise BlacklistError(
            f"invalid IP address: {address}"
        ) from error

    if not isinstance(parsed, ipaddress.IPv4Address):
        raise BlacklistError(
            f"only IPv4 addresses are currently supported: {address}"
        )

    return str(parsed)


def validate_not_protected(
    address: str,
    protected_networks: list[str],
) -> None:
    """Reject addresses belonging to protected networks."""

    parsed_address = ipaddress.ip_address(address)

    for network_text in protected_networks:
        try:
            network = ipaddress.ip_network(
                network_text,
                strict=False,
            )
        except ValueError as error:
            raise BlacklistError(
                f"invalid protected network: {network_text}"
            ) from error

        if not isinstance(
            network,
            ipaddress.IPv4Network,
        ):
            raise BlacklistError(
                "only IPv4 protected networks are "
                f"currently supported: {network_text}"
            )

        if parsed_address in network:
            raise BlacklistError(
                f"address {address} belongs to protected "
                f"network {network}"
            )

def parse_timeout(timeout: str) -> timedelta:
    """Parse simple nftables timeout values."""

    if len(timeout) < 2:
        raise BlacklistError(
            f"invalid timeout: {timeout}"
        )

    value_text = timeout[:-1]
    unit = timeout[-1]

    try:
        value = int(value_text)
    except ValueError as error:
        raise BlacklistError(
            f"invalid timeout: {timeout}"
        ) from error

    if value <= 0:
        raise BlacklistError(
            "timeout must be greater than zero"
        )

    if unit == "s":
        return timedelta(seconds=value)

    if unit == "m":
        return timedelta(minutes=value)

    if unit == "h":
        return timedelta(hours=value)

    if unit == "d":
        return timedelta(days=value)

    raise BlacklistError(
        f"unsupported timeout unit: {unit}"
    )


def run_nft(
    command: list[str],
) -> subprocess.CompletedProcess[str]:
    """Run nftables command."""

    try:
        return subprocess.run(
            [NFT_BIN, *command],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as error:
        message = error.stderr.strip() or str(error)

        raise BlacklistError(
            f"nftables command failed: {message}"
        ) from error
    except OSError as error:
        raise BlacklistError(
            f"failed to execute nftables: {error}"
        ) from error


def _add_blacklist_entry_unlocked(
    address: str,
    timeout: str,
    reason: str = "manual",
    source: str = "cli",
    store: BlacklistStore | None = None,
    protected_networks: list[str] | None = None,
) -> None:
    """Add IPv4 address using persistent state as source of truth."""

    normalized_address = validate_ipv4_address(
        address
    )

    if protected_networks is None:
        protected_networks = []

    validate_not_protected(
        normalized_address,
        protected_networks,
    )

    duration = parse_timeout(timeout)

    if store is None:
        store = BlacklistStore()

    previous_entries = load_store_entries(
        store
    )

    now = datetime.now(UTC)

    entry = BlacklistEntry(
        address=normalized_address,
        reason=reason,
        source=source,
        created_at=now,
        expires_at=now + duration,
    )

    new_entries = [
        existing
        for existing in previous_entries
        if existing.address != normalized_address
    ]

    new_entries.append(entry)

    # Persistent state is written first. If the process dies
    # afterwards, reconcile can restore the nftables element.
    save_store_entries(
        store,
        new_entries,
    )

    add_command = [
        "add",
        "element",
        NFT_FAMILY,
        NFT_TABLE,
        NFT_SET,
        (
            "{ "
            f"{normalized_address} "
            f"timeout {timeout} "
            "}"
        ),
    ]

    try:
        try:
            run_nft(add_command)

        except BlacklistError as error:
            if "File exists" not in str(error):
                raise

            run_nft(
                [
                    "delete",
                    "element",
                    NFT_FAMILY,
                    NFT_TABLE,
                    NFT_SET,
                    f"{{ {normalized_address} }}",
                ]
            )

            run_nft(add_command)

    except BlacklistError as nft_error:
        try:
            save_store_entries(
                store,
                previous_entries,
            )

        except BlacklistError as rollback_error:
            raise BlacklistError(
                (
                    "nftables update failed and "
                    "persistent state rollback also failed: "
                    f"nft={nft_error}; "
                    f"rollback={rollback_error}"
                )
            ) from nft_error

        raise


def _delete_blacklist_entry_unlocked(
    address: str,
    store: BlacklistStore | None = None,
) -> None:
    """Delete IPv4 address with persistent state rollback."""

    normalized_address = validate_ipv4_address(
        address
    )

    if store is None:
        store = BlacklistStore()

    previous_entries = load_store_entries(
        store
    )

    new_entries = [
        entry
        for entry in previous_entries
        if entry.address != normalized_address
    ]

    # Remove from persistent desired state first.
    save_store_entries(
        store,
        new_entries,
    )

    try:
        run_nft(
            [
                "delete",
                "element",
                NFT_FAMILY,
                NFT_TABLE,
                NFT_SET,
                f"{{ {normalized_address} }}",
            ]
        )

    except BlacklistError as nft_error:
        try:
            save_store_entries(
                store,
                previous_entries,
            )

        except BlacklistError as rollback_error:
            raise BlacklistError(
                (
                    "nftables delete failed and "
                    "persistent state rollback also failed: "
                    f"nft={nft_error}; "
                    f"rollback={rollback_error}"
                )
            ) from nft_error

        raise


def list_blacklist_entries() -> list[str]:
    """Return IPv4 addresses currently present in nftables blacklist."""

    result = run_nft(
        [
            "--json",
            "list",
            "set",
            NFT_FAMILY,
            NFT_TABLE,
            NFT_SET,
        ]
    )

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise BlacklistError(
            "invalid JSON returned by nftables"
        ) from error

    addresses: list[str] = []

    for item in payload.get("nftables", []):
        set_data = item.get("set")

        if not isinstance(set_data, dict):
            continue

        elements = set_data.get("elem", [])

        if not isinstance(elements, list):
            continue

        for element in elements:
            address: str | None = None

            if isinstance(element, str):
                address = element

            elif isinstance(element, dict):
                elem_data = element.get("elem")

                if isinstance(elem_data, str):
                    address = elem_data

                elif isinstance(elem_data, dict):
                    value = elem_data.get("val")

                    if isinstance(value, str):
                        address = value

            if address is None:
                continue

            try:
                addresses.append(
                    validate_ipv4_address(address)
                )
            except BlacklistError:
                continue

    return addresses


def _list_blacklist_state_unlocked(
    store: BlacklistStore | None = None,
) -> list[BlacklistEntry]:
    """Return active stored blacklist metadata."""

    if store is None:
        store = BlacklistStore()

    now = datetime.now(UTC)

    entries = load_store_entries(store)

    active_entries = [
        entry
        for entry in entries
        if entry.expires_at > now
    ]

    if active_entries != entries:
        save_store_entries(
        store,
        active_entries,
    )

    return active_entries


def _reconcile_blacklist_unlocked(
    store: BlacklistStore | None = None,
) -> tuple[int, int]:
    """Synchronize persistent blacklist state with nftables.

    Returns:
        A tuple containing:
        - number of restored nftables entries;
        - number of expired persistent entries removed.
    """

    if store is None:
        store = BlacklistStore()

    now = datetime.now(UTC)

    entries = load_store_entries(store)

    active_entries: list[BlacklistEntry] = []
    expired_count = 0

    for entry in entries:
        if entry.expires_at <= now:
            expired_count += 1
            continue

        active_entries.append(entry)

    if active_entries != entries:
        save_store_entries(
        store,
        active_entries,
    )

    runtime_addresses = set(
        list_blacklist_entries()
    )

    restored_count = 0

    for entry in active_entries:
        if entry.address in runtime_addresses:
            continue

        remaining_seconds = math.ceil(
            (
                entry.expires_at - now
            ).total_seconds()
        )

        if remaining_seconds <= 0:
            continue

        run_nft(
            [
                "add",
                "element",
                NFT_FAMILY,
                NFT_TABLE,
                NFT_SET,
                (
                    "{ "
                    f"{entry.address} "
                    f"timeout {remaining_seconds}s "
                    "}"
                ),
            ]
        )

        restored_count += 1

    return restored_count, expired_count


# Public blacklist operations serialized across processes.

def _run_locked(operation):
    """Run one blacklist operation under the interprocess lock."""

    try:
        with locked_blacklist_operation():
            return operation()

    except BlacklistLockError as error:
        raise BlacklistError(
            f"blacklist lock error: {error}"
        ) from error


def add_blacklist_entry(
    address: str,
    timeout: str,
    reason: str = "manual",
    source: str = "cli",
    store: BlacklistStore | None = None,
    protected_networks: list[str] | None = None,
) -> None:
    """Add IPv4 address under the blacklist operation lock."""

    def operation() -> None:
        _add_blacklist_entry_unlocked(
            address=address,
            timeout=timeout,
            reason=reason,
            source=source,
            store=store,
            protected_networks=protected_networks,
        )

    _run_locked(operation)


def delete_blacklist_entry(
    address: str,
    store: BlacklistStore | None = None,
) -> None:
    """Delete IPv4 address under the blacklist operation lock."""

    def operation() -> None:
        _delete_blacklist_entry_unlocked(
            address=address,
            store=store,
        )

    _run_locked(operation)


def list_blacklist_state(
    store: BlacklistStore | None = None,
) -> list[BlacklistEntry]:
    """Read/clean persistent state under the operation lock."""

    def operation() -> list[BlacklistEntry]:
        return _list_blacklist_state_unlocked(
            store=store,
        )

    return _run_locked(operation)


def reconcile_blacklist(
    store: BlacklistStore | None = None,
) -> tuple[int, int]:
    """Reconcile blacklist under the operation lock."""

    def operation() -> tuple[int, int]:
        return _reconcile_blacklist_unlocked(
            store=store,
        )

    return _run_locked(operation)
