"""Runtime management of the managed DoH nftables set."""

import subprocess
from ipaddress import IPv4Address
from pathlib import Path
from tempfile import NamedTemporaryFile

from secbox.modules.content_filter.models import (
    ContentFilterConfig,
)
from secbox.modules.content_filter.doh_feed.fetcher import (
    DohFeedFetchError,
    fetch_doh_feed,
)
from secbox.modules.content_filter.doh_feed.parser import (
    DohFeedParseError,
    parse_doh_feed,
)
from secbox.modules.content_filter.doh_feed.resolver import (
    resolve_effective_doh_addresses,
)
from secbox.modules.content_filter.doh_feed.models import (
    DohFeedState,
)
from secbox.modules.content_filter.doh_feed.store import (
    DohFeedStore,
    DohFeedStoreError,
)


NFT_BIN = "/usr/sbin/nft"

NFT_FAMILY = "inet"
NFT_TABLE = "secbox_filter"
NFT_SET = "doh_resolvers_v4"


class DohFeedServiceError(Exception):
    """Raised when managed DoH runtime update fails."""


def render_nft_update(
    addresses: list[IPv4Address],
) -> str:
    """Render transactional nftables set update."""

    lines = [
        (
            f"flush set {NFT_FAMILY} "
            f"{NFT_TABLE} {NFT_SET}"
        ),
    ]

    if addresses:
        elements = ", ".join(
            str(address)
            for address in sorted(
                set(addresses),
                key=int,
            )
        )

        lines.append(
            f"add element {NFT_FAMILY} "
            f"{NFT_TABLE} {NFT_SET} "
            f"{{ {elements} }}"
        )

    return "\n".join(lines) + "\n"


def _run_nft_file(
    path: Path,
    *,
    check_only: bool,
) -> None:
    """Check or apply an nftables batch file."""

    command = [NFT_BIN]

    if check_only:
        command.append("--check")

    command.extend(
        [
            "-f",
            str(path),
        ]
    )

    try:
        subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        )

    except subprocess.CalledProcessError as error:
        message = (
            error.stderr.strip()
            or error.stdout.strip()
            or str(error)
        )

        raise DohFeedServiceError(
            f"nftables update failed: {message}"
        ) from error

    except OSError as error:
        raise DohFeedServiceError(
            f"failed to execute nftables: {error}"
        ) from error


def apply_nft_update(
    addresses: list[IPv4Address],
) -> None:
    """Validate and atomically apply a DoH nft set update."""

    batch = render_nft_update(addresses)

    temporary_path: Path | None = None

    try:
        with NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix="secbox-doh-",
            suffix=".nft",
            delete=False,
        ) as temporary:
            temporary.write(batch)
            temporary.flush()

            temporary_path = Path(
                temporary.name
            )

        _run_nft_file(
            temporary_path,
            check_only=True,
        )

        _run_nft_file(
            temporary_path,
            check_only=False,
        )

    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(
                    missing_ok=True,
                )
            except OSError:
                pass


def update_managed_resolvers(
    addresses: list[IPv4Address],
    content_filter: ContentFilterConfig,
    store: DohFeedStore | None = None,
) -> DohFeedState:
    """Update managed state and effective runtime DoH set."""

    from datetime import UTC, datetime

    if store is None:
        store = DohFeedStore()

    try:
        previous_state = store.load()
    except DohFeedStoreError as error:
        raise DohFeedServiceError(
            f"failed to load previous DoH state: {error}"
        ) from error

    state = DohFeedState(
        addresses=sorted(
            set(addresses),
            key=int,
        ),
        updated_at=datetime.now(UTC),
    )

    effective_addresses = (
        resolve_effective_doh_addresses(
            content_filter,
            state,
        )
    )

    apply_nft_update(
        effective_addresses
    )

    try:
        store.save(state)

    except DohFeedStoreError as save_error:
        previous_effective = (
            resolve_effective_doh_addresses(
                content_filter,
                previous_state,
            )
        )

        try:
            apply_nft_update(
                previous_effective
            )
        except DohFeedServiceError as rollback_error:
            raise DohFeedServiceError(
                "persistent DoH state could not be saved "
                "and runtime rollback also failed: "
                f"save={save_error}; "
                f"rollback={rollback_error}"
            ) from save_error

        raise DohFeedServiceError(
            "persistent DoH state could not be saved; "
            "runtime was rolled back successfully: "
            f"{save_error}"
        ) from save_error

    return state

def reconcile_managed_resolvers(
    content_filter: ContentFilterConfig,
    store: DohFeedStore | None = None,
) -> DohFeedState:
    """Restore effective runtime DoH set from config and state."""

    if store is None:
        store = DohFeedStore()

    try:
        state = store.load()
    except DohFeedStoreError as error:
        raise DohFeedServiceError(
            f"failed to load persisted DoH state: {error}"
        ) from error

    effective_addresses = (
        resolve_effective_doh_addresses(
            content_filter,
            state,
        )
    )

    apply_nft_update(
        effective_addresses
    )

    return state


def refresh_managed_resolvers(
    content_filter: ContentFilterConfig,
    store: DohFeedStore | None = None,
) -> DohFeedState:
    """Fetch, parse, apply and persist the managed DoH feed."""

    if not content_filter.enabled:
        raise DohFeedServiceError(
            "content filtering is disabled"
        )

    doh = content_filter.encrypted_dns.doh

    if not doh.enabled:
        raise DohFeedServiceError(
            "DoH filtering is disabled"
        )

    if not doh.managed_feed_enabled:
        raise DohFeedServiceError(
            "managed DoH feed is disabled"
        )

    if doh.managed_feed_url is None:
        raise DohFeedServiceError(
            "managed DoH feed URL is not configured"
        )

    try:
        feed_text = fetch_doh_feed(
            doh.managed_feed_url,
            timeout_seconds=(
                doh.managed_feed_timeout_seconds
            ),
            max_bytes=doh.managed_feed_max_bytes,
        )
    except DohFeedFetchError as error:
        raise DohFeedServiceError(
            f"failed to fetch managed DoH feed: {error}"
        ) from error

    try:
        addresses = parse_doh_feed(feed_text)
    except DohFeedParseError as error:
        raise DohFeedServiceError(
            f"failed to parse managed DoH feed: {error}"
        ) from error

    address_count = len(addresses)

    if address_count < doh.managed_feed_min_addresses:
        raise DohFeedServiceError(
            "managed DoH feed contains too few addresses: "
            f"{address_count} < "
            f"{doh.managed_feed_min_addresses}"
        )

    if address_count > doh.managed_feed_max_addresses:
        raise DohFeedServiceError(
            "managed DoH feed contains too many addresses: "
            f"{address_count} > "
            f"{doh.managed_feed_max_addresses}"
        )

    return update_managed_resolvers(
        addresses,
        content_filter=content_filter,
        store=store,
    )
