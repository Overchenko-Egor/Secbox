"""Resolve the effective DoH resolver address set."""

from ipaddress import IPv4Address

from secbox.modules.content_filter.models import (
    ContentFilterConfig,
)
from secbox.modules.content_filter.doh_feed.models import (
    DohFeedState,
)


def resolve_effective_doh_addresses(
    content_filter: ContentFilterConfig | None,
    managed_state: DohFeedState | None = None,
) -> list[IPv4Address]:
    """Return effective manual and managed DoH addresses."""

    if (
        content_filter is None
        or not content_filter.enabled
        or not content_filter.encrypted_dns.doh.enabled
    ):
        return []

    doh = content_filter.encrypted_dns.doh

    addresses = set(
        doh.resolver_addresses
    )

    if (
        doh.managed_feed_enabled
        and managed_state is not None
    ):
        addresses.update(
            managed_state.addresses
        )

    return sorted(
        addresses,
        key=int,
    )
