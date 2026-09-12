from ipaddress import IPv4Address

from secbox.modules.content_filter.models import (
    ContentFilterConfig,
    DnsFilterConfig,
    DohFilterConfig,
    EncryptedDnsFilterConfig,
)
from secbox.modules.content_filter.doh_feed.models import (
    DohFeedState,
)
from secbox.modules.content_filter.doh_feed.resolver import (
    resolve_effective_doh_addresses,
)


def make_filter(
    *,
    enabled: bool = True,
    doh_enabled: bool = True,
    managed_enabled: bool = False,
    manual: list[str] | None = None,
) -> ContentFilterConfig:
    return ContentFilterConfig(
        enabled=enabled,
        dns=DnsFilterConfig(
            listen_interface="ens36",
            listen_address="192.168.50.1",
            upstream_servers=[
                "1.1.1.1",
            ],
        ),
        encrypted_dns=EncryptedDnsFilterConfig(
            doh=DohFilterConfig(
                enabled=doh_enabled,
                managed_feed_enabled=managed_enabled,
                resolver_addresses=manual or [],
            )
        ),
    )


def test_manual_addresses_are_returned() -> None:
    config = make_filter(
        manual=[
            "8.8.8.8",
            "1.1.1.1",
        ]
    )

    result = resolve_effective_doh_addresses(
        config
    )

    assert result == [
        IPv4Address("1.1.1.1"),
        IPv4Address("8.8.8.8"),
    ]


def test_managed_addresses_are_merged() -> None:
    config = make_filter(
        managed_enabled=True,
        manual=[
            "1.1.1.1",
        ],
    )

    state = DohFeedState(
        addresses=[
            IPv4Address("9.9.9.9"),
            IPv4Address("1.1.1.1"),
        ]
    )

    result = resolve_effective_doh_addresses(
        config,
        state,
    )

    assert result == [
        IPv4Address("1.1.1.1"),
        IPv4Address("9.9.9.9"),
    ]


def test_managed_state_ignored_when_disabled() -> None:
    config = make_filter(
        managed_enabled=False,
        manual=[
            "1.1.1.1",
        ],
    )

    state = DohFeedState(
        addresses=[
            IPv4Address("9.9.9.9"),
        ]
    )

    result = resolve_effective_doh_addresses(
        config,
        state,
    )

    assert result == [
        IPv4Address("1.1.1.1"),
    ]


def test_disabled_filter_returns_empty() -> None:
    config = make_filter(
        enabled=False,
        managed_enabled=True,
        manual=[
            "1.1.1.1",
        ],
    )

    state = DohFeedState(
        addresses=[
            IPv4Address("9.9.9.9"),
        ]
    )

    assert resolve_effective_doh_addresses(
        config,
        state,
    ) == []


def test_disabled_doh_returns_empty() -> None:
    config = make_filter(
        doh_enabled=False,
        managed_enabled=True,
        manual=[
            "1.1.1.1",
        ],
    )

    state = DohFeedState(
        addresses=[
            IPv4Address("9.9.9.9"),
        ]
    )

    assert resolve_effective_doh_addresses(
        config,
        state,
    ) == []
