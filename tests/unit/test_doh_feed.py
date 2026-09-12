from datetime import UTC, datetime
from ipaddress import IPv4Address

import pytest

from secbox.modules.content_filter.doh_feed.models import (
    DohFeedState,
)
from secbox.modules.content_filter.doh_feed.store import (
    DohFeedStore,
    DohFeedStoreError,
)


def test_missing_state_returns_empty_state(
    tmp_path,
) -> None:
    store = DohFeedStore(
        tmp_path / "state.json"
    )

    state = store.load()

    assert state.addresses == []
    assert state.updated_at is None


def test_state_round_trip(tmp_path) -> None:
    path = tmp_path / "state.json"
    store = DohFeedStore(path)

    state = DohFeedState(
        addresses=[
            IPv4Address("1.1.1.1"),
            IPv4Address("8.8.8.8"),
        ],
        updated_at=datetime.now(UTC),
    )

    store.save(state)

    loaded = store.load()

    assert loaded == state
    assert path.stat().st_mode & 0o777 == 0o600


def test_invalid_state_is_rejected(
    tmp_path,
) -> None:
    path = tmp_path / "state.json"

    path.write_text(
        "{not-json",
        encoding="utf-8",
    )

    store = DohFeedStore(path)

    with pytest.raises(
        DohFeedStoreError,
        match="failed to load",
    ):
        store.load()


from secbox.modules.content_filter.doh_feed.parser import (
    DohFeedParseError,
    parse_doh_feed,
)


def test_parse_doh_feed() -> None:
    addresses = parse_doh_feed(
        """
        # resolver feed

        8.8.8.8
        1.1.1.1
        8.8.8.8
        """
    )

    assert addresses == [
        IPv4Address("1.1.1.1"),
        IPv4Address("8.8.8.8"),
    ]


def test_parse_doh_feed_ignores_invalid_lines() -> None:
    addresses = parse_doh_feed(
        """
        invalid
        example.com
        2001:4860:4860::8888
        9.9.9.9 resolver
        """
    )

    assert addresses == [
        IPv4Address("9.9.9.9"),
    ]


def test_parse_doh_feed_rejects_empty_result() -> None:
    with pytest.raises(
        DohFeedParseError,
        match="no valid IPv4 addresses",
    ):
        parse_doh_feed(
            """
            # only comments
            invalid
            2001:4860:4860::8888
            """
        )


from secbox.modules.content_filter.doh_feed.service import (
    render_nft_update,
)


def test_render_nft_update() -> None:
    rendered = render_nft_update(
        [
            IPv4Address("8.8.8.8"),
            IPv4Address("1.1.1.1"),
            IPv4Address("8.8.8.8"),
        ]
    )

    assert rendered == (
        "flush set inet secbox_filter doh_resolvers_v4\n"
        "add element inet secbox_filter doh_resolvers_v4 "
        "{ 1.1.1.1, 8.8.8.8 }\n"
    )


def test_render_empty_nft_update() -> None:
    rendered = render_nft_update([])

    assert rendered == (
        "flush set inet secbox_filter doh_resolvers_v4\n"
    )


def test_update_managed_resolvers_applies_before_save(
    tmp_path,
    monkeypatch,
) -> None:
    from secbox.modules.content_filter.doh_feed import (
        service,
    )

    events = []

    class RecordingStore(DohFeedStore):
        def save(self, state):
            events.append(
                ("save", list(state.addresses))
            )
            super().save(state)

    store = RecordingStore(
        tmp_path / "state.json"
    )

    def fake_apply(addresses):
        events.append(
            ("apply", list(addresses))
        )

    monkeypatch.setattr(
        service,
        "apply_nft_update",
        fake_apply,
    )

    state = service.update_managed_resolvers(
        [
            IPv4Address("8.8.8.8"),
            IPv4Address("1.1.1.1"),
            IPv4Address("8.8.8.8"),
        ],
        content_filter=make_doh_content_filter(),
        store=store,
    )

    expected = [
        IPv4Address("1.1.1.1"),
        IPv4Address("8.8.8.8"),
    ]

    assert state.addresses == expected

    assert events == [
        ("apply", expected),
        ("save", expected),
    ]

    assert store.load().addresses == expected


def test_runtime_failure_does_not_save_state(
    tmp_path,
    monkeypatch,
) -> None:
    from secbox.modules.content_filter.doh_feed import (
        service,
    )

    store = DohFeedStore(
        tmp_path / "state.json"
    )

    original = DohFeedState(
        addresses=[
            IPv4Address("9.9.9.9"),
        ],
    )

    store.save(original)

    def fail_apply(addresses):
        raise service.DohFeedServiceError(
            "simulated nft failure"
        )

    monkeypatch.setattr(
        service,
        "apply_nft_update",
        fail_apply,
    )

    with pytest.raises(
        service.DohFeedServiceError,
        match="simulated nft failure",
    ):
        service.update_managed_resolvers(
            [
                IPv4Address("1.1.1.1"),
            ],
            content_filter=make_doh_content_filter(),
            store=store,
        )

    assert store.load() == original


def test_apply_nft_update_checks_before_apply(
    tmp_path,
    monkeypatch,
) -> None:
    from secbox.modules.content_filter.doh_feed import (
        service,
    )

    events = []

    def fake_run(path, *, check_only):
        assert path.exists()

        events.append(
            "check" if check_only else "apply"
        )

    monkeypatch.setattr(
        service,
        "_run_nft_file",
        fake_run,
    )

    service.apply_nft_update(
        [
            IPv4Address("1.1.1.1"),
        ]
    )

    assert events == [
        "check",
        "apply",
    ]


def test_failed_nft_check_prevents_apply(
    monkeypatch,
) -> None:
    from secbox.modules.content_filter.doh_feed import (
        service,
    )

    events = []

    def fake_run(path, *, check_only):
        events.append(
            "check" if check_only else "apply"
        )

        if check_only:
            raise service.DohFeedServiceError(
                "simulated check failure"
            )

    monkeypatch.setattr(
        service,
        "_run_nft_file",
        fake_run,
    )

    with pytest.raises(
        service.DohFeedServiceError,
        match="simulated check failure",
    ):
        service.apply_nft_update(
            [
                IPv4Address("1.1.1.1"),
            ]
        )

    assert events == ["check"]


def test_save_failure_rolls_runtime_back(
    tmp_path,
    monkeypatch,
) -> None:
    from secbox.modules.content_filter.doh_feed import (
        service,
    )
    from secbox.modules.content_filter.doh_feed.store import (
        DohFeedStoreError,
    )

    class FailingStore(DohFeedStore):
        def save(self, state):
            raise DohFeedStoreError(
                "simulated save failure"
            )

    store = FailingStore(
        tmp_path / "state.json"
    )

    previous = DohFeedState(
        addresses=[
            IPv4Address("9.9.9.9"),
        ],
    )

    DohFeedStore(store.path).save(previous)

    calls = []

    def fake_apply(addresses):
        calls.append(list(addresses))

    monkeypatch.setattr(
        service,
        "apply_nft_update",
        fake_apply,
    )

    with pytest.raises(
        service.DohFeedServiceError,
        match="rolled back successfully",
    ):
        service.update_managed_resolvers(
            [
                IPv4Address("1.1.1.1"),
            ],
            content_filter=make_doh_content_filter(),
            store=store,
        )

    assert calls == [
        [IPv4Address("1.1.1.1")],
        [
            IPv4Address("1.1.1.1"),
            IPv4Address("9.9.9.9"),
        ],
    ]

    assert DohFeedStore(
        store.path
    ).load() == previous


def test_save_and_rollback_failure_is_reported(
    tmp_path,
    monkeypatch,
) -> None:
    from secbox.modules.content_filter.doh_feed import (
        service,
    )
    from secbox.modules.content_filter.doh_feed.store import (
        DohFeedStoreError,
    )

    class FailingStore(DohFeedStore):
        def save(self, state):
            raise DohFeedStoreError(
                "simulated save failure"
            )

    store = FailingStore(
        tmp_path / "state.json"
    )

    previous = DohFeedState(
        addresses=[
            IPv4Address("9.9.9.9"),
        ],
    )

    DohFeedStore(store.path).save(previous)

    calls = []

    def fake_apply(addresses):
        calls.append(list(addresses))

        if len(calls) == 2:
            raise service.DohFeedServiceError(
                "simulated rollback failure"
            )

    monkeypatch.setattr(
        service,
        "apply_nft_update",
        fake_apply,
    )

    with pytest.raises(
        service.DohFeedServiceError,
        match="rollback also failed",
    ):
        service.update_managed_resolvers(
            [
                IPv4Address("1.1.1.1"),
            ],
            content_filter=make_doh_content_filter(),
            store=store,
        )

    assert len(calls) == 2


def test_reconcile_restores_persisted_state(
    tmp_path,
    monkeypatch,
) -> None:
    from secbox.modules.content_filter.doh_feed import (
        service,
    )

    store = DohFeedStore(
        tmp_path / "state.json"
    )

    persisted = DohFeedState(
        addresses=[
            IPv4Address("1.1.1.1"),
            IPv4Address("9.9.9.9"),
        ],
    )

    store.save(persisted)

    calls = []

    def fake_apply(addresses):
        calls.append(list(addresses))

    monkeypatch.setattr(
        service,
        "apply_nft_update",
        fake_apply,
    )

    result = service.reconcile_managed_resolvers(
        content_filter=make_doh_content_filter(),
        store=store,
    )

    assert result == persisted

    assert calls == [
        [
            IPv4Address("1.1.1.1"),
            IPv4Address("9.9.9.9"),
        ]
    ]


def make_doh_content_filter():
    from secbox.modules.content_filter.models import (
        ContentFilterConfig,
        DnsFilterConfig,
        DohFilterConfig,
        EncryptedDnsFilterConfig,
    )

    return ContentFilterConfig(
        enabled=True,
        dns=DnsFilterConfig(
            listen_interface="ens36",
            listen_address="192.168.50.1",
            upstream_servers=["1.1.1.1"],
        ),
        encrypted_dns=EncryptedDnsFilterConfig(
            doh=DohFilterConfig(
                enabled=True,
                managed_feed_enabled=True,
                resolver_addresses=[
                    "1.1.1.1",
                ],
            )
        ),
    )


def test_update_runtime_contains_manual_and_managed(
    tmp_path,
    monkeypatch,
) -> None:
    from secbox.modules.content_filter.doh_feed import (
        service,
    )

    store = DohFeedStore(
        tmp_path / "state.json"
    )

    calls = []

    def fake_apply(addresses):
        calls.append(list(addresses))

    monkeypatch.setattr(
        service,
        "apply_nft_update",
        fake_apply,
    )

    service.update_managed_resolvers(
        [
            IPv4Address("9.9.9.9"),
        ],
        content_filter=make_doh_content_filter(),
        store=store,
    )

    assert calls == [
        [
            IPv4Address("1.1.1.1"),
            IPv4Address("9.9.9.9"),
        ]
    ]

    assert store.load().addresses == [
        IPv4Address("9.9.9.9"),
    ]


def test_refresh_managed_resolvers(
    monkeypatch,
) -> None:
    from secbox.modules.content_filter.doh_feed import (
        service,
    )

    content_filter = make_doh_content_filter()

    content_filter.encrypted_dns.doh.managed_feed_enabled = (
        True
    )
    content_filter.encrypted_dns.doh.managed_feed_url = (
        "https://example.test/doh.txt"
    )
    content_filter.encrypted_dns.doh.managed_feed_min_addresses = (
        1
    )

    monkeypatch.setattr(
        service,
        "fetch_doh_feed",
        lambda *args, **kwargs: (
            "9.9.9.9\n"
            "1.0.0.1\n"
        ),
    )

    applied = []

    def fake_update(
        addresses,
        content_filter,
        store=None,
    ):
        applied.extend(addresses)
        return DohFeedState(
            addresses=addresses,
        )

    monkeypatch.setattr(
        service,
        "update_managed_resolvers",
        fake_update,
    )

    state = service.refresh_managed_resolvers(
        content_filter
    )

    assert state.addresses == [
        IPv4Address("1.0.0.1"),
        IPv4Address("9.9.9.9"),
    ]

    assert applied == [
        IPv4Address("1.0.0.1"),
        IPv4Address("9.9.9.9"),
    ]


def test_refresh_fetch_failure_does_not_update(
    monkeypatch,
) -> None:
    import pytest

    from secbox.modules.content_filter.doh_feed import (
        service,
    )

    content_filter = make_doh_content_filter()

    content_filter.encrypted_dns.doh.managed_feed_enabled = (
        True
    )
    content_filter.encrypted_dns.doh.managed_feed_url = (
        "https://example.test/doh.txt"
    )
    content_filter.encrypted_dns.doh.managed_feed_min_addresses = (
        1
    )

    def fail_fetch(*args, **kwargs):
        raise service.DohFeedFetchError(
            "network unavailable"
        )

    monkeypatch.setattr(
        service,
        "fetch_doh_feed",
        fail_fetch,
    )

    update_called = False

    def fake_update(*args, **kwargs):
        nonlocal update_called
        update_called = True
        raise AssertionError(
            "update must not be called"
        )

    monkeypatch.setattr(
        service,
        "update_managed_resolvers",
        fake_update,
    )

    with pytest.raises(
        service.DohFeedServiceError,
        match="failed to fetch",
    ):
        service.refresh_managed_resolvers(
            content_filter
        )

    assert update_called is False


def test_refresh_parse_failure_does_not_update(
    monkeypatch,
) -> None:
    import pytest

    from secbox.modules.content_filter.doh_feed import (
        service,
    )

    content_filter = make_doh_content_filter()

    content_filter.encrypted_dns.doh.managed_feed_enabled = (
        True
    )
    content_filter.encrypted_dns.doh.managed_feed_url = (
        "https://example.test/doh.txt"
    )
    content_filter.encrypted_dns.doh.managed_feed_min_addresses = (
        1
    )

    monkeypatch.setattr(
        service,
        "fetch_doh_feed",
        lambda *args, **kwargs: (
            "<html>not a feed</html>"
        ),
    )

    update_called = False

    def fake_update(*args, **kwargs):
        nonlocal update_called
        update_called = True
        raise AssertionError(
            "update must not be called"
        )

    monkeypatch.setattr(
        service,
        "update_managed_resolvers",
        fake_update,
    )

    with pytest.raises(
        service.DohFeedServiceError,
        match="failed to parse",
    ):
        service.refresh_managed_resolvers(
            content_filter
        )

    assert update_called is False


def test_refresh_rejects_disabled_managed_feed() -> None:
    import pytest

    from secbox.modules.content_filter.doh_feed import (
        service,
    )

    content_filter = make_doh_content_filter()

    content_filter.encrypted_dns.doh.managed_feed_enabled = (
        False
    )

    with pytest.raises(
        service.DohFeedServiceError,
        match="managed DoH feed is disabled",
    ):
        service.refresh_managed_resolvers(
            content_filter
        )


def test_refresh_requires_feed_url() -> None:
    import pytest

    from secbox.modules.content_filter.doh_feed import (
        service,
    )

    content_filter = make_doh_content_filter()

    content_filter.encrypted_dns.doh.managed_feed_enabled = (
        True
    )

    with pytest.raises(
        service.DohFeedServiceError,
        match="URL is not configured",
    ):
        service.refresh_managed_resolvers(
            content_filter
        )


def test_refresh_rejects_too_small_feed(
    monkeypatch,
) -> None:
    import pytest

    from secbox.modules.content_filter.doh_feed import (
        service,
    )

    content_filter = make_doh_content_filter()

    doh = content_filter.encrypted_dns.doh
    doh.managed_feed_enabled = True
    doh.managed_feed_url = (
        "https://example.test/doh.txt"
    )
    doh.managed_feed_min_addresses = 3

    monkeypatch.setattr(
        service,
        "fetch_doh_feed",
        lambda *args, **kwargs: (
            "1.1.1.1\n8.8.8.8\n"
        ),
    )

    update_called = False

    def forbidden_update(*args, **kwargs):
        nonlocal update_called
        update_called = True
        raise AssertionError(
            "invalid feed must not be applied"
        )

    monkeypatch.setattr(
        service,
        "update_managed_resolvers",
        forbidden_update,
    )

    with pytest.raises(
        service.DohFeedServiceError,
        match="too few addresses",
    ):
        service.refresh_managed_resolvers(
            content_filter
        )

    assert update_called is False


def test_refresh_rejects_too_large_feed(
    monkeypatch,
) -> None:
    import pytest

    from secbox.modules.content_filter.doh_feed import (
        service,
    )

    content_filter = make_doh_content_filter()

    doh = content_filter.encrypted_dns.doh
    doh.managed_feed_enabled = True
    doh.managed_feed_url = (
        "https://example.test/doh.txt"
    )
    doh.managed_feed_min_addresses = 1
    doh.managed_feed_max_addresses = 1

    monkeypatch.setattr(
        service,
        "fetch_doh_feed",
        lambda *args, **kwargs: (
            "1.1.1.1\n8.8.8.8\n"
        ),
    )

    with pytest.raises(
        service.DohFeedServiceError,
        match="too many addresses",
    ):
        service.refresh_managed_resolvers(
            content_filter
        )
