from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path

import pytest
from typer.testing import CliRunner

import secbox.cli as cli
from secbox.modules.content_filter.doh_feed.models import (
    DohFeedState,
)
from secbox.modules.content_filter.models import (
    ContentFilterConfig,
    DnsFilterConfig,
    DohFilterConfig,
    EncryptedDnsFilterConfig,
)


class Config:
    def __init__(self, content_filter):
        self.content_filter = content_filter


runner = CliRunner()


class FakeConfigStore:
    def __init__(self, config):
        self.config = config

    def load(self):
        return self.config


def make_filter(
    *,
    managed_enabled: bool,
) -> ContentFilterConfig:
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
                managed_feed_enabled=managed_enabled,
                resolver_addresses=["1.1.1.1"],
            )
        ),
    )


def test_managed_state_not_loaded_when_disabled(
    monkeypatch,
) -> None:
    config = Config(
        make_filter(
            managed_enabled=False,
        )
    )

    class ForbiddenStore:
        def load(self):
            raise AssertionError(
                "store must not be loaded"
            )

    monkeypatch.setattr(
        cli,
        "DohFeedStore",
        ForbiddenStore,
    )

    assert cli._load_doh_managed_state(
        config
    ) is None


def test_corrupt_managed_state_fails_closed(
    monkeypatch,
) -> None:
    config = Config(
        make_filter(
            managed_enabled=True,
        )
    )

    class BrokenStore:
        def load(self):
            raise cli.DohFeedStoreError(
                "corrupt state"
            )

    monkeypatch.setattr(
        cli,
        "DohFeedStore",
        BrokenStore,
    )

    with pytest.raises(
        RuntimeError,
        match="failed to load managed DoH state",
    ):
        cli._load_doh_managed_state(
            config
        )


def test_doh_feed_status_is_read_only(
    monkeypatch,
) -> None:
    content_filter = make_filter(
        managed_enabled=True,
    )
    content_filter.encrypted_dns.doh.managed_feed_url = (
        "https://example.test/doh.txt"
    )

    config = Config(content_filter)

    monkeypatch.setattr(
        cli,
        "_store",
        lambda: FakeConfigStore(config),
    )

    state = DohFeedState(
        addresses=[
            IPv4Address("9.9.9.9"),
        ],
        updated_at=datetime(
            2026,
            9,
            12,
            10,
            30,
            tzinfo=UTC,
        ),
    )

    class FakeDohStore:
        def load(self):
            return state

    monkeypatch.setattr(
        cli,
        "DohFeedStore",
        FakeDohStore,
    )

    def forbidden(*args, **kwargs):
        raise AssertionError(
            "status must not modify DoH state"
        )

    monkeypatch.setattr(
        cli,
        "refresh_managed_resolvers",
        forbidden,
    )
    monkeypatch.setattr(
        cli,
        "reconcile_managed_resolvers",
        forbidden,
    )

    result = runner.invoke(
        cli.app,
        [
            "content-filter",
            "doh-feed",
            "status",
        ],
    )

    assert result.exit_code == 0
    assert "Managed DoH Feed Status" in result.stdout
    assert "https://example.test/doh.txt" in result.stdout
    assert "1.1.1.1" in result.stdout
    assert "9.9.9.9" in result.stdout


def test_doh_feed_update_calls_service(
    monkeypatch,
) -> None:
    content_filter = make_filter(
        managed_enabled=True,
    )
    content_filter.encrypted_dns.doh.managed_feed_url = (
        "https://example.test/doh.txt"
    )

    config = Config(content_filter)

    monkeypatch.setattr(
        cli,
        "_store",
        lambda: FakeConfigStore(config),
    )

    calls = []

    def fake_refresh(
        *,
        content_filter,
    ):
        calls.append(content_filter)

        return DohFeedState(
            addresses=[
                IPv4Address("9.9.9.9"),
                IPv4Address("1.0.0.1"),
            ],
            updated_at=datetime(
                2026,
                9,
                12,
                11,
                0,
                tzinfo=UTC,
            ),
        )

    monkeypatch.setattr(
        cli,
        "refresh_managed_resolvers",
        fake_refresh,
    )

    result = runner.invoke(
        cli.app,
        [
            "content-filter",
            "doh-feed",
            "update",
        ],
    )

    assert result.exit_code == 0
    assert calls == [content_filter]
    assert "Managed DoH feed updated" in result.stdout
    assert "Managed addresses: 2" in result.stdout


def test_doh_feed_reconcile_calls_service(
    monkeypatch,
) -> None:
    content_filter = make_filter(
        managed_enabled=True,
    )

    config = Config(content_filter)

    monkeypatch.setattr(
        cli,
        "_store",
        lambda: FakeConfigStore(config),
    )

    calls = []

    def fake_reconcile(
        *,
        content_filter,
    ):
        calls.append(content_filter)

        return DohFeedState(
            addresses=[
                IPv4Address("9.9.9.9"),
            ]
        )

    monkeypatch.setattr(
        cli,
        "reconcile_managed_resolvers",
        fake_reconcile,
    )

    result = runner.invoke(
        cli.app,
        [
            "content-filter",
            "doh-feed",
            "reconcile",
        ],
    )

    assert result.exit_code == 0
    assert calls == [content_filter]

    assert (
        "Managed DoH state reconciled"
        in result.stdout
    )
    assert "Managed addresses: 1" in result.stdout
    assert "Effective addresses: 2" in result.stdout


def test_doh_feed_update_service_error(
    monkeypatch,
) -> None:
    content_filter = make_filter(
        managed_enabled=True,
    )

    config = Config(content_filter)

    monkeypatch.setattr(
        cli,
        "_store",
        lambda: FakeConfigStore(config),
    )

    def fail_refresh(*args, **kwargs):
        raise cli.DohFeedServiceError(
            "managed feed unavailable"
        )

    monkeypatch.setattr(
        cli,
        "refresh_managed_resolvers",
        fail_refresh,
    )

    result = runner.invoke(
        cli.app,
        [
            "content-filter",
            "doh-feed",
            "update",
        ],
    )

    assert result.exit_code == 1
    assert (
        "managed feed unavailable"
        in result.stderr
    )


def test_doh_feed_reconcile_service_error(
    monkeypatch,
) -> None:
    content_filter = make_filter(
        managed_enabled=True,
    )

    config = Config(content_filter)

    monkeypatch.setattr(
        cli,
        "_store",
        lambda: FakeConfigStore(config),
    )

    def fail_reconcile(*args, **kwargs):
        raise cli.DohFeedServiceError(
            "runtime reconcile failed"
        )

    monkeypatch.setattr(
        cli,
        "reconcile_managed_resolvers",
        fail_reconcile,
    )

    result = runner.invoke(
        cli.app,
        [
            "content-filter",
            "doh-feed",
            "reconcile",
        ],
    )

    assert result.exit_code == 1
    assert (
        "runtime reconcile failed"
        in result.stderr
    )
