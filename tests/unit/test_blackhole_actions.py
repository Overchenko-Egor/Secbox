from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from secbox.actions import blackhole
from secbox.modules.blacklist.models import (
    BlacklistEntry,
)


class FakeStore:
    def __init__(
        self,
        config,
    ) -> None:
        self.config = config

    def load(self):
        return self.config


def make_config():
    firewall = SimpleNamespace(
        enabled=True,
        dynamic_blacklist_enabled=True,
        dynamic_blacklist_timeout="1h",
        dynamic_blacklist_protected_networks=[
            "192.168.100.0/24",
        ],
    )

    return SimpleNamespace(
        firewall=firewall,
    )


def test_manual_add_uses_root_side_protection(
    monkeypatch,
) -> None:
    observed = {}

    interface = SimpleNamespace(
        addresses=[
            SimpleNamespace(
                family="inet",
                address="192.168.100.2",
            )
        ]
    )

    monkeypatch.setattr(
        blackhole,
        "discover_interfaces",
        lambda: [interface],
    )

    monkeypatch.setattr(
        blackhole,
        "parse_timeout",
        lambda value: 3600,
    )

    monkeypatch.setattr(
        blackhole,
        "validate_ipv4_address",
        lambda value: value,
    )

    monkeypatch.setattr(
        blackhole,
        "add_blacklist_entry",
        lambda **kwargs:
            observed.update(kwargs),
    )

    result = (
        blackhole
        .add_blackhole_action(
            address="203.0.113.10",
            timeout="15m",
            reason="manual test",
            store=FakeStore(
                make_config()
            ),
        )
    )

    assert (
        result["address"]
        == "203.0.113.10"
    )

    assert (
        observed["source"]
        == "web"
    )

    assert (
        "192.168.100.0/24"
        in observed[
            "protected_networks"
        ]
    )

    assert (
        "192.168.100.2/32"
        in observed[
            "protected_networks"
        ]
    )


def test_manual_reason_rejects_control_characters():
    with pytest.raises(
        blackhole.BlackholeActionError,
    ):
        blackhole._manual_reason(
            "bad\nreason"
        )


def test_runtime_reports_consistency(
    monkeypatch,
) -> None:
    now = datetime.now(
        UTC
    )

    entry = BlacklistEntry(
        address="203.0.113.10",
        reason="test",
        source="web",
        created_at=now,
        expires_at=(
            now
            + timedelta(
                minutes=10
            )
        ),
    )

    monkeypatch.setattr(
        blackhole,
        "discover_interfaces",
        lambda: [],
    )

    monkeypatch.setattr(
        blackhole,
        "list_blacklist_state",
        lambda: [entry],
    )

    monkeypatch.setattr(
        blackhole,
        "list_blacklist_entries",
        lambda: [
            "203.0.113.10"
        ],
    )

    result = (
        blackhole
        .get_blackhole_runtime_action(
            store=FakeStore(
                make_config()
            )
        )
    )

    assert (
        result["consistent"]
        is True
    )

    assert (
        result["runtime_count"]
        == 1
    )

    assert (
        result[
            "persistent_count"
        ]
        == 1
    )

    assert (
        result["entries"][0]
        ["runtime_present"]
        is True
    )
