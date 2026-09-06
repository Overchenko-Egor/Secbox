import json
import subprocess

import pytest
from pytest import MonkeyPatch

from secbox.modules.blacklist.service import (
    BlacklistError,
    add_blacklist_entry,
    delete_blacklist_entry,
    list_blacklist_entries,
    validate_ipv4_address,
    parse_timeout,
    reconcile_blacklist,
    list_blacklist_state,
)
from datetime import UTC, datetime, timedelta
from pathlib import Path
from secbox.modules.blacklist.models import BlacklistEntry
from secbox.modules.blacklist.store import BlacklistStore

def test_validate_ipv4_address() -> None:
    assert validate_ipv4_address(
        "192.168.1.10"
    ) == "192.168.1.10"


def test_ipv6_is_rejected() -> None:
    with pytest.raises(
        BlacklistError,
        match="only IPv4",
    ):
        validate_ipv4_address("2001:db8::1")


def test_invalid_address_is_rejected() -> None:
    with pytest.raises(
        BlacklistError,
        match="invalid IP",
    ):
        validate_ipv4_address("999.1.1.1")


def test_add_blacklist_entry(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    commands: list[list[str]] = []

    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        commands.append(command)

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    store = BlacklistStore(
        tmp_path / "blacklist.json"
    )

    add_blacklist_entry(
        "203.0.113.10",
        "1h",
        store=store,
    )

    command = commands[0]

    assert "/usr/sbin/nft" in command
    assert "add" in command
    assert "element" in command
    assert "203.0.113.10 timeout 1h" in command[-1]

    entries = store.load()

    assert len(entries) == 1
    assert entries[0].address == "203.0.113.10"
    assert entries[0].reason == "manual"
    assert entries[0].source == "cli"


def test_delete_blacklist_entry(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    commands: list[list[str]] = []

    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        commands.append(command)

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    store = BlacklistStore(
        tmp_path / "blacklist.json"
    )

    add_blacklist_entry(
        "203.0.113.10",
        "1h",
        store=store,
    )

    commands.clear()

    delete_blacklist_entry(
        "203.0.113.10",
        store=store,
    )

    command = commands[0]

    assert "delete" in command
    assert "element" in command
    assert "203.0.113.10" in command[-1]

    assert store.load() == []


def test_list_blacklist_entries(
    monkeypatch: MonkeyPatch,
) -> None:
    payload = {
        "nftables": [
            {
                "set": {
                    "family": "inet",
                    "name": "blacklist_v4",
                    "table": "secbox_filter",
                    "elem": [
                        {
                            "elem": {
                                "val": "203.0.113.10",
                                "timeout": 3600000,
                                "expires": 3500000,
                            }
                        },
                        {
                            "elem": {
                                "val": "198.51.100.7",
                                "timeout": 900000,
                                "expires": 800000,
                            }
                        },
                    ],
                }
            }
        ]
    }

    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        )

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    entries = list_blacklist_entries()

    assert entries == [
        "203.0.113.10",
        "198.51.100.7",
    ]


def test_parse_timeout() -> None:
    assert parse_timeout("30s") == timedelta(
        seconds=30
    )

    assert parse_timeout("10m") == timedelta(
        minutes=10
    )

    assert parse_timeout("2h") == timedelta(
        hours=2
    )

    assert parse_timeout("3d") == timedelta(
        days=3
    )


def test_reconcile_restores_missing_entry(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    commands: list[list[str]] = []

    store = BlacklistStore(
        tmp_path / "blacklist.json"
    )

    now = datetime.now(UTC)

    store.save(
        [
            BlacklistEntry(
                address="203.0.113.10",
                reason="port-scan",
                source="test",
                created_at=now,
                expires_at=now + timedelta(hours=1),
            )
        ]
    )

    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        commands.append(command)

        if "--json" in command:
            payload = {
                "nftables": [
                    {
                        "set": {
                            "family": "inet",
                            "table": "secbox_filter",
                            "name": "blacklist_v4",
                            "elem": [],
                        }
                    }
                ]
            }

            return subprocess.CompletedProcess(
                args=command,
                returncode=0,
                stdout=json.dumps(payload),
                stderr="",
            )

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    restored, expired = reconcile_blacklist(
        store=store
    )

    assert restored == 1
    assert expired == 0

    add_commands = [
        command
        for command in commands
        if "add" in command
        and "element" in command
    ]

    assert len(add_commands) == 1
    assert "203.0.113.10" in add_commands[0][-1]
    assert "timeout" in add_commands[0][-1]


def test_reconcile_removes_expired_state(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    store = BlacklistStore(
        tmp_path / "blacklist.json"
    )

    now = datetime.now(UTC)

    store.save(
        [
            BlacklistEntry(
                address="203.0.113.10",
                reason="port-scan",
                source="test",
                created_at=now - timedelta(hours=2),
                expires_at=now - timedelta(hours=1),
            )
        ]
    )

    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        payload = {
            "nftables": [
                {
                    "set": {
                        "family": "inet",
                        "table": "secbox_filter",
                        "name": "blacklist_v4",
                        "elem": [],
                    }
                }
            ]
        }

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        )

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    restored, expired = reconcile_blacklist(
        store=store
    )

    assert restored == 0
    assert expired == 1
    assert store.load() == []


def test_add_rejects_protected_address(
    monkeypatch,
    tmp_path,
) -> None:
    commands: list[list[str]] = []

    def fake_run_nft(
        command: list[str],
    ) -> None:
        commands.append(command)

    monkeypatch.setattr(
        "secbox.modules.blacklist.service.run_nft",
        fake_run_nft,
    )

    store = BlacklistStore(
        tmp_path / "blacklist.json"
    )

    with pytest.raises(
        BlacklistError,
        match="belongs to protected network",
    ):
        add_blacklist_entry(
            address="192.168.100.1",
            timeout="1h",
            store=store,
            protected_networks=[
                "192.168.100.0/24",
            ],
        )

    assert commands == []
    assert store.load() == []


def test_add_allows_address_outside_protected_network(
    monkeypatch,
    tmp_path,
) -> None:
    commands: list[list[str]] = []

    def fake_run_nft(
        command: list[str],
    ) -> None:
        commands.append(command)

    monkeypatch.setattr(
        "secbox.modules.blacklist.service.run_nft",
        fake_run_nft,
    )

    store = BlacklistStore(
        tmp_path / "blacklist.json"
    )

    add_blacklist_entry(
        address="192.168.1.35",
        timeout="1h",
        store=store,
        protected_networks=[
            "192.168.100.0/24",
        ],
    )

    assert len(commands) == 1
    assert store.load()[0].address == "192.168.1.35"



def test_storage_error_is_exposed_as_blacklist_error(
    tmp_path,
) -> None:
    state_path = tmp_path / "blacklist.json"

    state_path.write_text(
        "{ invalid json",
        encoding="utf-8",
    )

    store = BlacklistStore(state_path)

    with pytest.raises(
        BlacklistError,
        match="blacklist storage error",
    ):
        list_blacklist_state(store)



def test_repeated_blacklist_add_refreshes_timeout(
    monkeypatch,
) -> None:
    """Existing nft element is removed and added with a fresh timeout."""

    from secbox.modules.blacklist.service import (
        BlacklistError,
        add_blacklist_entry,
    )

    commands: list[list[str]] = []
    saved_entries = []
    add_attempts = 0

    def fake_run_nft(command):
        nonlocal add_attempts

        commands.append(command)

        if command[0] == "add":
            add_attempts += 1

            if add_attempts == 1:
                raise BlacklistError(
                    "nftables command failed: File exists"
                )

    monkeypatch.setattr(
        "secbox.modules.blacklist.service.run_nft",
        fake_run_nft,
    )

    monkeypatch.setattr(
        "secbox.modules.blacklist.service.load_store_entries",
        lambda store: [],
    )

    monkeypatch.setattr(
        "secbox.modules.blacklist.service.save_store_entries",
        lambda store, entries: saved_entries.extend(entries),
    )

    add_blacklist_entry(
        address="203.0.113.50",
        timeout="15m",
        reason="ids:test",
        source="ids",
        store=object(),
        protected_networks=[],
    )

    assert [command[0] for command in commands] == [
        "add",
        "delete",
        "add",
    ]

    assert commands[0][-1] == (
        "{ 203.0.113.50 timeout 15m }"
    )

    assert commands[1][-1] == (
        "{ 203.0.113.50 }"
    )

    assert commands[2][-1] == (
        "{ 203.0.113.50 timeout 15m }"
    )

    assert len(saved_entries) == 1
    assert saved_entries[0].address == "203.0.113.50"
    assert saved_entries[0].reason == "ids:test"
    assert saved_entries[0].source == "ids"


def test_blacklist_add_does_not_hide_other_nft_errors(
    monkeypatch,
    tmp_path,
) -> None:
    """Unexpected nft errors must still propagate."""

    import pytest

    from secbox.modules.blacklist.service import (
        BlacklistError,
        add_blacklist_entry,
    )

    commands: list[list[str]] = []

    def fake_run_nft(command):
        commands.append(command)

        raise BlacklistError(
            "nftables command failed: Permission denied"
        )

    monkeypatch.setattr(
        "secbox.modules.blacklist.service.run_nft",
        fake_run_nft,
    )

    store = BlacklistStore(
        tmp_path / "blacklist.json"
    )

    with pytest.raises(
        BlacklistError,
        match="Permission denied",
    ):
        add_blacklist_entry(
            address="203.0.113.50",
            timeout="15m",
            store=store,
            protected_networks=[],
        )

    assert len(commands) == 1
    assert commands[0][0] == "add"

    # Persistent state was written before nftables,
    # but must be rolled back after the nft failure.
    assert store.load() == []


def test_add_store_failure_does_not_touch_nft(
    monkeypatch,
) -> None:
    """nftables must not change if persistent state cannot be saved."""

    commands = []

    monkeypatch.setattr(
        "secbox.modules.blacklist.service.load_store_entries",
        lambda store: [],
    )

    def fail_save(store, entries):
        raise BlacklistError(
            "simulated storage failure"
        )

    monkeypatch.setattr(
        "secbox.modules.blacklist.service.save_store_entries",
        fail_save,
    )

    monkeypatch.setattr(
        "secbox.modules.blacklist.service.run_nft",
        lambda command: commands.append(command),
    )

    with pytest.raises(
        BlacklistError,
        match="storage failure",
    ):
        add_blacklist_entry(
            address="203.0.113.70",
            timeout="15m",
            store=object(),
            protected_networks=[],
        )

    assert commands == []


def test_add_nft_failure_rolls_back_persistent_state(
    monkeypatch,
) -> None:
    """Failed nft add restores previous persistent state."""

    previous = BlacklistEntry(
        address="198.51.100.10",
        reason="existing",
        source="test",
        created_at=datetime.now(UTC),
        expires_at=(
            datetime.now(UTC)
            + timedelta(hours=1)
        ),
    )

    saves = []

    monkeypatch.setattr(
        "secbox.modules.blacklist.service.load_store_entries",
        lambda store: [previous],
    )

    monkeypatch.setattr(
        "secbox.modules.blacklist.service.save_store_entries",
        lambda store, entries: saves.append(list(entries)),
    )

    def fail_nft(command):
        raise BlacklistError(
            "nftables command failed: Permission denied"
        )

    monkeypatch.setattr(
        "secbox.modules.blacklist.service.run_nft",
        fail_nft,
    )

    with pytest.raises(
        BlacklistError,
        match="Permission denied",
    ):
        add_blacklist_entry(
            address="203.0.113.70",
            timeout="15m",
            store=object(),
            protected_networks=[],
        )

    assert len(saves) == 2

    assert {
        entry.address
        for entry in saves[0]
    } == {
        "198.51.100.10",
        "203.0.113.70",
    }

    assert saves[1] == [
        previous
    ]


def test_delete_nft_failure_rolls_back_persistent_state(
    monkeypatch,
) -> None:
    """Failed nft delete restores the deleted persistent entry."""

    previous = BlacklistEntry(
        address="203.0.113.70",
        reason="existing",
        source="test",
        created_at=datetime.now(UTC),
        expires_at=(
            datetime.now(UTC)
            + timedelta(hours=1)
        ),
    )

    saves = []

    monkeypatch.setattr(
        "secbox.modules.blacklist.service.load_store_entries",
        lambda store: [previous],
    )

    monkeypatch.setattr(
        "secbox.modules.blacklist.service.save_store_entries",
        lambda store, entries: saves.append(list(entries)),
    )

    def fail_nft(command):
        raise BlacklistError(
            "nftables command failed: Permission denied"
        )

    monkeypatch.setattr(
        "secbox.modules.blacklist.service.run_nft",
        fail_nft,
    )

    with pytest.raises(
        BlacklistError,
        match="Permission denied",
    ):
        delete_blacklist_entry(
            address="203.0.113.70",
            store=object(),
        )

    assert saves[0] == []
    assert saves[1] == [
        previous
    ]



@pytest.fixture(autouse=True)
def isolated_blacklist_lock(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Exercise real locking without accessing system runtime state."""
    from functools import partial
    from secbox.modules.blacklist.lock import blacklist_lock

    monkeypatch.setattr(
        "secbox.modules.blacklist.service.locked_blacklist_operation",
        partial(blacklist_lock, tmp_path / "blacklist.lock"),
    )
