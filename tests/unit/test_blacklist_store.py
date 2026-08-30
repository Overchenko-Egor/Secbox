from datetime import UTC, datetime, timedelta
from pathlib import Path

from secbox.modules.blacklist.models import BlacklistEntry
from secbox.modules.blacklist.store import BlacklistStore


def test_blacklist_store_roundtrip(
    tmp_path: Path,
) -> None:
    path = tmp_path / "blacklist.json"

    store = BlacklistStore(path)

    now = datetime.now(UTC)

    entries = [
        BlacklistEntry(
            address="203.0.113.10",
            reason="port-scan",
            source="test",
            created_at=now,
            expires_at=now + timedelta(hours=1),
        )
    ]

    store.save(entries)

    loaded = store.load()

    assert len(loaded) == 1
    assert loaded[0].address == "203.0.113.10"
    assert loaded[0].reason == "port-scan"
    assert loaded[0].source == "test"


def test_store_does_not_leave_temporary_files(
    tmp_path,
) -> None:
    state_path = tmp_path / "blacklist.json"

    store = BlacklistStore(state_path)

    store.save([])

    assert state_path.exists()

    temporary_files = list(
        tmp_path.glob(
            ".blacklist.json.*.tmp"
        )
    )

    assert temporary_files == []
