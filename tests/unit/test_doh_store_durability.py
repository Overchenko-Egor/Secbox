from datetime import UTC, datetime
from ipaddress import IPv4Address

from secbox.modules.content_filter.doh_feed.models import DohFeedState
from secbox.modules.content_filter.doh_feed.store import DohFeedStore


def test_store_persists_state_with_secure_permissions(tmp_path):
    path = tmp_path / "doh-resolvers.json"
    store = DohFeedStore(path)

    state = DohFeedState(
        addresses=[
            IPv4Address("1.1.1.1"),
            IPv4Address("9.9.9.9"),
        ],
        updated_at=datetime.now(UTC),
    )

    store.save(state)

    assert store.load() == state
    assert path.stat().st_mode & 0o777 == 0o600


def test_store_fsyncs_file_and_directory(tmp_path, monkeypatch):
    from secbox.modules.content_filter.doh_feed import store as store_module

    calls = []

    real_fsync = store_module.os.fsync

    def recording_fsync(fd):
        calls.append(fd)
        return real_fsync(fd)

    monkeypatch.setattr(
        store_module.os,
        "fsync",
        recording_fsync,
    )

    store = DohFeedStore(
        tmp_path / "doh-resolvers.json"
    )

    store.save(
        DohFeedState(
            addresses=[
                IPv4Address("1.1.1.1"),
            ],
            updated_at=datetime.now(UTC),
        )
    )

    assert len(calls) == 2
