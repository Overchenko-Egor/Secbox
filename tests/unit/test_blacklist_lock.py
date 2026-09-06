"""Tests for blacklist interprocess locking."""

import multiprocessing
import time
from pathlib import Path

from secbox.modules.blacklist.lock import (
    blacklist_lock,
)


def _hold_lock(
    path_text: str,
    ready,
    release,
) -> None:
    path = Path(path_text)

    with blacklist_lock(path):
        ready.set()
        release.wait(timeout=5)


def _wait_for_lock(
    path_text: str,
    acquired,
) -> None:
    path = Path(path_text)

    with blacklist_lock(path):
        acquired.set()


def test_blacklist_lock_serializes_processes(
    tmp_path: Path,
) -> None:
    """Second process cannot enter while first owns the lock."""

    lock_path = (
        tmp_path
        / "blacklist.lock"
    )

    context = multiprocessing.get_context(
        "spawn"
    )

    ready = context.Event()
    release = context.Event()
    acquired = context.Event()

    first = context.Process(
        target=_hold_lock,
        args=(
            str(lock_path),
            ready,
            release,
        ),
    )

    second = context.Process(
        target=_wait_for_lock,
        args=(
            str(lock_path),
            acquired,
        ),
    )

    first.start()

    assert ready.wait(timeout=3)

    second.start()

    time.sleep(0.2)

    assert not acquired.is_set()

    release.set()

    assert acquired.wait(timeout=3)

    first.join(timeout=3)
    second.join(timeout=3)

    assert first.exitcode == 0
    assert second.exitcode == 0
