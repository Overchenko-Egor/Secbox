"""Interprocess locking for dynamic blacklist operations."""

import fcntl
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


DEFAULT_LOCK_PATH = Path(
    "/var/lib/secbox/blacklist.lock"
)


class BlacklistLockError(Exception):
    """Raised when blacklist lock cannot be acquired."""


@contextmanager
def blacklist_lock(
    path: Path = DEFAULT_LOCK_PATH,
) -> Iterator[None]:
    """Serialize blacklist mutations across SecBox processes."""

    try:
        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        lock_file = path.open(
            "a+",
            encoding="utf-8",
        )

    except OSError as error:
        raise BlacklistLockError(
            f"failed to open blacklist lock: {error}"
        ) from error

    try:
        try:
            fcntl.flock(
                lock_file.fileno(),
                fcntl.LOCK_EX,
            )

        except OSError as error:
            raise BlacklistLockError(
                f"failed to acquire blacklist lock: {error}"
            ) from error

        yield

    finally:
        try:
            fcntl.flock(
                lock_file.fileno(),
                fcntl.LOCK_UN,
            )
        except OSError:
            pass

        lock_file.close()
