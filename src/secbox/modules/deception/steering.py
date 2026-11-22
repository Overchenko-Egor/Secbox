"""Persistent state for transparent Deception quarantine."""

from __future__ import annotations

import fcntl
import ipaddress
import json
import os
import tempfile

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


DEFAULT_STATE_PATH = Path(
    "/var/lib/secbox/deception/quarantine.json"
)


@contextmanager
def _file_lock(
    path: Path,
) -> Iterator[None]:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fd = os.open(
        path,
        os.O_CREAT | os.O_RDWR,
        0o600,
    )

    try:
        fcntl.flock(
            fd,
            fcntl.LOCK_EX,
        )

        yield

    finally:
        try:
            fcntl.flock(
                fd,
                fcntl.LOCK_UN,
            )
        finally:
            os.close(fd)


@contextmanager
def _state_lock(
    path: Path = DEFAULT_STATE_PATH,
) -> Iterator[None]:
    """Serialize quarantine state read-modify-write operations."""

    lock_path = (
        path.parent
        / ".quarantine.lock"
    )

    with _file_lock(lock_path):
        yield


@contextmanager
def source_operation_lock(
    source_ip: str,
    path: Path = DEFAULT_STATE_PATH,
) -> Iterator[str]:
    """Serialize complete lifecycle operations for one source."""

    address = normalize_source_ip(
        source_ip
    )

    lock_path = (
        path.parent
        / "locks"
        / f"{address}.lock"
    )

    with _file_lock(lock_path):
        yield address


class DeceptionSteeringError(RuntimeError):
    """Invalid or unavailable Deception steering state."""


def normalize_source_ip(
    source_ip: str,
) -> str:
    try:
        address = ipaddress.ip_address(
            source_ip
        )
    except ValueError as error:
        raise DeceptionSteeringError(
            "invalid source IPv4 address"
        ) from error

    if not isinstance(
        address,
        ipaddress.IPv4Address,
    ):
        raise DeceptionSteeringError(
            "only IPv4 sources are supported"
        )

    return str(address)


def _empty_state() -> dict[str, object]:
    return {
        "version": 1,
        "sources": {},
    }


def load_state(
    path: Path = DEFAULT_STATE_PATH,
) -> dict[str, object]:
    try:
        raw = path.read_text(
            encoding="utf-8"
        )
    except FileNotFoundError:
        return _empty_state()
    except OSError as error:
        raise DeceptionSteeringError(
            f"failed to read quarantine state: {error}"
        ) from error

    try:
        state = json.loads(raw)
    except json.JSONDecodeError as error:
        raise DeceptionSteeringError(
            "invalid quarantine state JSON"
        ) from error

    if not isinstance(state, dict):
        raise DeceptionSteeringError(
            "quarantine state must be an object"
        )

    if state.get("version") != 1:
        raise DeceptionSteeringError(
            "unsupported quarantine state version"
        )

    sources = state.get(
        "sources"
    )

    if not isinstance(
        sources,
        dict,
    ):
        raise DeceptionSteeringError(
            "quarantine sources must be an object"
        )

    return state


def save_state(
    state: dict[str, object],
    path: Path = DEFAULT_STATE_PATH,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    payload = (
        json.dumps(
            state,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )

    fd: int | None = None
    temporary: str | None = None

    try:
        fd, temporary = tempfile.mkstemp(
            prefix=".quarantine-",
            dir=path.parent,
            text=True,
        )

        with os.fdopen(
            fd,
            "w",
            encoding="utf-8",
        ) as handle:
            fd = None
            handle.write(
                payload
            )
            handle.flush()
            os.fsync(
                handle.fileno()
            )

        os.chmod(
            temporary,
            0o600,
        )

        os.replace(
            temporary,
            path,
        )

    except OSError as error:
        raise DeceptionSteeringError(
            f"failed to save quarantine state: {error}"
        ) from error

    finally:
        if fd is not None:
            os.close(fd)

        if (
            temporary is not None
            and os.path.exists(
                temporary
            )
        ):
            os.unlink(
                temporary
            )


def add_source(
    *,
    source_ip: str,
    case_id: str,
    path: Path = DEFAULT_STATE_PATH,
) -> bool:
    address = normalize_source_ip(
        source_ip
    )

    if not case_id.strip():
        raise DeceptionSteeringError(
            "case_id must not be empty"
        )

    with _state_lock(path):
        state = load_state(
            path
        )

        sources = state[
            "sources"
        ]

        assert isinstance(
            sources,
            dict,
        )

        current = sources.get(
            address
        )

        if current is None:
            cases: list[str] = []

        elif isinstance(
            current,
            dict,
        ):
            raw_cases = current.get(
                "cases"
            )

            if not isinstance(
                raw_cases,
                list,
            ):
                raise DeceptionSteeringError(
                    "invalid quarantine case list"
                )

            if not all(
                isinstance(item, str)
                for item in raw_cases
            ):
                raise DeceptionSteeringError(
                    "invalid quarantine case id"
                )

            cases = list(
                raw_cases
            )

        else:
            raise DeceptionSteeringError(
                "invalid quarantine source entry"
            )

        changed = (
            case_id not in cases
        )

        if changed:
            cases.append(
                case_id
            )

        sources[address] = {
            "cases":
                sorted(
                    set(cases)
                )
        }

        save_state(
            state,
            path,
        )

        return changed


def remove_source(
    *,
    source_ip: str,
    case_id: str,
    path: Path = DEFAULT_STATE_PATH,
) -> bool:
    address = normalize_source_ip(
        source_ip
    )

    with _state_lock(path):
        state = load_state(
            path
        )

        sources = state[
            "sources"
        ]

        assert isinstance(
            sources,
            dict,
        )

        current = sources.get(
            address
        )

        if not isinstance(
            current,
            dict,
        ):
            return False

        raw_cases = current.get(
            "cases"
        )

        if not isinstance(
            raw_cases,
            list,
        ):
            raise DeceptionSteeringError(
                "invalid quarantine case list"
            )

        cases = [
            item
            for item in raw_cases
            if isinstance(
                item,
                str,
            )
            and item != case_id
        ]

        if len(cases) == len(
            raw_cases
        ):
            return False

        if cases:
            sources[address] = {
                "cases":
                    sorted(
                        set(cases)
                    )
            }

        else:
            sources.pop(
                address,
                None,
            )

        save_state(
            state,
            path,
        )

        return True

def active_sources(
    path: Path = DEFAULT_STATE_PATH,
) -> list[str]:
    state = load_state(
        path
    )

    sources = state[
        "sources"
    ]

    assert isinstance(
        sources,
        dict,
    )

    result = []

    for source_ip in sources:
        result.append(
            normalize_source_ip(
                source_ip
            )
        )

    return sorted(
        result,
        key=lambda value:
            int(
                ipaddress.IPv4Address(
                    value
                )
            ),
    )


def source_is_active(
    source_ip: str,
    path: Path = DEFAULT_STATE_PATH,
) -> bool:
    address = normalize_source_ip(
        source_ip
    )

    return address in active_sources(
        path
    )
