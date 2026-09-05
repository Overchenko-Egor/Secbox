"""Tests for incremental Suricata EVE reader."""

from pathlib import Path

import pytest

from secbox.modules.ids.reader import (
    EveReaderError,
    EveTailReader,
)


def test_read_existing_lines_from_start(
    tmp_path: Path,
) -> None:
    """Read existing complete lines when requested."""

    eve_path = (
        tmp_path / "eve.json"
    )

    eve_path.write_text(
        '{"event_type":"alert"}\n'
        '{"event_type":"stats"}\n',
        encoding="utf-8",
    )

    reader = EveTailReader(
        eve_path,
        start_at_end=False,
    )

    reader.open()

    try:
        lines = (
            reader.read_available()
        )
    finally:
        reader.close()

    assert lines == [
        '{"event_type":"alert"}\n',
        '{"event_type":"stats"}\n',
    ]


def test_start_at_end_ignores_old_lines(
    tmp_path: Path,
) -> None:
    """Ignore events written before reader startup."""

    eve_path = (
        tmp_path / "eve.json"
    )

    eve_path.write_text(
        '{"old":true}\n',
        encoding="utf-8",
    )

    reader = EveTailReader(
        eve_path,
        start_at_end=True,
    )

    reader.open()

    try:
        assert (
            reader.read_available()
            == []
        )

        with eve_path.open(
            mode="a",
            encoding="utf-8",
        ) as file:
            file.write(
                '{"new":true}\n'
            )

        lines = (
            reader.read_available()
        )

    finally:
        reader.close()

    assert lines == [
        '{"new":true}\n',
    ]


def test_incomplete_line_is_not_returned(
    tmp_path: Path,
) -> None:
    """Wait until a partial JSON line is complete."""

    eve_path = (
        tmp_path / "eve.json"
    )

    eve_path.write_text(
        "",
        encoding="utf-8",
    )

    reader = EveTailReader(
        eve_path,
        start_at_end=False,
    )

    reader.open()

    try:
        with eve_path.open(
            mode="a",
            encoding="utf-8",
        ) as file:
            file.write(
                '{"partial":'
            )

        assert (
            reader.read_available()
            == []
        )

        with eve_path.open(
            mode="a",
            encoding="utf-8",
        ) as file:
            file.write(
                'true}\n'
            )

        lines = (
            reader.read_available()
        )

    finally:
        reader.close()

    assert lines == [
        '{"partial":true}\n',
    ]


def test_truncated_file_is_restarted(
    tmp_path: Path,
) -> None:
    """Restart from beginning after in-place truncation."""

    eve_path = (
        tmp_path / "eve.json"
    )

    eve_path.write_text(
        '{"first":true}\n'
        '{"another":"event"}\n',
        encoding="utf-8",
    )

    reader = EveTailReader(
        eve_path,
        start_at_end=False,
    )

    reader.open()

    try:
        assert len(
            reader.read_available()
        ) == 2

        with eve_path.open(
            mode="w",
            encoding="utf-8",
        ) as file:
            file.write(
                '{"new":1}\n'
            )

        assert reader.refresh() is True

        lines = (
            reader.read_available()
        )

    finally:
        reader.close()

    assert lines == [
        '{"new":1}\n',
    ]


def test_rotated_file_is_reopened(
    tmp_path: Path,
) -> None:
    """Open the new EVE file after log rotation."""

    eve_path = (
        tmp_path / "eve.json"
    )

    rotated_path = (
        tmp_path / "eve.json.1"
    )

    eve_path.write_text(
        '{"old":true}\n',
        encoding="utf-8",
    )

    reader = EveTailReader(
        eve_path,
        start_at_end=False,
    )

    reader.open()

    try:
        assert len(
            reader.read_available()
        ) == 1

        eve_path.rename(
            rotated_path
        )

        eve_path.write_text(
            '{"new":true}\n',
            encoding="utf-8",
        )

        assert reader.refresh() is True

        lines = (
            reader.read_available()
        )

    finally:
        reader.close()

    assert lines == [
        '{"new":true}\n',
    ]


def test_missing_file_fails_on_open(
    tmp_path: Path,
) -> None:
    """Report a missing EVE log."""

    eve_path = (
        tmp_path / "missing.json"
    )

    reader = EveTailReader(
        eve_path
    )

    with pytest.raises(
        EveReaderError,
        match="failed to open EVE log",
    ):
        reader.open()


def test_invalid_poll_interval_fails(
    tmp_path: Path,
) -> None:
    """Reject invalid polling intervals."""

    with pytest.raises(
        ValueError,
        match="poll_interval",
    ):
        EveTailReader(
            tmp_path / "eve.json",
            poll_interval=0,
        )
