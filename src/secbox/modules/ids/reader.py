"""Incremental reader for the Suricata EVE JSON log."""

import os
import time
from collections.abc import Iterator
from pathlib import Path
from typing import TextIO


class EveReaderError(Exception):
    """Raised when the Suricata EVE log cannot be read."""


class EveTailReader:
    """Follow new lines appended to a Suricata EVE log."""

    def __init__(
        self,
        path: Path,
        *,
        poll_interval: float = 0.2,
        start_at_end: bool = True,
    ) -> None:
        if poll_interval <= 0:
            raise ValueError(
                "poll_interval must be positive"
            )

        self.path = path
        self.poll_interval = poll_interval
        self.start_at_end = start_at_end

        self._file: TextIO | None = None
        self._device: int | None = None
        self._inode: int | None = None

    def open(self) -> None:
        """Open the EVE log."""

        if self._file is not None:
            return

        try:
            file = self.path.open(
                mode="r",
                encoding="utf-8",
            )
        except OSError as error:
            raise EveReaderError(
                f"failed to open EVE log "
                f"{self.path}: {error}"
            ) from error

        try:
            stat_result = os.fstat(
                file.fileno()
            )

            if self.start_at_end:
                file.seek(
                    0,
                    os.SEEK_END,
                )

        except OSError as error:
            file.close()

            raise EveReaderError(
                f"failed to initialize EVE log "
                f"{self.path}: {error}"
            ) from error

        self._file = file
        self._device = stat_result.st_dev
        self._inode = stat_result.st_ino

    def close(self) -> None:
        """Close the current EVE log."""

        if self._file is None:
            return

        self._file.close()

        self._file = None
        self._device = None
        self._inode = None

    def __enter__(
        self,
    ) -> "EveTailReader":
        self.open()
        return self

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        self.close()

    def _require_file(self) -> TextIO:
        """Return the currently opened file."""

        if self._file is None:
            raise EveReaderError(
                "EVE reader is not open"
            )

        return self._file

    def read_available(
        self,
    ) -> list[str]:
        """Read all complete lines currently available."""

        file = self._require_file()

        lines: list[str] = []

        while True:
            position = file.tell()

            line = file.readline()

            if not line:
                break

            if not line.endswith("\n"):
                file.seek(position)
                break

            lines.append(line)

        return lines

    def _path_stat(
        self,
    ) -> os.stat_result | None:
        """Return current path metadata if the file exists."""

        try:
            return self.path.stat()
        except FileNotFoundError:
            return None
        except OSError as error:
            raise EveReaderError(
                f"failed to stat EVE log "
                f"{self.path}: {error}"
            ) from error

    def _was_rotated(
        self,
    ) -> bool:
        """Check whether the path now points to another file."""

        stat_result = self._path_stat()

        if stat_result is None:
            return False

        return (
            stat_result.st_dev != self._device
            or stat_result.st_ino != self._inode
        )

    def _was_truncated(
        self,
    ) -> bool:
        """Check whether the current file was truncated in place."""

        file = self._require_file()

        try:
            current_position = file.tell()

            stat_result = os.fstat(
                file.fileno()
            )

        except OSError as error:
            raise EveReaderError(
                f"failed to inspect EVE log "
                f"{self.path}: {error}"
            ) from error

        return (
            stat_result.st_size
            < current_position
        )

    def refresh(self) -> bool:
        """Handle log rotation or truncation.

        Return True when the reader position was reset.
        """

        if self._file is None:
            self.open()
            return True

        if self._was_rotated():
            self.close()

            try:
                self.open()
            except EveReaderError:
                return False

            file = self._require_file()

            file.seek(
                0,
                os.SEEK_SET,
            )

            return True

        if self._was_truncated():
            file = self._require_file()

            file.seek(
                0,
                os.SEEK_SET,
            )

            return True

        return False

    def follow(
        self,
    ) -> Iterator[str]:
        """Yield newly appended complete lines forever."""

        self.open()

        while True:
            lines = self.read_available()

            if lines:
                yield from lines
                continue

            self.refresh()

            time.sleep(
                self.poll_interval
            )
