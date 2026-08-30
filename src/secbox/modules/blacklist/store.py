"""Persistent state storage for dynamic blacklist."""

import json
import os
import tempfile
from pathlib import Path

from secbox.modules.blacklist.models import BlacklistEntry


DEFAULT_STATE_PATH = Path("/var/lib/secbox/blacklist.json")


class BlacklistStoreError(Exception):
    """Raised when blacklist state cannot be read or written."""


class BlacklistStore:
    """JSON-backed persistent blacklist state."""

    def __init__(
        self,
        path: Path = DEFAULT_STATE_PATH,
    ) -> None:
        self.path = path

    def load(self) -> list[BlacklistEntry]:
        """Load stored blacklist entries."""

        if not self.path.exists():
            return []

        try:
            payload = json.loads(
                self.path.read_text(
                    encoding="utf-8",
                )
            )
        except (
            OSError,
            json.JSONDecodeError,
        ) as error:
            raise BlacklistStoreError(
                f"failed to read blacklist state: {error}"
            ) from error

        if not isinstance(payload, list):
            raise BlacklistStoreError(
                "blacklist state must contain a JSON list"
            )

        try:
            return [
                BlacklistEntry.model_validate(item)
                for item in payload
            ]
        except Exception as error:
            raise BlacklistStoreError(
                f"invalid blacklist state: {error}"
            ) from error

    def save(
        self,
        entries: list[BlacklistEntry],
    ) -> None:
        """Persist blacklist entries atomically."""

        temporary_path: Path | None = None

        try:
            self.path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            payload = [
                entry.model_dump(
                    mode="json",
                )
                for entry in entries
            ]

            content = (
                json.dumps(
                    payload,
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n"
            )

            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary_file:
                temporary_path = Path(
                    temporary_file.name
                )

                temporary_file.write(content)
                temporary_file.flush()
                os.fsync(
                    temporary_file.fileno()
                )

            os.replace(
                temporary_path,
                self.path,
            )

            temporary_path = None

        except OSError as error:
            raise BlacklistStoreError(
                f"failed to write blacklist state: {error}"
            ) from error

        finally:
            if (
                temporary_path is not None
                and temporary_path.exists()
            ):
                try:
                    temporary_path.unlink()
                except OSError:
                    pass
