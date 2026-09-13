"""Persistent storage for managed DoH resolver state."""

import json
import os
from pathlib import Path

from pydantic import ValidationError

from secbox.modules.content_filter.doh_feed.models import (
    DohFeedState,
)


DEFAULT_STATE_PATH = Path(
    "/var/lib/secbox/doh-resolvers.json"
)


class DohFeedStoreError(Exception):
    """Raised when DoH feed state cannot be stored."""


class DohFeedStore:
    """Load and atomically save managed DoH resolver state."""

    def __init__(
        self,
        path: Path = DEFAULT_STATE_PATH,
    ) -> None:
        self.path = path

    def load(self) -> DohFeedState:
        """Load persisted state."""

        if not self.path.exists():
            return DohFeedState()

        try:
            data = json.loads(
                self.path.read_text(
                    encoding="utf-8",
                )
            )

            return DohFeedState.model_validate(data)

        except (
            OSError,
            json.JSONDecodeError,
            ValidationError,
        ) as error:
            raise DohFeedStoreError(
                f"failed to load DoH feed state: {error}"
            ) from error

    def save(
        self,
        state: DohFeedState,
    ) -> None:
        """Atomically save persisted state."""

        temporary = self.path.with_name(
            f".{self.path.name}.tmp"
        )

        try:
            self.path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            payload = state.model_dump(
                mode="json",
            )

            with temporary.open(
                "w",
                encoding="utf-8",
            ) as file:
                file.write(
                    json.dumps(
                        payload,
                        indent=2,
                        sort_keys=True,
                    )
                    + "\n"
                )

                file.flush()
                os.fsync(file.fileno())

            os.chmod(
                temporary,
                0o600,
            )

            os.replace(
                temporary,
                self.path,
            )

            directory_fd = os.open(
                self.path.parent,
                os.O_RDONLY | os.O_DIRECTORY,
            )

            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)

        except OSError as error:
            try:
                temporary.unlink(
                    missing_ok=True,
                )
            except OSError:
                pass

            raise DohFeedStoreError(
                f"failed to save DoH feed state: {error}"
            ) from error
