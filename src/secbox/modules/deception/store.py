"""Persistent case storage for SecBox Deception."""

from __future__ import annotations

import json
import os
import re
import tempfile

from datetime import UTC, datetime
from pathlib import Path

from secbox.modules.deception.models import (
    DeceptionCase,
)


DEFAULT_CASE_ROOT = Path(
    "/var/lib/secbox/deception/cases"
)

CASE_ID_PATTERN = re.compile(
    r"^case-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$"
)


class DeceptionStoreError(RuntimeError):
    """Case store operation failed."""


def validate_case_id(
    case_id: str,
) -> str:
    if not CASE_ID_PATTERN.fullmatch(
        case_id
    ):
        raise DeceptionStoreError(
            "invalid deception case ID"
        )

    return case_id


class DeceptionCaseStore:
    """Filesystem-backed deception case store."""

    def __init__(
        self,
        root: Path = DEFAULT_CASE_ROOT,
    ) -> None:
        self.root = root

    def case_path(
        self,
        case_id: str,
    ) -> Path:
        validate_case_id(
            case_id
        )

        return (
            self.root
            / case_id
        )

    def metadata_path(
        self,
        case_id: str,
    ) -> Path:
        return (
            self.case_path(
                case_id
            )
            / "metadata.json"
        )

    def create_layout(
        self,
        *,
        case: DeceptionCase,
        deception_uid: int | None = None,
        deception_gid: int | None = None,
    ) -> Path:
        self.root.mkdir(
            parents=True,
            exist_ok=True,
        )

        path = self.case_path(
            case.case_id
        )

        try:
            path.mkdir(
                mode=0o750,
                exist_ok=False,
            )

        except FileExistsError as error:
            raise DeceptionStoreError(
                "deception case already exists"
            ) from error

        capture = (
            path / "capture"
        )

        capture.mkdir(
            mode=0o750
        )

        if deception_gid is not None:
            os.chown(
                path,
                0,
                deception_gid,
            )

            os.chmod(
                path,
                0o750,
            )

        if (
            deception_uid is not None
            and deception_gid is not None
        ):
            os.chown(
                capture,
                deception_uid,
                deception_gid,
            )

            os.chmod(
                capture,
                0o750,
            )

        source_path = (
            path / "source_ip"
        )

        source_path.write_text(
            case.source_ip + "\n",
            encoding="utf-8",
        )

        if deception_gid is not None:
            os.chown(
                source_path,
                0,
                deception_gid,
            )

        os.chmod(
            source_path,
            0o640,
        )

        self.save(
            case
        )

        self.append_timeline(
            case.case_id,
            {
                "timestamp":
                    case.created_at.isoformat(),
                "event":
                    "case_created",
                "status":
                    case.status,
                "source_ip":
                    case.source_ip,
                "trigger_source":
                    case.trigger.source,
                "reason":
                    case.trigger.reason,
            },
        )

        return path

    def load(
        self,
        case_id: str,
    ) -> DeceptionCase:
        path = self.metadata_path(
            case_id
        )

        try:
            raw = json.loads(
                path.read_text(
                    encoding="utf-8"
                )
            )

            return (
                DeceptionCase
                .model_validate(
                    raw
                )
            )

        except Exception as error:
            raise DeceptionStoreError(
                f"failed to load deception case "
                f"{case_id}: {error}"
            ) from error

    def save(
        self,
        case: DeceptionCase,
    ) -> None:
        path = self.metadata_path(
            case.case_id
        )

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        payload = (
            case.model_dump_json(
                indent=2,
            )
            + "\n"
        )

        fd, temporary = (
            tempfile.mkstemp(
                prefix=".metadata-",
                suffix=".tmp",
                dir=path.parent,
                text=True,
            )
        )

        temporary_path = Path(
            temporary
        )

        try:
            with os.fdopen(
                fd,
                "w",
                encoding="utf-8",
            ) as file:
                file.write(
                    payload
                )

                file.flush()
                os.fsync(
                    file.fileno()
                )

            os.chmod(
                temporary_path,
                0o600,
            )

            os.replace(
                temporary_path,
                path,
            )

        finally:
            temporary_path.unlink(
                missing_ok=True
            )

    def append_timeline(
        self,
        case_id: str,
        event: dict[str, object],
    ) -> None:
        path = (
            self.case_path(
                case_id
            )
            / "timeline.jsonl"
        )

        line = (
            json.dumps(
                event,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            + "\n"
        )

        with path.open(
            "a",
            encoding="utf-8",
        ) as file:
            file.write(
                line
            )

            file.flush()

        os.chmod(
            path,
            0o600,
        )

    def list_cases(
        self,
    ) -> list[DeceptionCase]:
        if not self.root.exists():
            return []

        cases: list[
            DeceptionCase
        ] = []

        for path in sorted(
            self.root.iterdir(),
            reverse=True,
        ):
            if not path.is_dir():
                continue

            try:
                case = self.load(
                    path.name
                )

            except DeceptionStoreError:
                continue

            cases.append(
                case
            )

        return cases

    def mark_stopped(
        self,
        case_id: str,
    ) -> DeceptionCase:
        case = self.load(
            case_id
        )

        now = datetime.now(
            UTC
        )

        updated = case.model_copy(
            update={
                "status":
                    "stopped",
                "updated_at":
                    now,
                "stopped_at":
                    now,
            }
        )

        self.save(
            updated
        )

        self.append_timeline(
            case_id,
            {
                "timestamp":
                    now.isoformat(),
                "event":
                    "capture_stopped",
                "status":
                    "stopped",
            },
        )

        return updated

    def mark_error(
        self,
        case_id: str,
        message: str,
    ) -> DeceptionCase:
        case = self.load(
            case_id
        )

        now = datetime.now(
            UTC
        )

        updated = case.model_copy(
            update={
                "status":
                    "error",
                "updated_at":
                    now,
                "error":
                    message,
            }
        )

        self.save(
            updated
        )

        self.append_timeline(
            case_id,
            {
                "timestamp":
                    now.isoformat(),
                "event":
                    "error",
                "status":
                    "error",
                "detail":
                    message,
            },
        )

        return updated

    def pcap_files(
        self,
        case_id: str,
    ) -> list[dict[str, object]]:
        capture = (
            self.case_path(
                case_id
            )
            / "capture"
        )

        if not capture.exists():
            return []

        result = []

        for path in sorted(
            capture.glob(
                "traffic.pcap*"
            )
        ):
            try:
                stat = path.stat()

            except OSError:
                continue

            result.append(
                {
                    "name":
                        path.name,
                    "size_bytes":
                        stat.st_size,
                }
            )

        return result
