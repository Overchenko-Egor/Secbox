"""Correlation of Deception honeypot telemetry with cases."""

from __future__ import annotations

import json

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path


DEFAULT_EVENT_PATH = Path(
    "/var/lib/secbox/deception/honeypot/events.jsonl"
)

MAX_TAIL_BYTES = 4 * 1024 * 1024
MAX_CASE_EVENTS = 500

SENSITIVE_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "cookie",
)


class DeceptionTelemetryError(RuntimeError):
    """Failed to read Deception telemetry."""


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None

    try:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)

    return parsed.astimezone(UTC)


def _sanitize(
    value: object,
) -> object:
    if isinstance(value, dict):
        result: dict[str, object] = {}

        for key, item in value.items():
            name = str(key)

            if any(
                part in name.lower()
                for part in SENSITIVE_PARTS
            ):
                result[name] = "[redacted]"
                continue

            result[name] = _sanitize(item)

        return result

    if isinstance(value, list):
        return [
            _sanitize(item)
            for item in value
        ]

    if isinstance(value, str):
        return value[:512]

    return value


def _read_tail(
    path: Path,
) -> list[dict[str, object]]:
    try:
        size = path.stat().st_size

        with path.open("rb") as file:
            start = max(
                0,
                size - MAX_TAIL_BYTES,
            )

            file.seek(start)
            raw = file.read(MAX_TAIL_BYTES)

    except FileNotFoundError:
        return []

    except OSError as error:
        raise DeceptionTelemetryError(
            f"failed to read telemetry: {error}"
        ) from error

    lines = raw.splitlines()

    if start > 0 and lines:
        lines = lines[1:]

    result = []

    for raw_line in lines:
        try:
            event = json.loads(
                raw_line.decode("utf-8")
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            continue

        if isinstance(event, dict):
            result.append(event)

    return result


def case_telemetry(
    *,
    source_ip: str,
    started_at: datetime,
    ended_at: datetime | None = None,
    event_path: Path = DEFAULT_EVENT_PATH,
    limit: int = MAX_CASE_EVENTS,
) -> dict[str, object]:
    start = started_at.astimezone(UTC)

    end = (
        ended_at.astimezone(UTC)
        if ended_at is not None
        else None
    )

    events: list[dict[str, object]] = []

    for raw in _read_tail(event_path):
        if raw.get("source_ip") != source_ip:
            continue

        when = _timestamp(
            raw.get("timestamp")
        )

        if when is None or when < start:
            continue

        if end is not None and when > end:
            continue

        protocol = str(
            raw.get("protocol") or "unknown"
        )

        if protocol == "runtime":
            continue

        events.append(
            {
                "timestamp":
                    when.isoformat(),
                "protocol":
                    protocol,
                "event":
                    str(
                        raw.get("event")
                        or "unknown"
                    ),
                "source_ip":
                    source_ip,
                "source_port":
                    raw.get("source_port"),
                "details":
                    _sanitize(
                        raw.get("details")
                        or {}
                    ),
            }
        )

    events = events[-max(1, limit):]

    counts = Counter(
        str(event["protocol"])
        for event in events
    )

    return {
        "event_count":
            len(events),
        "protocol_counts":
            dict(sorted(counts.items())),
        "first_seen":
            (
                events[0]["timestamp"]
                if events
                else None
            ),
        "last_seen":
            (
                events[-1]["timestamp"]
                if events
                else None
            ),
        "events":
            events,
    }
