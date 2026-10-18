"""Suricata EVE extraction for Deception cases."""

from __future__ import annotations

import json
import os

from pathlib import Path


MAX_EVE_TAIL_BYTES = (
    8 * 1024 * 1024
)

MAX_CASE_EVE_EVENTS = 2000


class DeceptionEveError(RuntimeError):
    """EVE extraction failed."""


def snapshot_eve_for_source(
    *,
    source_ip: str,
    source_path: Path,
    destination_path: Path,
) -> int:
    """Copy bounded related EVE events into a case."""

    try:
        size = source_path.stat().st_size

        with source_path.open(
            "rb"
        ) as file:
            start = max(
                0,
                size
                - MAX_EVE_TAIL_BYTES,
            )

            file.seek(
                start
            )

            raw = file.read(
                MAX_EVE_TAIL_BYTES
            )

    except OSError as error:
        raise DeceptionEveError(
            f"failed to read EVE log: {error}"
        ) from error

    lines = raw.splitlines()

    if (
        start > 0
        and lines
    ):
        lines = lines[1:]

    matches: list[
        dict[str, object]
    ] = []

    for raw_line in lines:
        try:
            event = json.loads(
                raw_line.decode(
                    "utf-8",
                    errors="strict",
                )
            )

        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            continue

        if not isinstance(
            event,
            dict,
        ):
            continue

        if (
            event.get(
                "src_ip"
            ) != source_ip
            and event.get(
                "dest_ip"
            ) != source_ip
        ):
            continue

        matches.append(
            event
        )

        if (
            len(matches)
            > MAX_CASE_EVE_EVENTS
        ):
            matches.pop(
                0
            )

    destination_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with destination_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        for event in matches:
            file.write(
                json.dumps(
                    event,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            )

            file.write(
                "\n"
            )

    os.chmod(
        destination_path,
        0o600,
    )

    return len(
        matches
    )
