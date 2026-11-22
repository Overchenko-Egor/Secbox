import json

from datetime import UTC, datetime
from pathlib import Path

from secbox.modules.deception.telemetry import (
    case_telemetry,
)


def write_events(path: Path) -> None:
    events = [
        {
            "timestamp": "2026-10-25T10:00:00+00:00",
            "protocol": "dns",
            "event": "query",
            "source_ip": "10.10.10.20",
            "source_port": 50000,
            "details": {
                "qname": "gitlab.corp.local",
            },
        },
        {
            "timestamp": "2026-10-25T10:00:02+00:00",
            "protocol": "ssh",
            "event": "login",
            "source_ip": "10.10.10.20",
            "source_port": 50001,
            "details": {
                "username": "admin",
                "password": "secret123",
            },
        },
        {
            "timestamp": "2026-10-25T10:00:03+00:00",
            "protocol": "dns",
            "event": "query",
            "source_ip": "10.10.10.99",
            "source_port": 50002,
            "details": {},
        },
    ]

    path.write_text(
        "\n".join(
            json.dumps(item)
            for item in events
        )
        + "\n"
    )


def test_case_telemetry_correlates_and_redacts(
    tmp_path: Path,
):
    path = tmp_path / "events.jsonl"
    write_events(path)

    result = case_telemetry(
        source_ip="10.10.10.20",
        started_at=datetime(
            2026, 10, 25,
            9, 59,
            tzinfo=UTC,
        ),
        event_path=path,
    )

    assert result["event_count"] == 2

    assert result["protocol_counts"] == {
        "dns": 1,
        "ssh": 1,
    }

    events = result["events"]

    assert events[0]["details"]["qname"] == (
        "gitlab.corp.local"
    )

    assert (
        events[1]["details"]["password"]
        == "[redacted]"
    )
