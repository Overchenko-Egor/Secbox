import json

from secbox.modules.deception.eve import (
    snapshot_eve_for_source,
)


def test_eve_snapshot_filters_source(
    tmp_path,
):
    source = (
        tmp_path
        / "eve.json"
    )

    destination = (
        tmp_path
        / "case.jsonl"
    )

    events = [
        {
            "event_type": "dns",
            "src_ip": "203.0.113.10",
            "dest_ip": "192.0.2.10",
        },
        {
            "event_type": "flow",
            "src_ip": "198.51.100.10",
            "dest_ip": "192.0.2.10",
        },
        {
            "event_type": "tls",
            "src_ip": "192.0.2.10",
            "dest_ip": "203.0.113.10",
        },
    ]

    source.write_text(
        "".join(
            json.dumps(event)
            + "\n"
            for event
            in events
        )
    )

    count = (
        snapshot_eve_for_source(
            source_ip=(
                "203.0.113.10"
            ),
            source_path=source,
            destination_path=(
                destination
            ),
        )
    )

    assert count == 2

    lines = (
        destination
        .read_text()
        .splitlines()
    )

    assert len(lines) == 2
