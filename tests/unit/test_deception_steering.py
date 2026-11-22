from pathlib import Path

import pytest

from secbox.modules.deception import steering


def test_empty_state(
    tmp_path: Path,
):
    path = (
        tmp_path
        / "quarantine.json"
    )

    assert (
        steering.active_sources(
            path
        )
        == []
    )


def test_add_and_remove_source(
    tmp_path: Path,
):
    path = (
        tmp_path
        / "quarantine.json"
    )

    assert steering.add_source(
        source_ip="203.0.113.10",
        case_id="case-a",
        path=path,
    )

    assert (
        steering.active_sources(
            path
        )
        == [
            "203.0.113.10"
        ]
    )

    assert steering.remove_source(
        source_ip="203.0.113.10",
        case_id="case-a",
        path=path,
    )

    assert (
        steering.active_sources(
            path
        )
        == []
    )


def test_multiple_cases_keep_source_active(
    tmp_path: Path,
):
    path = (
        tmp_path
        / "quarantine.json"
    )

    steering.add_source(
        source_ip="203.0.113.20",
        case_id="case-a",
        path=path,
    )

    steering.add_source(
        source_ip="203.0.113.20",
        case_id="case-b",
        path=path,
    )

    steering.remove_source(
        source_ip="203.0.113.20",
        case_id="case-a",
        path=path,
    )

    assert steering.source_is_active(
        "203.0.113.20",
        path,
    )

    steering.remove_source(
        source_ip="203.0.113.20",
        case_id="case-b",
        path=path,
    )

    assert not steering.source_is_active(
        "203.0.113.20",
        path,
    )


def test_duplicate_add_is_idempotent(
    tmp_path: Path,
):
    path = (
        tmp_path
        / "quarantine.json"
    )

    assert steering.add_source(
        source_ip="198.51.100.7",
        case_id="case-a",
        path=path,
    )

    assert not steering.add_source(
        source_ip="198.51.100.7",
        case_id="case-a",
        path=path,
    )


def test_ipv6_rejected(
    tmp_path: Path,
):
    with pytest.raises(
        steering.DeceptionSteeringError,
        match="only IPv4",
    ):
        steering.add_source(
            source_ip="2001:db8::1",
            case_id="case-a",
            path=(
                tmp_path
                / "state.json"
            ),
        )


def test_invalid_address_rejected(
    tmp_path: Path,
):
    with pytest.raises(
        steering.DeceptionSteeringError,
        match="invalid source",
    ):
        steering.add_source(
            source_ip="not-an-ip",
            case_id="case-a",
            path=(
                tmp_path
                / "state.json"
            ),
        )


def test_state_file_is_private(
    tmp_path: Path,
):
    path = (
        tmp_path
        / "quarantine.json"
    )

    steering.add_source(
        source_ip="192.0.2.5",
        case_id="case-a",
        path=path,
    )

    assert (
        path.stat().st_mode
        & 0o777
    ) == 0o600


def test_source_operation_lock_uses_custom_state_path(
    tmp_path: Path,
) -> None:
    path = (
        tmp_path
        / "deception"
        / "quarantine.json"
    )

    with steering.source_operation_lock(
        "198.18.0.50",
        path=path,
    ) as address:
        assert address == "198.18.0.50"

    assert (
        path.parent
        / "locks"
        / "198.18.0.50.lock"
    ).exists()
