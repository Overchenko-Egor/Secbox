from datetime import UTC, datetime, timedelta
from pathlib import Path

from secbox.modules.deception import recovery
from secbox.modules.deception.models import (
    DeceptionCase,
    DeceptionTrigger,
)
from secbox.modules.deception.store import (
    DeceptionCaseStore,
)
from secbox.modules.deception.steering import (
    add_source,
    load_state,
)


def make_case(
    store: DeceptionCaseStore,
    *,
    case_id: str,
    source_ip: str,
    status: str = "observing",
    created_at: datetime,
    expires_at=None,
) -> DeceptionCase:
    case = DeceptionCase(
        case_id=case_id,
        source_ip=source_ip,
        status=status,
        created_at=created_at,
        updated_at=created_at,
        expires_at=expires_at,
        trigger=DeceptionTrigger(
            source="ids",
            reason="recovery-test",
            signature_id=900001,
            severity=1,
            count=5,
        ),
        capture_unit=(
            f"secbox-deception-capture@"
            f"{case_id}.service"
        ),
    )

    store.create_layout(
        case=case,
    )

    return case


def test_recovery_removes_missing_case_reference(
    tmp_path: Path,
) -> None:
    state_path = (
        tmp_path
        / "quarantine.json"
    )

    store = DeceptionCaseStore(
        tmp_path / "cases"
    )

    add_source(
        source_ip="198.18.0.40",
        case_id="case-20261025T120000Z-deadbeef",
        path=state_path,
    )

    result = recovery.recover(
        case_store=store,
        state_path=state_path,
    )

    assert result["removed_count"] == 1

    assert (
        load_state(state_path)["sources"]
        == {}
    )


def test_recovery_restores_observing_ids_case(
    tmp_path: Path,
) -> None:
    state_path = (
        tmp_path
        / "quarantine.json"
    )

    store = DeceptionCaseStore(
        tmp_path / "cases"
    )

    now = datetime.now(UTC)

    case = make_case(
        store,
        case_id=(
            "case-20261025T120001Z-acde1234"
        ),
        source_ip="198.18.0.41",
        created_at=now,
        expires_at=(
            now + timedelta(minutes=15)
        ),
    )

    result = recovery.recover(
        now=now,
        case_store=store,
        state_path=state_path,
    )

    assert result["restored_count"] == 1

    sources = (
        load_state(state_path)[
            "sources"
        ]
    )

    assert sources[
        "198.18.0.41"
    ]["cases"] == [
        case.case_id
    ]


def test_recovery_stops_expired_case(
    tmp_path: Path,
    monkeypatch,
) -> None:
    state_path = (
        tmp_path
        / "quarantine.json"
    )

    store = DeceptionCaseStore(
        tmp_path / "cases"
    )

    now = datetime.now(UTC)

    case = make_case(
        store,
        case_id=(
            "case-20261025T120002Z-acde5678"
        ),
        source_ip="198.18.0.42",
        created_at=(
            now - timedelta(minutes=20)
        ),
        expires_at=(
            now - timedelta(minutes=5)
        ),
    )

    add_source(
        source_ip=case.source_ip,
        case_id=case.case_id,
        path=state_path,
    )

    def fake_stop(
        *,
        case_id,
        case_store,
    ):
        case_store.mark_stopped(
            case_id
        )

        return {
            "case_id": case_id,
            "status": "stopped",
        }

    monkeypatch.setattr(
        recovery,
        "stop_observe_case_action",
        fake_stop,
    )

    result = recovery.recover(
        now=now,
        case_store=store,
        state_path=state_path,
    )

    assert result["stopped_count"] == 1

    assert (
        load_state(state_path)["sources"]
        == {}
    )

    assert (
        store.load(case.case_id).status
        == "stopped"
    )
