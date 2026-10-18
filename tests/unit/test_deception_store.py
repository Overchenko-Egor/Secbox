from datetime import UTC, datetime

from secbox.modules.deception.models import (
    DeceptionCase,
    DeceptionTrigger,
)
from secbox.modules.deception.store import (
    DeceptionCaseStore,
)


def make_case():
    now = datetime.now(
        UTC
    )

    return DeceptionCase(
        case_id=(
            "case-20261017T120000Z-"
            "1234abcd"
        ),
        source_ip="203.0.113.10",
        status="observing",
        created_at=now,
        updated_at=now,
        trigger=DeceptionTrigger(
            source="manual",
            reason="test",
        ),
        capture_unit=(
            "secbox-deception-capture@"
            "case-20261017T120000Z-"
            "1234abcd.service"
        ),
    )


def test_case_round_trip(
    tmp_path,
):
    store = DeceptionCaseStore(
        tmp_path
    )

    case = make_case()

    store.create_layout(
        case=case,
    )

    loaded = store.load(
        case.case_id
    )

    assert (
        loaded.case_id
        == case.case_id
    )

    assert (
        loaded.source_ip
        == "203.0.113.10"
    )

    assert (
        store.pcap_files(
            case.case_id
        )
        == []
    )


def test_mark_stopped(
    tmp_path,
):
    store = DeceptionCaseStore(
        tmp_path
    )

    case = make_case()

    store.create_layout(
        case=case,
    )

    stopped = (
        store.mark_stopped(
            case.case_id
        )
    )

    assert (
        stopped.status
        == "stopped"
    )

    assert (
        stopped.stopped_at
        is not None
    )
