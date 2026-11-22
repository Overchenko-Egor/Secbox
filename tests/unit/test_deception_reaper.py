from datetime import UTC, datetime, timedelta

from secbox.modules.deception.models import (
    DeceptionCase,
    DeceptionTrigger,
)


def make_case(
    *,
    source: str,
    expires_at,
) -> DeceptionCase:
    now = datetime.now(UTC)

    return DeceptionCase(
        case_id="case-20261025T120000Z-1234abcd",
        source_ip="198.18.0.10",
        status="observing",
        created_at=now,
        updated_at=now,
        expires_at=expires_at,
        trigger=DeceptionTrigger(
            source=source,
            reason="test",
        ),
        capture_unit="test.service",
    )


def test_case_expiry_is_persisted() -> None:
    now = datetime.now(UTC)

    case = make_case(
        source="ids",
        expires_at=now + timedelta(minutes=15),
    )

    assert case.expires_at is not None
    assert case.expires_at > now


def test_manual_case_can_have_no_expiry() -> None:
    case = make_case(
        source="manual",
        expires_at=None,
    )

    assert case.expires_at is None
