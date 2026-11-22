"""HTTP API for Deception telemetry."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from secbox.web.deception_actions import (
    DeceptionWebActionError,
    get_deception_case_via_helper,
    list_deception_cases_via_helper,
    list_deception_quarantine_via_helper,
    release_deception_quarantine_via_helper,
)


router = APIRouter()


def _fail(
    error: Exception,
) -> None:
    raise HTTPException(
        status_code=503,
        detail=str(error),
    ) from error


@router.get(
    "/api/v1/deception/cases"
)
def deception_cases():
    try:
        return list_deception_cases_via_helper()

    except DeceptionWebActionError as error:
        _fail(error)


@router.get(
    "/api/v1/deception/cases/{case_id}"
)
def deception_case(
    case_id: str,
):
    try:
        return get_deception_case_via_helper(
            case_id=case_id
        )

    except DeceptionWebActionError as error:
        _fail(error)



@router.get(
    "/api/v1/deception/quarantine"
)
def deception_quarantine():
    try:
        return (
            list_deception_quarantine_via_helper()
        )

    except DeceptionWebActionError as error:
        _fail(error)


@router.post(
    "/api/v1/deception/quarantine/{case_id}/release"
)
def release_deception_quarantine(
    case_id: str,
):
    try:
        return (
            release_deception_quarantine_via_helper(
                case_id=case_id
            )
        )

    except DeceptionWebActionError as error:
        _fail(error)
