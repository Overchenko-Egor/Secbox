"""HTTP API for Dynamic Blackhole."""

from __future__ import annotations

from fastapi import (
    APIRouter,
    HTTPException,
)

from secbox.web.blackhole_actions import (
    BlackholeWebActionError,
    add_blackhole_via_helper,
    delete_blackhole_via_helper,
    get_blackhole_runtime_via_helper,
    reconcile_blackhole_via_helper,
)


router = APIRouter()


def _fail(
    error: Exception,
) -> None:
    raise HTTPException(
        status_code=422,
        detail=str(error),
    ) from error


@router.get(
    "/api/v1/blackhole/runtime"
)
def blackhole_runtime():
    try:
        return {
            "runtime":
                get_blackhole_runtime_via_helper()
        }

    except BlackholeWebActionError as error:
        _fail(error)


@router.post(
    "/api/v1/blackhole/add"
)
def blackhole_add(
    payload: dict[str, object],
):
    address = payload.get(
        "address"
    )

    timeout = payload.get(
        "timeout"
    )

    reason = payload.get(
        "reason"
    )

    if not isinstance(
        address,
        str,
    ):
        raise HTTPException(
            status_code=422,
            detail="address must be a string",
        )

    if not isinstance(
        timeout,
        str,
    ):
        raise HTTPException(
            status_code=422,
            detail="timeout must be a string",
        )

    if not isinstance(
        reason,
        str,
    ):
        raise HTTPException(
            status_code=422,
            detail="reason must be a string",
        )

    try:
        return add_blackhole_via_helper(
            address=address,
            timeout=timeout,
            reason=reason,
        )

    except BlackholeWebActionError as error:
        _fail(error)


@router.post(
    "/api/v1/blackhole/delete"
)
def blackhole_delete(
    payload: dict[str, object],
):
    address = payload.get(
        "address"
    )

    if not isinstance(
        address,
        str,
    ):
        raise HTTPException(
            status_code=422,
            detail="address must be a string",
        )

    try:
        return delete_blackhole_via_helper(
            address=address
        )

    except BlackholeWebActionError as error:
        _fail(error)


@router.post(
    "/api/v1/blackhole/reconcile"
)
def blackhole_reconcile():
    try:
        return (
            reconcile_blackhole_via_helper()
        )

    except BlackholeWebActionError as error:
        _fail(error)
