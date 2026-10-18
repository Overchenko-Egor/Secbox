"""HTTP API for SecBox host monitoring and power control."""

from __future__ import annotations

from fastapi import (
    APIRouter,
    HTTPException,
)

from secbox.web.system_actions import (
    SystemWebActionError,
    SystemWebActionTimeoutError,
    get_system_runtime_via_helper,
    system_power_via_helper,
)


router = APIRouter()


@router.get(
    "/api/v1/system/runtime",
    tags=["system"],
)
def system_runtime(
) -> dict[str, object]:
    try:
        return {
            "runtime":
                get_system_runtime_via_helper()
        }

    except SystemWebActionTimeoutError as error:
        raise HTTPException(
            status_code=504,
            detail=str(error),
        ) from error

    except SystemWebActionError as error:
        raise HTTPException(
            status_code=503,
            detail=str(error),
        ) from error


@router.post(
    "/api/v1/system/power",
    tags=["system"],
)
def system_power(
    payload: dict[str, object],
) -> dict[str, object]:
    operation = payload.get(
        "operation"
    )

    confirmation = payload.get(
        "confirmation"
    )

    if not isinstance(
        operation,
        str,
    ):
        raise HTTPException(
            status_code=422,
            detail="operation must be a string",
        )

    if not isinstance(
        confirmation,
        str,
    ):
        raise HTTPException(
            status_code=422,
            detail="confirmation must be a string",
        )

    if operation not in {
        "reboot",
        "poweroff",
    }:
        raise HTTPException(
            status_code=422,
            detail="unsupported power operation",
        )

    try:
        return system_power_via_helper(
            operation=operation,
            confirmation=confirmation,
        )

    except SystemWebActionTimeoutError as error:
        raise HTTPException(
            status_code=504,
            detail=str(error),
        ) from error

    except SystemWebActionError as error:
        raise HTTPException(
            status_code=422,
            detail=str(error),
        ) from error
