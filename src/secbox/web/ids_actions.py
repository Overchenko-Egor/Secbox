"""Web client for privileged IDS actions."""

from __future__ import annotations

import json
import socket

from dataclasses import dataclass
from pathlib import Path

from secbox.modules.ids.config import (
    IdsConfig,
)


ACTION_SOCKET = Path(
    "/run/secbox/action.sock"
)

ACTION_TIMEOUT = 15.0
MAX_RESPONSE_BYTES = 16 * 1024 * 1024


class IdsWebActionError(RuntimeError):
    pass


class IdsWebActionTimeoutError(
    IdsWebActionError
):
    pass


class IdsWebActionBusyError(
    IdsWebActionError
):
    pass


@dataclass(frozen=True)
class IdsWebApplyResult:
    enabled: bool
    automatic_blackhole_enabled: bool
    automatic_blackhole_timeout: str


def _request(
    payload: dict[str, object],
) -> dict[str, object]:
    client = socket.socket(
        socket.AF_UNIX,
        socket.SOCK_STREAM,
    )

    client.settimeout(
        ACTION_TIMEOUT
    )

    try:
        client.connect(
            str(
                ACTION_SOCKET
            )
        )

        request = (
            json.dumps(
                payload,
                separators=(",", ":"),
            ).encode(
                "utf-8"
            )
            + b"\n"
        )

        client.sendall(
            request
        )

        client.shutdown(
            socket.SHUT_WR
        )

        chunks: list[
            bytes
        ] = []

        total = 0

        while True:
            chunk = client.recv(
                65536
            )

            if not chunk:
                break

            total += len(
                chunk
            )

            if (
                total
                > MAX_RESPONSE_BYTES
            ):
                raise IdsWebActionError(
                    "IDS action response "
                    "exceeds size limit"
                )

            chunks.append(
                chunk
            )

    except socket.timeout as error:
        raise IdsWebActionTimeoutError(
            "IDS privileged action "
            "timed out"
        ) from error

    except OSError as error:
        raise IdsWebActionError(
            "IDS privileged action "
            f"failed: {error}"
        ) from error

    finally:
        client.close()

    raw = b"".join(
        chunks
    ).strip()

    try:
        response = json.loads(
            raw.decode(
                "utf-8"
            )
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as error:
        raise IdsWebActionError(
            "IDS privileged action "
            "returned invalid JSON"
        ) from error

    if not isinstance(
        response,
        dict,
    ):
        raise IdsWebActionError(
            "IDS privileged action "
            "returned invalid response"
        )

    if response.get("ok") is True:
        result = response.get(
            "result"
        )

        if isinstance(
            result,
            dict,
        ):
            return result

        raise IdsWebActionError(
            "IDS privileged action "
            "returned no result"
        )

    detail = str(
        response.get(
            "detail"
        )
        or response.get(
            "error"
        )
        or "IDS action failed"
    )

    if (
        response.get("error")
        == "busy"
    ):
        raise IdsWebActionBusyError(
            detail
        )

    raise IdsWebActionError(
        detail
    )


def get_ids_via_helper(
) -> IdsConfig:
    result = _request(
        {
            "action": "get-ids",
        }
    )

    return IdsConfig.model_validate(
        result["ids"]
    )


def validate_ids_via_helper(
    ids: IdsConfig,
) -> None:
    _request(
        {
            "action": "validate-ids",
            "ids": ids.model_dump(
                mode="json"
            ),
        }
    )


def apply_ids_via_helper(
    ids: IdsConfig,
) -> IdsWebApplyResult:
    result = _request(
        {
            "action": "apply-ids",
            "ids": ids.model_dump(
                mode="json"
            ),
        }
    )

    return IdsWebApplyResult(
        enabled=bool(
            result["enabled"]
        ),
        automatic_blackhole_enabled=bool(
            result[
                "automatic_blackhole_enabled"
            ]
        ),
        automatic_blackhole_timeout=str(
            result[
                "automatic_blackhole_timeout"
            ]
        ),
    )


def get_ids_runtime_via_helper(
) -> dict[str, object]:
    result = _request(
        {
            "action":
                "get-ids-runtime",
        }
    )

    runtime = result.get(
        "runtime"
    )

    if not isinstance(
        runtime,
        dict,
    ):
        raise IdsWebActionError(
            "IDS runtime result "
            "is invalid"
        )

    return runtime
