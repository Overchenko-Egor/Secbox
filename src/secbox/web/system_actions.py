"""Unprivileged Web client for System actions."""

from __future__ import annotations

import json
import socket

from pathlib import Path


ACTION_SOCKET = Path(
    "/run/secbox/action.sock"
)

TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 512 * 1024


class SystemWebActionError(RuntimeError):
    """System helper request failed."""


class SystemWebActionTimeoutError(
    SystemWebActionError
):
    """System helper timed out."""


def _exchange(
    request: dict[str, object],
) -> dict[str, object]:
    payload = (
        json.dumps(
            request,
            separators=(",", ":"),
        ).encode(
            "utf-8"
        )
        + b"\n"
    )

    client = socket.socket(
        socket.AF_UNIX,
        socket.SOCK_STREAM,
    )

    client.settimeout(
        TIMEOUT_SECONDS
    )

    try:
        client.connect(
            str(
                ACTION_SOCKET
            )
        )

        client.sendall(
            payload
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
                raise SystemWebActionError(
                    "system helper response exceeds size limit"
                )

            chunks.append(
                chunk
            )

    except socket.timeout as error:
        raise SystemWebActionTimeoutError(
            "system helper timed out"
        ) from error

    except OSError as error:
        raise SystemWebActionError(
            f"system helper unavailable: {error}"
        ) from error

    finally:
        client.close()

    raw = b"".join(
        chunks
    )

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
        raise SystemWebActionError(
            "system helper returned invalid JSON"
        ) from error

    if not isinstance(
        response,
        dict,
    ):
        raise SystemWebActionError(
            "system helper returned invalid response"
        )

    if response.get(
        "ok"
    ) is not True:
        detail = response.get(
            "detail"
        )

        raise SystemWebActionError(
            str(detail)
            if detail
            else "system action failed"
        )

    result = response.get(
        "result"
    )

    if not isinstance(
        result,
        dict,
    ):
        raise SystemWebActionError(
            "system helper result is invalid"
        )

    return result


def get_system_runtime_via_helper(
) -> dict[str, object]:
    return _exchange(
        {
            "action":
                "get-system-runtime",
        }
    )


def system_power_via_helper(
    *,
    operation: str,
    confirmation: str,
) -> dict[str, object]:
    return _exchange(
        {
            "action":
                "system-power",
            "operation":
                operation,
            "confirmation":
                confirmation,
        }
    )
