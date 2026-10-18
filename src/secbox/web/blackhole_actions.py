"""Unprivileged Web client for Dynamic Blackhole actions."""

from __future__ import annotations

import json
import socket

from pathlib import Path


ACTION_SOCKET = Path(
    "/run/secbox/action.sock"
)

TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 256 * 1024


class BlackholeWebActionError(RuntimeError):
    """Blackhole action helper request failed."""


def _exchange(
    request: dict[str, object],
) -> dict[str, object]:
    client = socket.socket(
        socket.AF_UNIX,
        socket.SOCK_STREAM,
    )

    client.settimeout(
        TIMEOUT_SECONDS
    )

    payload = (
        json.dumps(
            request,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )

    try:
        client.connect(
            str(ACTION_SOCKET)
        )

        client.sendall(
            payload
        )

        client.shutdown(
            socket.SHUT_WR
        )

        chunks = []
        total = 0

        while True:
            chunk = client.recv(
                4096
            )

            if not chunk:
                break

            total += len(chunk)

            if total > MAX_RESPONSE_BYTES:
                raise BlackholeWebActionError(
                    "blackhole helper response is too large"
                )

            chunks.append(
                chunk
            )

    except socket.timeout as error:
        raise BlackholeWebActionError(
            "blackhole helper timed out"
        ) from error

    except OSError as error:
        raise BlackholeWebActionError(
            f"blackhole helper unavailable: {error}"
        ) from error

    finally:
        client.close()

    raw = b"".join(
        chunks
    )

    try:
        response = json.loads(
            raw.decode("utf-8")
        )

    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as error:
        raise BlackholeWebActionError(
            "blackhole helper returned invalid JSON"
        ) from error

    if not isinstance(
        response,
        dict,
    ):
        raise BlackholeWebActionError(
            "blackhole helper returned invalid response"
        )

    if response.get(
        "ok"
    ) is not True:
        detail = response.get(
            "detail"
        )

        raise BlackholeWebActionError(
            str(detail)
            if detail
            else "blackhole action failed"
        )

    result = response.get(
        "result"
    )

    if not isinstance(
        result,
        dict,
    ):
        raise BlackholeWebActionError(
            "blackhole helper result is invalid"
        )

    return result


def get_blackhole_runtime_via_helper(
) -> dict[str, object]:
    return _exchange(
        {
            "action":
                "get-blackhole-runtime",
        }
    )


def add_blackhole_via_helper(
    *,
    address: str,
    timeout: str,
    reason: str,
) -> dict[str, object]:
    return _exchange(
        {
            "action":
                "blackhole-add",
            "address":
                address,
            "timeout":
                timeout,
            "reason":
                reason,
        }
    )


def delete_blackhole_via_helper(
    *,
    address: str,
) -> dict[str, object]:
    return _exchange(
        {
            "action":
                "blackhole-delete",
            "address":
                address,
        }
    )


def reconcile_blackhole_via_helper(
) -> dict[str, object]:
    return _exchange(
        {
            "action":
                "blackhole-reconcile",
        }
    )
