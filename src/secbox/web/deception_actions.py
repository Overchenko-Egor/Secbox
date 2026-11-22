"""Unprivileged Web client for Deception actions."""

from __future__ import annotations

import json
import socket

from pathlib import Path


ACTION_SOCKET = Path("/run/secbox/action.sock")
TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class DeceptionWebActionError(RuntimeError):
    """Deception action helper request failed."""


def _exchange(
    request: dict[str, object],
) -> dict[str, object]:
    client = socket.socket(
        socket.AF_UNIX,
        socket.SOCK_STREAM,
    )

    client.settimeout(TIMEOUT_SECONDS)

    payload = (
        json.dumps(
            request,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )

    try:
        client.connect(str(ACTION_SOCKET))
        client.sendall(payload)
        client.shutdown(socket.SHUT_WR)

        chunks: list[bytes] = []
        total = 0

        while True:
            chunk = client.recv(65536)

            if not chunk:
                break

            total += len(chunk)

            if total > MAX_RESPONSE_BYTES:
                raise DeceptionWebActionError(
                    "deception helper response is too large"
                )

            chunks.append(chunk)

    except socket.timeout as error:
        raise DeceptionWebActionError(
            "deception helper timed out"
        ) from error

    except OSError as error:
        raise DeceptionWebActionError(
            f"deception helper unavailable: {error}"
        ) from error

    finally:
        client.close()

    raw = b"".join(chunks)

    try:
        response = json.loads(
            raw.decode("utf-8")
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as error:
        raise DeceptionWebActionError(
            "deception helper returned invalid JSON"
        ) from error

    if not isinstance(response, dict):
        raise DeceptionWebActionError(
            "deception helper returned invalid response"
        )

    if response.get("ok") is not True:
        detail = response.get("detail")

        raise DeceptionWebActionError(
            str(detail)
            if detail
            else "deception action failed"
        )

    result = response.get("result")

    if not isinstance(result, dict):
        raise DeceptionWebActionError(
            "deception helper result is invalid"
        )

    return result


def list_deception_cases_via_helper(
) -> dict[str, object]:
    return _exchange(
        {
            "action":
                "get-deception-cases",
        }
    )


def get_deception_case_via_helper(
    *,
    case_id: str,
) -> dict[str, object]:
    return _exchange(
        {
            "action":
                "get-deception-case",
            "case_id":
                case_id,
        }
    )


def list_deception_quarantine_via_helper(
) -> dict[str, object]:
    return _exchange(
        {
            "action":
                "get-deception-quarantine",
        }
    )


def release_deception_quarantine_via_helper(
    *,
    case_id: str,
) -> dict[str, object]:
    return _exchange(
        {
            "action":
                "release-deception-quarantine",
            "case_id":
                case_id,
        }
    )
