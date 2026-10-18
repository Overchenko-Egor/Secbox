"""Restricted client used by IDS for privileged response actions."""

from __future__ import annotations

import json
import socket

from pathlib import Path

from secbox.core.models import SecBoxConfig


ACTION_SOCKET = Path(
    "/run/secbox/ids-action.sock"
)

ACTION_TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 64 * 1024


class IdsActionClientError(RuntimeError):
    """Privileged IDS action could not be completed."""


def _exchange(
    request: dict[str, object],
) -> dict[str, object]:
    payload = (
        json.dumps(
            request,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )

    client = socket.socket(
        socket.AF_UNIX,
        socket.SOCK_STREAM,
    )

    client.settimeout(
        ACTION_TIMEOUT_SECONDS
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

        chunks: list[bytes] = []
        total = 0

        while True:
            chunk = client.recv(
                4096
            )

            if not chunk:
                break

            total += len(chunk)

            if total > MAX_RESPONSE_BYTES:
                raise IdsActionClientError(
                    "privileged IDS response exceeds size limit"
                )

            chunks.append(chunk)

    except socket.timeout as error:
        raise IdsActionClientError(
            "privileged IDS action timed out"
        ) from error

    except OSError as error:
        raise IdsActionClientError(
            "privileged IDS action socket is unavailable: "
            f"{error}"
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
        raise IdsActionClientError(
            "privileged IDS action returned invalid JSON"
        ) from error

    if not isinstance(
        response,
        dict,
    ):
        raise IdsActionClientError(
            "privileged IDS action returned invalid response"
        )

    return response


def add_ids_blackhole_via_helper(
    *,
    address: str,
    signature_id: int,
    severity: int,
    count: int,
) -> None:
    """Request one policy-approved IDS blackhole entry."""

    response = _exchange(
        {
            "action": "ids-blackhole-add",
            "address": address,
            "signature_id": signature_id,
            "severity": severity,
            "count": count,
        }
    )

    if response.get("ok") is True:
        return

    detail = response.get(
        "detail"
    )

    if (
        isinstance(detail, str)
        and detail.strip()
    ):
        raise IdsActionClientError(
            detail.strip()
        )

    raise IdsActionClientError(
        "privileged IDS blackhole action failed"
    )



def get_ids_runtime_config_via_helper(
) -> SecBoxConfig:
    """Read the minimal IDS runtime configuration."""

    response = _exchange(
        {
            "action":
                "get-ids-runtime-config",
        }
    )

    if response.get("ok") is not True:
        detail = response.get(
            "detail"
        )

        raise IdsActionClientError(
            str(detail)
            if detail
            else (
                "privileged IDS runtime "
                "configuration read failed"
            )
        )

    result = response.get(
        "result"
    )

    if not isinstance(
        result,
        dict,
    ):
        raise IdsActionClientError(
            "privileged IDS runtime "
            "configuration result is invalid"
        )

    raw_config = result.get(
        "config"
    )

    if not isinstance(
        raw_config,
        dict,
    ):
        raise IdsActionClientError(
            "privileged IDS runtime "
            "configuration is missing"
        )

    try:
        return SecBoxConfig.model_validate(
            raw_config
        )

    except Exception as error:
        raise IdsActionClientError(
            "privileged IDS runtime "
            "configuration is invalid"
        ) from error
