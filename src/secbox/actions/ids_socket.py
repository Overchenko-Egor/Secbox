"""Restricted privileged action endpoint for the IDS daemon."""

from __future__ import annotations

import json
import sys

from secbox.actions.ids import (
    IdsActionError,
    add_ids_blackhole_action,
    get_ids_runtime_config_action,
)


MAX_REQUEST_BYTES = 64 * 1024


def emit(
    payload: dict[str, object],
) -> None:
    sys.stdout.write(
        json.dumps(
            payload,
            separators=(",", ":"),
        )
        + "\n"
    )

    sys.stdout.flush()


def read_request() -> dict[str, object]:
    raw = sys.stdin.buffer.read(
        MAX_REQUEST_BYTES + 1
    )

    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError(
            "request too large"
        )

    request = json.loads(
        raw.decode("utf-8")
    )

    if not isinstance(
        request,
        dict,
    ):
        raise ValueError(
            "request must be an object"
        )

    return request


def handle(
    request: dict[str, object],
) -> dict[str, object]:
    action = request.get(
        "action"
    )

    if action == "get-ids-runtime-config":
        if set(request) != {
            "action",
        }:
            raise ValueError(
                "unexpected get-ids-runtime-config fields"
            )

        try:
            config = (
                get_ids_runtime_config_action()
            )

        except IdsActionError as error:
            return {
                "ok": False,
                "error":
                    "ids_runtime_config_failed",
                "detail":
                    str(error),
            }

        return {
            "ok": True,
            "result": {
                "config":
                    config,
            },
        }

    if action == "ids-blackhole-add":
        expected = {
            "action",
            "address",
            "signature_id",
            "severity",
            "count",
        }

        if set(request) != expected:
            raise ValueError(
                "unexpected ids-blackhole-add fields"
            )

        address = request[
            "address"
        ]

        signature_id = request[
            "signature_id"
        ]

        severity = request[
            "severity"
        ]

        count = request[
            "count"
        ]

        if not isinstance(
            address,
            str,
        ):
            raise ValueError(
                "address must be a string"
            )

        for name, value in (
            (
                "signature_id",
                signature_id,
            ),
            (
                "severity",
                severity,
            ),
            (
                "count",
                count,
            ),
        ):
            if (
                not isinstance(
                    value,
                    int,
                )
                or isinstance(
                    value,
                    bool,
                )
            ):
                raise ValueError(
                    f"{name} must be an integer"
                )

        try:
            result = (
                add_ids_blackhole_action(
                    address=address,
                    signature_id=signature_id,
                    severity=severity,
                    count=count,
                )
            )

        except IdsActionError as error:
            return {
                "ok": False,
                "error":
                    "ids_blackhole_failed",
                "detail":
                    str(error),
            }

        if hasattr(
            result,
            "model_dump",
        ):
            result_payload = (
                result.model_dump(
                    mode="json"
                )
            )

        elif isinstance(
            result,
            dict,
        ):
            result_payload = result

        else:
            result_payload = {
                "status":
                    "accepted"
            }

        return {
            "ok": True,
            "result":
                result_payload,
        }

    raise ValueError(
        "unsupported IDS action"
    )


def main() -> None:
    try:
        request = read_request()

        response = handle(
            request
        )

    except (
        ValueError,
        KeyError,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ):
        response = {
            "ok": False,
            "error":
                "invalid_request",
        }

    emit(
        response
    )


if __name__ == "__main__":
    main()
