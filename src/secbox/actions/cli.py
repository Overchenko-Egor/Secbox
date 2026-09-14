"""Restricted privileged action interface for SecBox."""

import fcntl
import json
import os
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import typer
from pydantic import ValidationError

from secbox.actions.vpn import (
    VpnActionError,
    VpnActionResult,
    apply_vpn_action,
)
from secbox.modules.vpn.models import VpnConfig


MAX_INPUT_BYTES = 1024 * 1024

LOCK_PATH = Path(
    "/run/secbox/config-action.lock"
)

EXIT_FAILED = 1
EXIT_BUSY = 75


app = typer.Typer(
    name="secbox-action",
    add_completion=False,
    no_args_is_help=True,
    help="Restricted privileged SecBox configuration actions.",
)


@app.callback()
def main() -> None:
    """Restricted privileged SecBox configuration actions."""


class ActionBusyError(RuntimeError):
    """Raised when another configuration action owns the lock."""


@contextmanager
def configuration_lock(
    timeout: float = 5.0,
) -> Iterator[None]:
    LOCK_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    descriptor = os.open(
        LOCK_PATH,
        os.O_CREAT | os.O_RDWR,
        0o600,
    )

    deadline = (
        time.monotonic()
        + timeout
    )

    try:
        while True:
            try:
                fcntl.flock(
                    descriptor,
                    fcntl.LOCK_EX
                    | fcntl.LOCK_NB,
                )
                break

            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ActionBusyError(
                        "another SecBox configuration action is running"
                    )

                time.sleep(
                    0.1
                )

        yield

    finally:
        try:
            fcntl.flock(
                descriptor,
                fcntl.LOCK_UN,
            )
        finally:
            os.close(
                descriptor
            )


def _emit(
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


def _read_json_stdin() -> object:
    raw = sys.stdin.buffer.read(
        MAX_INPUT_BYTES + 1
    )

    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError(
            "action payload exceeds 1 MiB"
        )

    if not raw:
        raise ValueError(
            "action payload is empty"
        )

    return json.loads(
        raw.decode("utf-8")
    )


def _result_payload(
    result: VpnActionResult,
) -> dict[str, object]:
    return {
        "ok": True,
        "result": {
            "applied_tunnels": result.applied_tunnels,
            "removed_tunnels": result.removed_tunnels,
            "active_name": result.active_name,
            "active_interface": result.active_interface,
        },
    }


def _execute_vpn(
    payload: object,
) -> dict[str, object]:
    vpn = VpnConfig.model_validate(
        payload
    )

    with configuration_lock():
        result = apply_vpn_action(
            vpn
        )

    return _result_payload(
        result
    )


def _handle_vpn(
    payload: object,
) -> tuple[dict[str, object], int]:
    try:
        return (
            _execute_vpn(
                payload
            ),
            0,
        )

    except ActionBusyError:
        return (
            {
                "ok": False,
                "error": "busy",
            },
            EXIT_BUSY,
        )

    except (
        ValidationError,
        ValueError,
    ):
        return (
            {
                "ok": False,
                "error": "invalid_request",
            },
            EXIT_FAILED,
        )

    except VpnActionError:
        return (
            {
                "ok": False,
                "error": "transaction_failed",
            },
            EXIT_FAILED,
        )

    except Exception:
        return (
            {
                "ok": False,
                "error": "internal_error",
            },
            EXIT_FAILED,
        )


@app.command("apply-vpn")
def apply_vpn() -> None:
    """Apply a complete VPN configuration supplied as JSON on stdin."""

    try:
        payload = _read_json_stdin()

    except (
        ValueError,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ):
        _emit(
            {
                "ok": False,
                "error": "invalid_request",
            }
        )

        raise typer.Exit(
            EXIT_FAILED
        )

    response, code = _handle_vpn(
        payload
    )

    _emit(
        response
    )

    if code:
        raise typer.Exit(
            code
        )


@app.command(
    "socket-request",
    hidden=True,
)
def socket_request() -> None:
    """Process one privileged request from a systemd-connected socket."""

    try:
        request = _read_json_stdin()

        if not isinstance(
            request,
            dict,
        ):
            raise ValueError(
                "request must be an object"
            )

        if set(request) != {
            "action",
            "vpn",
        }:
            raise ValueError(
                "unexpected request fields"
            )

        if request.get("action") != "apply-vpn":
            raise ValueError(
                "unsupported action"
            )

        payload = request["vpn"]

    except (
        ValueError,
        KeyError,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ):
        _emit(
            {
                "ok": False,
                "error": "invalid_request",
            }
        )

        raise typer.Exit(
            EXIT_FAILED
        )

    response, code = _handle_vpn(
        payload
    )

    _emit(
        response
    )

    if code:
        raise typer.Exit(
            code
        )


if __name__ == "__main__":
    app()
