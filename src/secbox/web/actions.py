"""Client for tightly constrained privileged SecBox actions."""

import json
import socket
from dataclasses import dataclass
from pathlib import Path

from secbox.modules.vpn.models import VpnConfig


ACTION_SOCKET = Path(
    "/run/secbox/action.sock"
)

ACTION_TIMEOUT_SECONDS = 45.0
MAX_RESPONSE_BYTES = 64 * 1024


class WebActionError(RuntimeError):
    """Base error for privileged Web actions."""


class WebActionBusyError(WebActionError):
    """Another configuration transaction is already running."""


class WebActionTimeoutError(WebActionError):
    """Privileged action timed out."""


@dataclass(frozen=True)
class WebVpnApplyResult:
    applied_tunnels: int
    removed_tunnels: int
    active_name: str | None
    active_interface: str | None


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

            total += len(
                chunk
            )

            if total > MAX_RESPONSE_BYTES:
                raise WebActionError(
                    "privileged helper response is too large"
                )

            chunks.append(
                chunk
            )

    except socket.timeout as error:
        raise WebActionTimeoutError(
            "privileged VPN action timed out"
        ) from error

    except OSError as error:
        raise WebActionError(
            "privileged action socket is unavailable"
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
        raise WebActionError(
            "privileged helper returned an invalid response"
        ) from error

    if not isinstance(
        response,
        dict,
    ):
        raise WebActionError(
            "privileged helper returned an invalid response"
        )

    return response


def apply_vpn_via_helper(
    vpn: VpnConfig,
) -> WebVpnApplyResult:
    """Submit validated VPN config through the privileged Unix socket."""

    response = _exchange(
        {
            "action": "apply-vpn",
            "vpn": vpn.model_dump(
                mode="json"
            ),
        }
    )

    error = response.get(
        "error"
    )

    if error == "busy":
        raise WebActionBusyError(
            "another configuration action is running"
        )

    if response.get("ok") is not True:
        raise WebActionError(
            "privileged VPN action failed"
        )

    data = response.get(
        "result"
    )

    if not isinstance(
        data,
        dict,
    ):
        raise WebActionError(
            "privileged helper result is missing"
        )

    try:
        return WebVpnApplyResult(
            applied_tunnels=int(
                data["applied_tunnels"]
            ),
            removed_tunnels=int(
                data["removed_tunnels"]
            ),
            active_name=data.get(
                "active_name"
            ),
            active_interface=data.get(
                "active_interface"
            ),
        )

    except (
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise WebActionError(
            "privileged helper result is invalid"
        ) from error


def get_vpn_via_helper() -> VpnConfig:
    """Read current VPN configuration through the privileged socket."""

    response = _exchange(
        {
            "action": "get-vpn",
        }
    )

    if response.get("ok") is not True:
        raise WebActionError(
            "privileged VPN configuration read failed"
        )

    result = response.get(
        "result"
    )

    if not isinstance(
        result,
        dict,
    ):
        raise WebActionError(
            "privileged helper result is missing"
        )

    raw_vpn = result.get(
        "vpn"
    )

    try:
        return VpnConfig.model_validate(
            raw_vpn
        )

    except Exception as error:
        raise WebActionError(
            "privileged helper returned invalid VPN configuration"
        ) from error


def get_vpn_via_helper() -> VpnConfig:
    """Read current VPN configuration through the privileged socket."""

    response = _exchange(
        {
            "action": "get-vpn",
        }
    )

    if response.get("ok") is not True:
        raise WebActionError(
            "privileged VPN configuration read failed"
        )

    result = response.get(
        "result"
    )

    if not isinstance(
        result,
        dict,
    ):
        raise WebActionError(
            "privileged helper result is missing"
        )

    raw_vpn = result.get(
        "vpn"
    )

    try:
        return VpnConfig.model_validate(
            raw_vpn
        )

    except Exception as error:
        raise WebActionError(
            "privileged helper returned invalid VPN configuration"
        ) from error
