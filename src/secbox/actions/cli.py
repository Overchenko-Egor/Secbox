"""Restricted privileged action interface for SecBox."""

import fcntl
import json
import os
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import typer
from pydantic import ValidationError

from secbox.core.config_store import (
    ConfigNotFoundError,
    ConfigStore,
    ConfigStoreError,
    ConfigValidationError,
)
from secbox.modules.content_filter.doh_feed.store import (
    DohFeedStore,
    DohFeedStoreError,
)


from secbox.actions.vpn import (
    VpnActionError,
    VpnActionResult,
    apply_vpn_action,
    get_vpn_action,
)
from secbox.modules.vpn.models import VpnConfig
from secbox.modules.network.models import NetworkConfig
from secbox.modules.dhcp.models import DhcpServerConfig
from secbox.actions.network_dhcp import (
    NetworkDhcpActionError,
    NetworkDhcpActionResult,
    apply_network_dhcp_action,
    get_network_dhcp_action,
)
from secbox.actions.content_filter import (
    ContentFilterActionError,
    apply_content_filter_action,
    get_content_filter_action,
)
from secbox.actions.firewall import (
    FirewallActionError,
    apply_firewall_action,
    get_firewall_action,
)
from secbox.modules.firewall.models import FirewallConfig
from secbox.modules.content_filter.models import ContentFilterConfig


from secbox.actions.ids import (
    IdsActionError,
    apply_ids_action,
    get_ids_action,
    get_ids_runtime_action,
    get_ids_runtime_config_action,
    validate_ids_action,
    add_ids_blackhole_action,
)
from secbox.modules.ids.config import IdsConfig


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



def _network_dhcp_result_payload(
    result: NetworkDhcpActionResult,
) -> dict[str, object]:
    return {
        "ok": True,
        "result": {
            "interfaces": result.interfaces,
            "dhcp_scopes": result.dhcp_scopes,
            "enabled_dhcp_scopes": result.enabled_dhcp_scopes,
        },
    }


def _execute_network_dhcp(
    network_payload: object,
    dhcp_payload: object,
) -> dict[str, object]:
    network = NetworkConfig.model_validate(
        network_payload
    )

    if not isinstance(dhcp_payload, list):
        raise ValueError(
            "dhcp must be an array"
        )

    dhcp = [
        DhcpServerConfig.model_validate(item)
        for item in dhcp_payload
    ]

    with configuration_lock():
        result = apply_network_dhcp_action(
            network,
            dhcp,
        )

    return _network_dhcp_result_payload(
        result
    )


def _handle_network_dhcp(
    network_payload: object,
    dhcp_payload: object,
) -> tuple[dict[str, object], int]:
    try:
        return (
            _execute_network_dhcp(
                network_payload,
                dhcp_payload,
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

    except NetworkDhcpActionError as error:
        return (
            {
                "ok": False,
                "error": "transaction_failed",
                "detail": str(error),
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



def _l2_handshake_status(
    interface: str,
) -> dict[str, object]:
    """Read WireGuard handshake state in the privileged worker."""

    wg = shutil.which("wg")

    if wg is None:
        return {
            "handshake_age_seconds": None,
            "error": "wg command is not available",
        }

    try:
        result = subprocess.run(
            [
                wg,
                "show",
                interface,
                "latest-handshakes",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {
            "handshake_age_seconds": None,
            "error": str(error),
        }

    if result.returncode != 0:
        return {
            "handshake_age_seconds": None,
            "error": (
                result.stderr.strip()
                or f"wg exited with {result.returncode}"
            ),
        }

    timestamps: list[int] = []

    for line in result.stdout.splitlines():
        fields = line.split()

        if len(fields) < 2:
            continue

        try:
            timestamps.append(int(fields[-1]))
        except ValueError:
            continue

    if not timestamps or max(timestamps) <= 0:
        return {
            "handshake_age_seconds": None,
            "error": "WireGuard handshake has not occurred yet",
        }

    return {
        "handshake_age_seconds": max(
            0,
            int(time.time()) - max(timestamps),
        ),
        "error": None,
    }


def _dashboard_context_payload() -> dict[str, object]:
    """Build sanitized privileged context for the Web Dashboard."""

    config_path = Path(
        os.environ.get(
            "SECBOX_CONFIG_PATH",
            "/etc/secbox/config.yml",
        )
    )

    try:
        config = ConfigStore(config_path).load()
    except (
        ConfigNotFoundError,
        ConfigValidationError,
        ConfigStoreError,
    ) as error:
        raise ValueError(
            f"dashboard configuration is unavailable: {error}"
        ) from error

    l2_handshakes: dict[str, object] = {}

    if config.vpn is not None and config.vpn.enabled:
        for tunnel in config.vpn.l2_tunnels:
            if not tunnel.enabled:
                continue

            interface = tunnel.transport.interface

            l2_handshakes[interface] = (
                _l2_handshake_status(interface)
            )

    try:
        feed_state = DohFeedStore().load()

        addresses = getattr(
            feed_state,
            "addresses",
            [],
        )

        updated_at = getattr(
            feed_state,
            "updated_at",
            None,
        )

        doh_feed: dict[str, object] = {
            "address_count": len(addresses),
            "updated_at": (
                updated_at.isoformat()
                if updated_at is not None
                else None
            ),
            "error": None,
        }

    except DohFeedStoreError as error:
        doh_feed = {
            "address_count": None,
            "updated_at": None,
            "error": str(error),
        }

    safe_config = {
        "network": config.network.model_dump(
            mode="json"
        ),
        "firewall": (
            config.firewall.model_dump(mode="json")
            if config.firewall is not None
            else None
        ),
        "ids": config.ids.model_dump(
            mode="json"
        ),
        "content_filter": (
            config.content_filter.model_dump(
                mode="json"
            )
            if config.content_filter is not None
            else None
        ),
        "vpn": (
            config.vpn.model_dump(mode="json")
            if config.vpn is not None
            else None
        ),
    }

    return {
        "config": safe_config,
        "l2_handshakes": l2_handshakes,
        "doh_feed": doh_feed,
    }


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

        action = request.get(
            "action"
        )

        if action == "get-dashboard-context":
            if set(request) != {
                "action",
            }:
                raise ValueError(
                    "unexpected get-dashboard-context fields"
                )

            _emit(
                {
                    "ok": True,
                    "result": _dashboard_context_payload(),
                }
            )
            return

        if action == "get-network-dhcp":
            if set(request) != {
                "action",
            }:
                raise ValueError(
                    "unexpected get-network-dhcp fields"
                )

            network, dhcp = get_network_dhcp_action()

            _emit(
                {
                    "ok": True,
                    "result": {
                        "network": network.model_dump(
                            mode="json"
                        ),
                        "dhcp": [
                            scope.model_dump(
                                mode="json"
                            )
                            for scope in dhcp
                        ],
                    },
                }
            )
            return

        if action == "apply-network-dhcp":
            if set(request) != {
                "action",
                "network",
                "dhcp",
            }:
                raise ValueError(
                    "unexpected apply-network-dhcp fields"
                )

            response, code = _handle_network_dhcp(
                request["network"],
                request["dhcp"],
            )

            _emit(
                response
            )

            if code:
                raise typer.Exit(
                    code
                )

            return

        if action == "get-blackhole-runtime":
            if set(request) != {
                "action",
            }:
                raise ValueError(
                    "unexpected get-blackhole-runtime fields"
                )

            from secbox.actions.blackhole import (
                BlackholeActionError,
                get_blackhole_runtime_action,
            )

            try:
                result = (
                    get_blackhole_runtime_action()
                )

            except BlackholeActionError as error:
                _emit(
                    {
                        "ok": False,
                        "error":
                            "blackhole_runtime_failed",
                        "detail": str(error),
                    }
                )
                return

            _emit(
                {
                    "ok": True,
                    "result": result,
                }
            )
            return

        if action == "blackhole-add":
            if set(request) != {
                "action",
                "address",
                "timeout",
                "reason",
            }:
                raise ValueError(
                    "unexpected blackhole-add fields"
                )

            if not all(
                isinstance(
                    request[field],
                    str,
                )
                for field in (
                    "address",
                    "timeout",
                    "reason",
                )
            ):
                raise ValueError(
                    "blackhole-add fields must be strings"
                )

            from secbox.actions.blackhole import (
                BlackholeActionError,
                add_blackhole_action,
            )

            try:
                result = (
                    add_blackhole_action(
                        address=request[
                            "address"
                        ],
                        timeout=request[
                            "timeout"
                        ],
                        reason=request[
                            "reason"
                        ],
                    )
                )

            except BlackholeActionError as error:
                _emit(
                    {
                        "ok": False,
                        "error":
                            "blackhole_add_failed",
                        "detail": str(error),
                    }
                )
                return

            _emit(
                {
                    "ok": True,
                    "result": result,
                }
            )
            return

        if action == "blackhole-delete":
            if set(request) != {
                "action",
                "address",
            }:
                raise ValueError(
                    "unexpected blackhole-delete fields"
                )

            if not isinstance(
                request["address"],
                str,
            ):
                raise ValueError(
                    "address must be a string"
                )

            from secbox.actions.blackhole import (
                BlackholeActionError,
                delete_blackhole_action,
            )

            try:
                result = (
                    delete_blackhole_action(
                        address=request[
                            "address"
                        ],
                    )
                )

            except BlackholeActionError as error:
                _emit(
                    {
                        "ok": False,
                        "error":
                            "blackhole_delete_failed",
                        "detail": str(error),
                    }
                )
                return

            _emit(
                {
                    "ok": True,
                    "result": result,
                }
            )
            return

        if action == "blackhole-reconcile":
            if set(request) != {
                "action",
            }:
                raise ValueError(
                    "unexpected blackhole-reconcile fields"
                )

            from secbox.actions.blackhole import (
                BlackholeActionError,
                reconcile_blackhole_action,
            )

            try:
                result = (
                    reconcile_blackhole_action()
                )

            except BlackholeActionError as error:
                _emit(
                    {
                        "ok": False,
                        "error":
                            "blackhole_reconcile_failed",
                        "detail": str(error),
                    }
                )
                return

            _emit(
                {
                    "ok": True,
                    "result": result,
                }
            )
            return

        if action == "get-firewall":
            if set(request) != {"action"}:
                raise ValueError(
                    "unexpected get-firewall fields"
                )

            firewall = get_firewall_action()

            _emit(
                {
                    "ok": True,
                    "result": {
                        "firewall": (
                            firewall.model_dump(mode="json")
                            if firewall is not None
                            else None
                        )
                    },
                }
            )
            return

        if action == "apply-firewall":
            if set(request) != {
                "action",
                "firewall",
            }:
                raise ValueError(
                    "unexpected apply-firewall fields"
                )

            try:
                firewall = FirewallConfig.model_validate(
                    request["firewall"]
                )

                result = apply_firewall_action(
                    firewall
                )

            except (
                FirewallActionError,
                ValidationError,
            ) as error:
                _emit(
                    {
                        "ok": False,
                        "error": "apply_failed",
                        "detail": str(error),
                    }
                )
                raise typer.Exit(EXIT_FAILED)

            _emit(
                {
                    "ok": True,
                    "result": {
                        "enabled": result.enabled,
                        "wan_interface": result.wan_interface,
                        "lan_interface": result.lan_interface,
                        "management_interface": (
                            result.management_interface
                        ),
                        "nat_enabled": result.nat_enabled,
                        "dynamic_blacklist_enabled": (
                            result.dynamic_blacklist_enabled
                        ),
                    },
                }
            )
            return

        if action == "get-firewall-runtime":
            if set(request) != {"action"}:
                raise ValueError(
                    "unexpected get-firewall-runtime fields"
                )

            from secbox.actions.firewall_runtime import (
                FirewallRuntimeError,
                get_firewall_runtime_action,
            )

            try:
                runtime = (
                    get_firewall_runtime_action()
                )

            except FirewallRuntimeError as error:
                _emit(
                    {
                        "ok": False,
                        "error": "runtime_failed",
                        "detail": str(error),
                    }
                )
                return

            _emit(
                {
                    "ok": True,
                    "result": {
                        "runtime": runtime,
                    },
                }
            )
            return

        if action == "get-ids-runtime-config":
            if set(request) != {
                "action",
            }:
                raise ValueError(
                    "unexpected "
                    "get-ids-runtime-config fields"
                )

            try:
                config = (
                    get_ids_runtime_config_action()
                )

            except IdsActionError as error:
                _emit(
                    {
                        "ok": False,
                        "error":
                            "ids_runtime_config_failed",
                        "detail": str(error),
                    }
                )
                return

            _emit(
                {
                    "ok": True,
                    "result": {
                        "config": config,
                    },
                }
            )
            return

        if action == "get-ids":
            if set(request) != {"action"}:
                raise ValueError(
                    "unexpected get-ids fields"
                )

            ids = get_ids_action()

            _emit(
                {
                    "ok": True,
                    "result": {
                        "ids": ids.model_dump(
                            mode="json"
                        )
                    },
                }
            )
            return

        if action == "validate-ids":
            if set(request) != {
                "action",
                "ids",
            }:
                raise ValueError(
                    "unexpected validate-ids fields"
                )

            try:
                ids = IdsConfig.model_validate(
                    request["ids"]
                )

                validate_ids_action(
                    ids
                )

            except (
                IdsActionError,
                ValidationError,
            ) as error:
                _emit(
                    {
                        "ok": False,
                        "error":
                            "validation_failed",
                        "detail": str(error),
                    }
                )
                return

            _emit(
                {
                    "ok": True,
                    "result": {
                        "valid": True,
                    },
                }
            )
            return

        if action == "apply-ids":
            if set(request) != {
                "action",
                "ids",
            }:
                raise ValueError(
                    "unexpected apply-ids fields"
                )

            try:
                ids = IdsConfig.model_validate(
                    request["ids"]
                )

                with configuration_lock():
                    result = apply_ids_action(
                        ids
                    )

            except ActionBusyError as error:
                _emit(
                    {
                        "ok": False,
                        "error": "busy",
                        "detail": str(error),
                    }
                )
                return

            except (
                IdsActionError,
                ValidationError,
            ) as error:
                _emit(
                    {
                        "ok": False,
                        "error":
                            "apply_failed",
                        "detail": str(error),
                    }
                )
                return

            _emit(
                {
                    "ok": True,
                    "result": {
                        "enabled":
                            result.enabled,
                        "automatic_blackhole_enabled":
                            result.automatic_blackhole_enabled,
                        "automatic_blackhole_timeout":
                            result.automatic_blackhole_timeout,
                    },
                }
            )
            return

        if action == "ids-blackhole-add":
            expected_fields = {
                "action",
                "address",
                "signature_id",
                "severity",
                "count",
            }

            if set(request) != expected_fields:
                raise ValueError(
                    "unexpected ids-blackhole-add fields"
                )

            address = request["address"]
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

            try:
                result = (
                    add_ids_blackhole_action(
                        address=address,
                        signature_id=(
                            signature_id
                        ),
                        severity=severity,
                        count=count,
                    )
                )

            except IdsActionError as error:
                _emit(
                    {
                        "ok": False,
                        "error":
                            "ids_blackhole_failed",
                        "detail": str(error),
                    }
                )
                return

            _emit(
                {
                    "ok": True,
                    "result": result,
                }
            )
            return

        if action == "get-ids-runtime":
            if set(request) != {"action"}:
                raise ValueError(
                    "unexpected get-ids-runtime fields"
                )

            try:
                runtime = (
                    get_ids_runtime_action()
                )

            except IdsActionError as error:
                _emit(
                    {
                        "ok": False,
                        "error":
                            "runtime_failed",
                        "detail": str(error),
                    }
                )
                return

            _emit(
                {
                    "ok": True,
                    "result": {
                        "runtime": runtime,
                    },
                }
            )
            return

        if action == "get-content-filter":
            if set(request) != {"action"}:
                raise ValueError(
                    "unexpected get-content-filter fields"
                )

            content_filter = get_content_filter_action()

            _emit(
                {
                    "ok": True,
                    "result": {
                        "content_filter": (
                            content_filter.model_dump(mode="json")
                            if content_filter is not None
                            else None
                        )
                    },
                }
            )
            return

        if action == "apply-content-filter":
            if set(request) != {
                "action",
                "content_filter",
            }:
                raise ValueError(
                    "unexpected apply-content-filter fields"
                )

            try:
                content_filter = ContentFilterConfig.model_validate(
                    request["content_filter"]
                )

                result = apply_content_filter_action(
                    content_filter
                )

            except (
                ContentFilterActionError,
                ValidationError,
            ) as error:
                _emit(
                    {
                        "ok": False,
                        "error": "apply_failed",
                        "detail": str(error),
                    }
                )
                raise typer.Exit(EXIT_FAILED)

            _emit(
                {
                    "ok": True,
                    "result": {
                        "enabled": result.enabled,
                        "default_action": (
                            result.default_action
                        ),
                        "blocked_domains": (
                            result.blocked_domains
                        ),
                        "allowed_domains": (
                            result.allowed_domains
                        ),
                        "doh_enabled": result.doh_enabled,
                        "managed_feed_enabled": (
                            result.managed_feed_enabled
                        ),
                    },
                }
            )
            return

        if action == "get-vpn":
            if set(request) != {
                "action",
            }:
                raise ValueError(
                    "unexpected get-vpn fields"
                )

            vpn = get_vpn_action()

            _emit(
                {
                    "ok": True,
                    "result": {
                        "vpn": vpn.model_dump(
                            mode="json"
                        )
                    },
                }
            )
            return

        if action == "apply-vpn":
            if set(request) != {
                "action",
                "vpn",
            }:
                raise ValueError(
                    "unexpected apply-vpn fields"
                )

            response, code = _handle_vpn(
                request["vpn"]
            )

            _emit(
                response
            )

            if code:
                raise typer.Exit(
                    code
                )

            return

        if action == "deception-observe-start":
            expected = {
                "action",
                "source_ip",
                "reason",
                "trigger_source",
                "signature_id",
                "severity",
                "count",
            }

            if set(request) != expected:
                raise ValueError(
                    "unexpected deception-observe-start fields"
                )

            from secbox.actions.deception import (
                DeceptionActionError,
                start_observe_case_action,
            )

            try:
                result = (
                    start_observe_case_action(
                        source_ip=request[
                            "source_ip"
                        ],
                        reason=request[
                            "reason"
                        ],
                        trigger_source=request[
                            "trigger_source"
                        ],
                        signature_id=request[
                            "signature_id"
                        ],
                        severity=request[
                            "severity"
                        ],
                        count=request[
                            "count"
                        ],
                    )
                )

            except DeceptionActionError as error:
                _emit(
                    {
                        "ok": False,
                        "error":
                            "deception_start_failed",
                        "detail":
                            str(error),
                    }
                )
                return

            _emit(
                {
                    "ok": True,
                    "result":
                        result,
                }
            )
            return

        if action == "deception-observe-stop":
            if set(request) != {
                "action",
                "case_id",
            }:
                raise ValueError(
                    "unexpected deception-observe-stop fields"
                )

            from secbox.actions.deception import (
                DeceptionActionError,
                stop_observe_case_action,
            )

            try:
                result = (
                    stop_observe_case_action(
                        case_id=request[
                            "case_id"
                        ]
                    )
                )

            except DeceptionActionError as error:
                _emit(
                    {
                        "ok": False,
                        "error":
                            "deception_stop_failed",
                        "detail":
                            str(error),
                    }
                )
                return

            _emit(
                {
                    "ok": True,
                    "result":
                        result,
                }
            )
            return

        if action == "get-deception-cases":
            if set(request) != {
                "action",
            }:
                raise ValueError(
                    "unexpected get-deception-cases fields"
                )

            from secbox.actions.deception import (
                list_deception_cases_action,
            )

            _emit(
                {
                    "ok": True,
                    "result":
                        list_deception_cases_action(),
                }
            )
            return

        if action == "get-deception-case":
            if set(request) != {
                "action",
                "case_id",
            }:
                raise ValueError(
                    "unexpected get-deception-case fields"
                )

            from secbox.actions.deception import (
                DeceptionActionError,
                get_deception_case_action,
            )

            try:
                result = (
                    get_deception_case_action(
                        case_id=request[
                            "case_id"
                        ]
                    )
                )

            except DeceptionActionError as error:
                _emit(
                    {
                        "ok": False,
                        "error":
                            "deception_get_failed",
                        "detail":
                            str(error),
                    }
                )
                return

            _emit(
                {
                    "ok": True,
                    "result":
                        result,
                }
            )
            return

        if action == "get-deception-quarantine":
            if set(request) != {
                "action",
            }:
                raise ValueError(
                    "unexpected get-deception-quarantine fields"
                )

            from secbox.actions.deception import (
                list_deception_quarantine_action,
            )

            try:
                result = (
                    list_deception_quarantine_action()
                )

            except Exception as error:
                _emit(
                    {
                        "ok": False,
                        "error":
                            "deception_quarantine_failed",
                        "detail":
                            str(error),
                    }
                )
                return

            _emit(
                {
                    "ok": True,
                    "result": result,
                }
            )
            return

        if action == "release-deception-quarantine":
            if set(request) != {
                "action",
                "case_id",
            }:
                raise ValueError(
                    "unexpected release-deception-quarantine fields"
                )

            from secbox.actions.deception import (
                DeceptionActionError,
                release_deception_quarantine_action,
            )

            try:
                result = (
                    release_deception_quarantine_action(
                        case_id=request[
                            "case_id"
                        ]
                    )
                )

            except DeceptionActionError as error:
                _emit(
                    {
                        "ok": False,
                        "error":
                            "deception_release_failed",
                        "detail":
                            str(error),
                    }
                )
                return

            _emit(
                {
                    "ok": True,
                    "result": result,
                }
            )
            return

        if action == "get-system-runtime":
            if set(request) != {
                "action",
            }:
                raise ValueError(
                    "unexpected get-system-runtime fields"
                )

            from secbox.actions.system import (
                SystemActionError,
                get_system_runtime_action,
            )

            try:
                result = (
                    get_system_runtime_action()
                )

            except SystemActionError as error:
                _emit(
                    {
                        "ok": False,
                        "error":
                            "system_runtime_failed",
                        "detail": str(error),
                    }
                )
                return

            _emit(
                {
                    "ok": True,
                    "result": result,
                }
            )
            return

        if action == "system-power":
            if set(request) != {
                "action",
                "operation",
                "confirmation",
            }:
                raise ValueError(
                    "unexpected system-power fields"
                )

            operation = request[
                "operation"
            ]

            confirmation = request[
                "confirmation"
            ]

            if (
                not isinstance(
                    operation,
                    str,
                )
                or not isinstance(
                    confirmation,
                    str,
                )
            ):
                raise ValueError(
                    "system-power fields must be strings"
                )

            from secbox.actions.system import (
                SystemActionError,
                system_power_action,
            )

            try:
                result = (
                    system_power_action(
                        operation=operation,
                        confirmation=confirmation,
                    )
                )

            except SystemActionError as error:
                _emit(
                    {
                        "ok": False,
                        "error":
                            "system_power_failed",
                        "detail": str(error),
                    }
                )
                return

            _emit(
                {
                    "ok": True,
                    "result": result,
                }
            )
            return

        if action == "get-services":
            if set(request) != {"action"}:
                raise ValueError(
                    "unexpected get-services fields"
                )

            from secbox.actions.services import (
                get_managed_services_action,
            )

            _emit(
                {
                    "ok": True,
                    "result": {
                        "services": (
                            get_managed_services_action()
                        )
                    },
                }
            )
            return

        if action == "service-action":
            if set(request) != {
                "action",
                "unit",
                "operation",
            }:
                raise ValueError(
                    "unexpected service-action fields"
                )

            from secbox.actions.services import (
                ServiceActionError,
                service_action,
            )

            try:
                result = service_action(
                    str(request["unit"]),
                    str(request["operation"]),
                )

            except ServiceActionError as error:
                _emit(
                    {
                        "ok": False,
                        "error": "service_action_failed",
                        "detail": str(error),
                    }
                )
                return

            _emit(
                {
                    "ok": True,
                    "result": {
                        "service": result,
                    },
                }
            )
            return

        raise ValueError(
            "unsupported action"
        )

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



if __name__ == "__main__":
    app()
