"""Privileged IDS configuration and runtime actions."""

from __future__ import annotations

import json
import os
import subprocess

from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path

from secbox.core.config_store import ConfigStore
from secbox.modules.ids.config import IdsConfig
from secbox.modules.ids.context import (
    build_ids_network_context,
)
from secbox.modules.ids.runtime import (
    build_ids_policy_config,
    build_ids_response_handler,
)
from secbox.modules.network.discovery import (
    discover_interfaces,
)


CONFIG_PATH = Path(
    "/etc/secbox/config.yml"
)

IDS_SERVICE = "secbox-ids.service"
SURICATA_SERVICE = "suricata.service"

MAX_EVE_TAIL_BYTES = 8 * 1024 * 1024
MAX_RECENT_ALERTS = 20


class IdsActionError(RuntimeError):
    """IDS configuration/runtime action failed."""


@dataclass(frozen=True)
class IdsActionResult:
    enabled: bool
    automatic_blackhole_enabled: bool
    automatic_blackhole_timeout: str


def _systemctl(
    operation: str,
    unit: str,
) -> None:
    result = subprocess.run(
        [
            "/usr/bin/systemctl",
            operation,
            unit,
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        detail = (
            result.stderr.strip()
            or result.stdout.strip()
            or f"exit code {result.returncode}"
        )

        raise IdsActionError(
            f"{operation} {unit} failed: "
            f"{detail}"
        )


def _service_state(
    unit: str,
) -> dict[str, object]:
    result = subprocess.run(
        [
            "/usr/bin/systemctl",
            "show",
            unit,
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=Result",
            "--property=ExecMainStatus",
            "--no-pager",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        return {
            "unit": unit,
            "available": False,
            "load_state": "unknown",
            "active_state": "unknown",
            "sub_state": "unknown",
        }

    values: dict[str, str] = {}

    for line in result.stdout.splitlines():
        if "=" not in line:
            continue

        key, value = line.split(
            "=",
            1,
        )

        values[key] = value

    return {
        "unit": unit,
        "available": (
            values.get("LoadState")
            == "loaded"
        ),
        "load_state": values.get(
            "LoadState",
            "unknown",
        ),
        "active_state": values.get(
            "ActiveState",
            "unknown",
        ),
        "sub_state": values.get(
            "SubState",
            "unknown",
        ),
        "result": values.get(
            "Result",
            "unknown",
        ),
        "exec_main_status": values.get(
            "ExecMainStatus",
            "",
        ),
    }


def _validate_candidate(
    candidate,
) -> None:
    ids = candidate.ids

    if (
        ids.automatic_blackhole.enabled
        and (
            candidate.firewall is None
            or not candidate.firewall.enabled
            or not candidate.firewall
            .dynamic_blacklist_enabled
        )
    ):
        raise IdsActionError(
            "IDS automatic blackhole requires "
            "Firewall dynamic blacklist to be enabled"
        )

    runtime_interfaces = (
        discover_interfaces()
    )

    if ids.enabled:
        build_ids_network_context(
            candidate,
            runtime_interfaces,
        )

        build_ids_policy_config(
            candidate,
            runtime_interfaces,
        )

    # Also validates automatic blackhole timeout.
    build_ids_response_handler(
        candidate,
        runtime_interfaces,
    )


def get_ids_action(
    *,
    store: ConfigStore | None = None,
) -> IdsConfig:
    store = store or ConfigStore(
        CONFIG_PATH
    )

    return store.load().ids


def validate_ids_action(
    ids: IdsConfig,
    *,
    store: ConfigStore | None = None,
) -> None:
    store = store or ConfigStore(
        CONFIG_PATH
    )

    previous = store.load()

    candidate = previous.model_copy(
        update={
            "ids": ids,
        }
    )

    candidate = type(
        previous
    ).model_validate(
        candidate.model_dump(
            mode="json"
        )
    )

    try:
        _validate_candidate(
            candidate
        )
    except IdsActionError:
        raise
    except Exception as error:
        raise IdsActionError(
            f"IDS validation failed: {error}"
        ) from error


def _activate_ids(
    ids: IdsConfig,
) -> None:
    if ids.enabled:
        _systemctl(
            "restart",
            IDS_SERVICE,
        )
    else:
        _systemctl(
            "stop",
            IDS_SERVICE,
        )


def apply_ids_action(
    ids: IdsConfig,
    *,
    store: ConfigStore | None = None,
) -> IdsActionResult:
    store = store or ConfigStore(
        CONFIG_PATH
    )

    previous = store.load()

    candidate = previous.model_copy(
        update={
            "ids": ids,
        }
    )

    candidate = type(
        previous
    ).model_validate(
        candidate.model_dump(
            mode="json"
        )
    )

    try:
        _validate_candidate(
            candidate
        )
    except IdsActionError:
        raise
    except Exception as error:
        raise IdsActionError(
            f"IDS validation failed: {error}"
        ) from error

    try:
        store.save(
            candidate
        )

        _activate_ids(
            candidate.ids
        )

    except Exception as error:
        rollback_errors: list[
            str
        ] = []

        try:
            store.save(
                previous
            )
        except Exception as rollback_error:
            rollback_errors.append(
                "configuration rollback "
                f"failed: {rollback_error}"
            )

        try:
            _activate_ids(
                previous.ids
            )
        except Exception as rollback_error:
            rollback_errors.append(
                "runtime rollback failed: "
                f"{rollback_error}"
            )

        detail = (
            "; ".join(
                rollback_errors
            )
            if rollback_errors
            else "previous configuration restored"
        )

        raise IdsActionError(
            f"IDS apply failed: {error}; "
            f"{detail}"
        ) from error

    return IdsActionResult(
        enabled=candidate.ids.enabled,
        automatic_blackhole_enabled=(
            candidate.ids
            .automatic_blackhole
            .enabled
        ),
        automatic_blackhole_timeout=(
            candidate.ids
            .automatic_blackhole
            .timeout
        ),
    )


def _read_eve_tail(
    path: Path,
) -> tuple[
    list[dict[str, object]],
    int,
]:
    try:
        size = path.stat().st_size

        with path.open(
            "rb"
        ) as file:
            start = max(
                0,
                size
                - MAX_EVE_TAIL_BYTES,
            )

            file.seek(
                start
            )

            raw = file.read(
                MAX_EVE_TAIL_BYTES
            )

    except OSError as error:
        raise IdsActionError(
            f"failed to read EVE log "
            f"{path}: {error}"
        ) from error

    lines = raw.splitlines()

    # First line may be partial when reading a
    # bounded tail from the middle of the file.
    if start > 0 and lines:
        lines = lines[1:]

    events: list[
        dict[str, object]
    ] = []

    for raw_line in lines:
        try:
            event = json.loads(
                raw_line.decode(
                    "utf-8",
                    errors="strict",
                )
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            continue

        if isinstance(
            event,
            dict,
        ):
            events.append(
                event
            )

    return events, size


def _sanitize_alert(
    event: dict[str, object],
) -> dict[str, object]:
    alert = event.get(
        "alert"
    )

    if not isinstance(
        alert,
        dict,
    ):
        alert = {}

    return {
        "timestamp": event.get(
            "timestamp"
        ),
        "interface": event.get(
            "in_iface"
        ),
        "source_ip": event.get(
            "src_ip"
        ),
        "source_port": event.get(
            "src_port"
        ),
        "destination_ip": event.get(
            "dest_ip"
        ),
        "destination_port": event.get(
            "dest_port"
        ),
        "protocol": event.get(
            "proto"
        ),
        "application": event.get(
            "app_proto"
        ),
        "signature_id": alert.get(
            "signature_id"
        ),
        "signature": alert.get(
            "signature"
        ),
        "category": alert.get(
            "category"
        ),
        "severity": alert.get(
            "severity"
        ),
        "action": alert.get(
            "action"
        ),
    }


def _stats_payload(
    event: dict[str, object] | None,
) -> dict[str, object]:
    if event is None:
        return {}

    stats = event.get(
        "stats"
    )

    if not isinstance(
        stats,
        dict,
    ):
        return {}

    capture = stats.get(
        "capture"
    )

    if not isinstance(
        capture,
        dict,
    ):
        capture = {}

    detect = stats.get(
        "detect"
    )

    if not isinstance(
        detect,
        dict,
    ):
        detect = {}

    engines = detect.get(
        "engines"
    )

    engine: dict[str, object] = {}

    if (
        isinstance(
            engines,
            list,
        )
        and engines
        and isinstance(
            engines[0],
            dict,
        )
    ):
        engine = engines[0]

    packets = capture.get(
        "kernel_packets"
    )

    drops = capture.get(
        "kernel_drops"
    )

    drop_percent = None

    if (
        isinstance(
            packets,
            int,
        )
        and packets > 0
        and isinstance(
            drops,
            int,
        )
    ):
        drop_percent = round(
            (
                drops
                / packets
            )
            * 100,
            4,
        )

    return {
        "timestamp": event.get(
            "timestamp"
        ),
        "kernel_packets": packets,
        "kernel_drops": drops,
        "kernel_drop_percent": (
            drop_percent
        ),
        "capture_errors": capture.get(
            "errors"
        ),
        "alerts": detect.get(
            "alert"
        ),
        "alerts_suppressed": detect.get(
            "alerts_suppressed"
        ),
        "rules_loaded": engine.get(
            "rules_loaded"
        ),
        "rules_failed": engine.get(
            "rules_failed"
        ),
        "rules_skipped": engine.get(
            "rules_skipped"
        ),
        "last_rule_reload": engine.get(
            "last_reload"
        ),
    }


def get_ids_runtime_action(
    *,
    store: ConfigStore | None = None,
) -> dict[str, object]:
    store = store or ConfigStore(
        CONFIG_PATH
    )

    config = store.load()

    eve_path = config.ids.eve_path

    events, eve_size = (
        _read_eve_tail(
            eve_path
        )
    )

    recent = deque(
        maxlen=MAX_RECENT_ALERTS
    )

    severity = Counter()
    signatures = Counter()
    interfaces = Counter()

    latest_stats: (
        dict[str, object]
        | None
    ) = None

    sampled_alert_count = 0

    for event in events:
        event_type = event.get(
            "event_type"
        )

        if event_type == "stats":
            latest_stats = event
            continue

        if event_type != "alert":
            continue

        sampled_alert_count += 1

        sanitized = (
            _sanitize_alert(
                event
            )
        )

        recent.append(
            sanitized
        )

        severity[
            str(
                sanitized.get(
                    "severity",
                    "unknown",
                )
            )
        ] += 1

        signatures[
            str(
                sanitized.get(
                    "signature"
                )
                or "unknown"
            )
        ] += 1

        interfaces[
            str(
                sanitized.get(
                    "interface"
                )
                or "unknown"
            )
        ] += 1

    return {
        "configured_enabled": (
            config.ids.enabled
        ),
        "eve_path": str(
            eve_path
        ),
        "eve_size_bytes": (
            eve_size
        ),
        "sample_window_bytes": min(
            eve_size,
            MAX_EVE_TAIL_BYTES,
        ),
        "sampled_alert_count": (
            sampled_alert_count
        ),
        "services": {
            "ids": _service_state(
                IDS_SERVICE
            ),
            "suricata": (
                _service_state(
                    SURICATA_SERVICE
                )
            ),
        },
        "stats": _stats_payload(
            latest_stats
        ),
        "severity_counts": dict(
            severity
        ),
        "interface_counts": dict(
            interfaces
        ),
        "top_signatures": [
            {
                "signature": name,
                "count": count,
            }
            for name, count
            in signatures.most_common(
                10
            )
        ],
        "recent_alerts": list(
            reversed(
                recent
            )
        ),
    }


def add_ids_blackhole_action(
    *,
    address: str,
    signature_id: int,
    severity: int,
    count: int,
    store: ConfigStore | None = None,
) -> dict[str, object]:
    """Validate and apply one IDS-triggered blacklist entry."""

    from secbox.modules.blacklist.service import (
        BlacklistError,
        add_blacklist_entry,
        parse_timeout,
        validate_ipv4_address,
    )
    from secbox.modules.ids.runtime import (
        build_protected_networks,
    )
    from secbox.modules.network.discovery import (
        discover_interfaces,
    )

    if isinstance(
        signature_id,
        bool,
    ) or not isinstance(
        signature_id,
        int,
    ):
        raise IdsActionError(
            "signature_id must be an integer"
        )

    if signature_id <= 0:
        raise IdsActionError(
            "signature_id must be greater than zero"
        )

    if isinstance(
        severity,
        bool,
    ) or not isinstance(
        severity,
        int,
    ):
        raise IdsActionError(
            "severity must be an integer"
        )

    if severity not in {
        1,
        2,
        3,
    }:
        raise IdsActionError(
            "severity must be between 1 and 3"
        )

    if isinstance(
        count,
        bool,
    ) or not isinstance(
        count,
        int,
    ):
        raise IdsActionError(
            "count must be an integer"
        )

    if count <= 0:
        raise IdsActionError(
            "count must be greater than zero"
        )

    try:
        normalized_address = (
            validate_ipv4_address(
                address
            )
        )

    except BlacklistError as error:
        raise IdsActionError(
            str(error)
        ) from error

    store = store or ConfigStore(
        CONFIG_PATH
    )

    try:
        config = store.load()

    except Exception as error:
        raise IdsActionError(
            "failed to load SecBox configuration: "
            f"{error}"
        ) from error

    if not config.ids.enabled:
        raise IdsActionError(
            "IDS is disabled"
        )

    automatic = (
        config.ids
        .automatic_blackhole
    )

    if not automatic.enabled:
        raise IdsActionError(
            "IDS automatic blackhole is disabled"
        )

    firewall = config.firewall

    if (
        firewall is None
        or not firewall.enabled
        or not firewall.dynamic_blacklist_enabled
    ):
        raise IdsActionError(
            "Firewall dynamic blacklist is disabled"
        )

    policy = config.ids.policy

    if (
        severity
        > policy.maximum_block_severity
    ):
        raise IdsActionError(
            "IDS severity does not meet "
            "automatic blocking policy"
        )

    if (
        count
        < policy.minimum_block_count
    ):
        raise IdsActionError(
            "IDS count does not meet "
            "automatic blocking policy"
        )

    try:
        parse_timeout(
            automatic.timeout
        )

        runtime_interfaces = (
            discover_interfaces()
        )

        protected_networks = [
            str(network)
            for network
            in build_protected_networks(
                config,
                runtime_interfaces,
            )
        ]

        reason = (
            "ids:"
            f"sid={signature_id};"
            f"severity={severity};"
            f"count={count}"
        )

        add_blacklist_entry(
            address=normalized_address,
            timeout=automatic.timeout,
            reason=reason,
            source="ids",
            protected_networks=(
                protected_networks
            ),
        )

    except Exception as error:
        raise IdsActionError(
            "failed to apply IDS blackhole: "
            f"{error}"
        ) from error

    return {
        "address": normalized_address,
        "timeout": automatic.timeout,
        "source": "ids",
    }



def get_ids_runtime_config_action(
    *,
    store: ConfigStore | None = None,
) -> dict[str, object]:
    """Return only configuration required by the IDS daemon."""

    store = store or ConfigStore(
        CONFIG_PATH
    )

    try:
        config = store.load()

    except Exception as error:
        raise IdsActionError(
            "failed to load IDS runtime configuration: "
            f"{error}"
        ) from error

    return {
        "network": config.network.model_dump(
            mode="json"
        ),
        "firewall": (
            config.firewall.model_dump(
                mode="json"
            )
            if config.firewall is not None
            else None
        ),
        "ids": config.ids.model_dump(
            mode="json"
        ),
    }


def add_ids_deception_action(
    *,
    address: str,
    signature_id: int,
    severity: int,
    count: int,
) -> dict[str, object]:
    """Validate and place one IDS source into Deception."""

    if not isinstance(address, str):
        raise IdsActionError(
            "address must be a string"
        )

    for name, value in (
        ("signature_id", signature_id),
        ("severity", severity),
        ("count", count),
    ):
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
        ):
            raise IdsActionError(
                f"{name} must be an integer"
            )

    if signature_id <= 0:
        raise IdsActionError(
            "signature_id must be greater than zero"
        )

    if severity not in {1, 2, 3}:
        raise IdsActionError(
            "severity must be between 1 and 3"
        )

    if count <= 0:
        raise IdsActionError(
            "count must be greater than zero"
        )

    ids = get_ids_action()

    if not ids.enabled:
        raise IdsActionError(
            "IDS is disabled"
        )

    if not ids.automatic_deception.enabled:
        raise IdsActionError(
            "IDS automatic deception is disabled"
        )

    if (
        severity
        > ids.policy.maximum_block_severity
    ):
        raise IdsActionError(
            "IDS severity does not meet "
            "automatic response threshold"
        )

    if (
        count
        < ids.policy.minimum_block_count
    ):
        raise IdsActionError(
            "IDS count does not meet "
            "automatic response threshold"
        )

    from secbox.modules.deception.steering import (
        add_source,
        remove_source,
        source_is_active,
        source_operation_lock,
    )
    from secbox.modules.deception.runtime import (
        reconcile,
    )
    from secbox.actions.deception import (
        DeceptionActionError,
        start_observe_case_action,
        stop_observe_case_action,
    )

    with source_operation_lock(address):
        if source_is_active(address):
            return {
                "status": "already_active",
                "source_ip": address,
            }

        from datetime import UTC, datetime
        from secbox.modules.blacklist.service import (
            parse_timeout,
        )

        try:
            deception_ttl = parse_timeout(
                ids.automatic_deception.timeout
            )
        except Exception as error:
            raise IdsActionError(
                "invalid automatic deception timeout: "
                f"{error}"
            ) from error

        expires_at = (
            datetime.now(UTC)
            + deception_ttl
        )

        try:
            case = start_observe_case_action(
                source_ip=address,
                reason=(
                    "ids:"
                    f"sid={signature_id};"
                    f"severity={severity};"
                    f"count={count}"
                ),
                trigger_source="ids",
                signature_id=signature_id,
                severity=severity,
                count=count,
                expires_at=expires_at,
            )

        except DeceptionActionError as error:
            raise IdsActionError(
                f"failed to create deception case: {error}"
            ) from error

        case_id = str(case["case_id"])

        source_added = False

        try:
            source_added = add_source(
                source_ip=address,
                case_id=case_id,
            )

            runtime = reconcile()

        except Exception as error:
            if source_added:
                try:
                    remove_source(
                        source_ip=address,
                        case_id=case_id,
                    )
                    reconcile()
                except Exception:
                    pass

            try:
                stop_observe_case_action(
                    case_id=case_id
                )
            except Exception:
                pass

            raise IdsActionError(
                f"failed to activate deception quarantine: {error}"
            ) from error

        return {
            "status": "quarantined",
            "source_ip": address,
            "case_id": case_id,
            "runtime": runtime,
        }
