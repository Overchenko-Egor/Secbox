"""Privileged Deception Observe-mode actions."""

from __future__ import annotations

import grp
import ipaddress
import os
import pwd
import secrets
import subprocess

from datetime import UTC, datetime
from pathlib import Path

from secbox.core.config_store import (
    ConfigStore,
)
from secbox.modules.deception.eve import (
    DeceptionEveError,
    snapshot_eve_for_source,
)
from secbox.modules.deception.models import (
    DeceptionCase,
    DeceptionTrigger,
)
from secbox.modules.deception.store import (
    DEFAULT_CASE_ROOT,
    DeceptionCaseStore,
    DeceptionStoreError,
    validate_case_id,
)
from secbox.modules.ids.runtime import (
    build_protected_networks,
)
from secbox.modules.network.discovery import (
    discover_interfaces,
)


CONFIG_PATH = Path(
    os.environ.get(
        "SECBOX_CONFIG_PATH",
        "/etc/secbox/config.yml",
    )
)

CAPTURE_UNIT_PREFIX = (
    "secbox-deception-capture@"
)

DECEPTION_USER = (
    "secbox-deception"
)

DECEPTION_GROUP = (
    "secbox-deception"
)


class DeceptionActionError(RuntimeError):
    """Privileged Deception operation failed."""


def _systemctl(
    operation: str,
    unit: str,
) -> None:
    result = subprocess.run(
        [
            "/usr/bin/systemctl",
            operation,
            unit,
            "--no-pager",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    if result.returncode != 0:
        detail = (
            result.stderr.strip()
            or result.stdout.strip()
            or f"exit code {result.returncode}"
        )

        raise DeceptionActionError(
            f"{operation} {unit} failed: {detail}"
        )


def _validate_source(
    *,
    source_ip: str,
    config,
) -> str:
    try:
        address = (
            ipaddress.ip_address(
                source_ip
            )
        )

    except ValueError as error:
        raise DeceptionActionError(
            "invalid source IPv4 address"
        ) from error

    if not isinstance(
        address,
        ipaddress.IPv4Address,
    ):
        raise DeceptionActionError(
            "only IPv4 sources are supported"
        )

    try:
        interfaces = (
            discover_interfaces()
        )

        protected = (
            build_protected_networks(
                config,
                interfaces,
            )
        )

    except Exception as error:
        raise DeceptionActionError(
            "failed to build protected networks: "
            f"{error}"
        ) from error

    if any(
        address in network
        for network
        in protected
    ):
        raise DeceptionActionError(
            "source belongs to a protected "
            "or local SecBox network"
        )

    return str(
        address
    )


def _new_case_id() -> str:
    timestamp = (
        datetime.now(
            UTC
        )
        .strftime(
            "%Y%m%dT%H%M%SZ"
        )
    )

    token = secrets.token_hex(
        4
    )

    return (
        f"case-{timestamp}-{token}"
    )


def _capture_identity(
) -> tuple[int, int]:
    try:
        uid = pwd.getpwnam(
            DECEPTION_USER
        ).pw_uid

        gid = grp.getgrnam(
            DECEPTION_GROUP
        ).gr_gid

    except KeyError as error:
        raise DeceptionActionError(
            "secbox-deception identity is missing"
        ) from error

    return uid, gid


def _sanitize_reason(
    reason: str,
) -> str:
    value = reason.strip()

    if not value:
        raise DeceptionActionError(
            "reason must not be empty"
        )

    if len(value) > 256:
        raise DeceptionActionError(
            "reason is too long"
        )

    if not value.isprintable():
        raise DeceptionActionError(
            "reason contains control characters"
        )

    return value


def _case_payload(
    *,
    case: DeceptionCase,
    store: DeceptionCaseStore,
) -> dict[str, object]:
    return {
        **case.model_dump(
            mode="json"
        ),
        "pcap_files":
            store.pcap_files(
                case.case_id
            ),
    }


def start_observe_case_action(
    *,
    source_ip: str,
    reason: str,
    trigger_source: str = "manual",
    signature_id: int | None = None,
    severity: int | None = None,
    count: int | None = None,
    config_store: ConfigStore | None = None,
    case_store: DeceptionCaseStore | None = None,
) -> dict[str, object]:
    """Create one Observe-mode case and start bounded PCAP capture."""

    config_store = (
        config_store
        or ConfigStore(
            CONFIG_PATH
        )
    )

    case_store = (
        case_store
        or DeceptionCaseStore()
    )

    try:
        config = (
            config_store.load()
        )

    except Exception as error:
        raise DeceptionActionError(
            "failed to load SecBox configuration: "
            f"{error}"
        ) from error

    normalized_source = (
        _validate_source(
            source_ip=source_ip,
            config=config,
        )
    )

    clean_reason = (
        _sanitize_reason(
            reason
        )
    )

    try:
        trigger = (
            DeceptionTrigger(
                source=trigger_source,
                reason=clean_reason,
                signature_id=signature_id,
                severity=severity,
                count=count,
            )
        )

    except Exception as error:
        raise DeceptionActionError(
            f"invalid deception trigger: {error}"
        ) from error

    now = datetime.now(
        UTC
    )

    case_id = (
        _new_case_id()
    )

    unit = (
        f"{CAPTURE_UNIT_PREFIX}"
        f"{case_id}.service"
    )

    case = DeceptionCase(
        case_id=case_id,
        source_ip=normalized_source,
        status="observing",
        created_at=now,
        updated_at=now,
        trigger=trigger,
        capture_unit=unit,
    )

    uid, gid = (
        _capture_identity()
    )

    try:
        case_path = (
            case_store.create_layout(
                case=case,
                deception_uid=uid,
                deception_gid=gid,
            )
        )

        eve_path = (
            config.ids.eve_path
        )

        event_count = (
            snapshot_eve_for_source(
                source_ip=(
                    normalized_source
                ),
                source_path=eve_path,
                destination_path=(
                    case_path
                    / "eve.jsonl"
                ),
            )
        )

        case = case.model_copy(
            update={
                "eve_event_count":
                    event_count,
                "updated_at":
                    datetime.now(
                        UTC
                    ),
            }
        )

        case_store.save(
            case
        )

        case_store.append_timeline(
            case_id,
            {
                "timestamp":
                    datetime.now(
                        UTC
                    ).isoformat(),
                "event":
                    "eve_snapshot",
                "event_count":
                    event_count,
            },
        )

        _systemctl(
            "start",
            unit,
        )

        case_store.append_timeline(
            case_id,
            {
                "timestamp":
                    datetime.now(
                        UTC
                    ).isoformat(),
                "event":
                    "capture_started",
                "unit":
                    unit,
            },
        )

    except (
        DeceptionStoreError,
        DeceptionEveError,
        DeceptionActionError,
        OSError,
    ) as error:
        try:
            if (
                case_store
                .case_path(
                    case_id
                )
                .exists()
            ):
                case_store.mark_error(
                    case_id,
                    str(error),
                )

        except Exception:
            pass

        raise DeceptionActionError(
            f"failed to start deception case: {error}"
        ) from error

    return _case_payload(
        case=case,
        store=case_store,
    )


def stop_observe_case_action(
    *,
    case_id: str,
    case_store: DeceptionCaseStore | None = None,
) -> dict[str, object]:
    """Stop packet capture for one observation case."""

    try:
        validate_case_id(
            case_id
        )

    except DeceptionStoreError as error:
        raise DeceptionActionError(
            str(error)
        ) from error

    case_store = (
        case_store
        or DeceptionCaseStore()
    )

    try:
        case = case_store.load(
            case_id
        )

    except DeceptionStoreError as error:
        raise DeceptionActionError(
            str(error)
        ) from error

    if case.status == "stopped":
        return _case_payload(
            case=case,
            store=case_store,
        )

    try:
        _systemctl(
            "stop",
            case.capture_unit,
        )

        case = (
            case_store
            .mark_stopped(
                case_id
            )
        )

    except (
        DeceptionActionError,
        DeceptionStoreError,
    ) as error:
        raise DeceptionActionError(
            f"failed to stop deception case: {error}"
        ) from error

    return _case_payload(
        case=case,
        store=case_store,
    )


def get_deception_case_action(
    *,
    case_id: str,
    case_store: DeceptionCaseStore | None = None,
) -> dict[str, object]:
    case_store = (
        case_store
        or DeceptionCaseStore()
    )

    try:
        case = case_store.load(
            case_id
        )

    except DeceptionStoreError as error:
        raise DeceptionActionError(
            str(error)
        ) from error

    return _case_payload(
        case=case,
        store=case_store,
    )


def list_deception_cases_action(
    *,
    case_store: DeceptionCaseStore | None = None,
) -> dict[str, object]:
    case_store = (
        case_store
        or DeceptionCaseStore()
    )

    cases = [
        _case_payload(
            case=case,
            store=case_store,
        )
        for case
        in case_store.list_cases()
    ]

    return {
        "case_count":
            len(cases),
        "cases":
            cases,
    }
