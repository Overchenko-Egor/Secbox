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
from secbox.modules.deception.telemetry import case_telemetry
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
    telemetry = case_telemetry(
        source_ip=case.source_ip,
        started_at=case.created_at,
        ended_at=case.stopped_at,
    )

    return {
        **case.model_dump(
            mode="json"
        ),
        "telemetry":
            telemetry,
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
    expires_at: datetime | None = None,
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
        expires_at=expires_at,
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


def reap_expired_cases_action(
    *,
    now: datetime | None = None,
    case_store: DeceptionCaseStore | None = None,
) -> dict[str, object]:
    """Release expired IDS-driven Deception cases."""

    from secbox.modules.deception.runtime import reconcile
    from secbox.modules.deception.steering import (
        add_source,
        remove_source,
        source_operation_lock,
    )

    current = now or datetime.now(UTC)
    store = case_store or DeceptionCaseStore()

    expired = []
    errors = []

    for case in store.list_cases():
        if case.status != "observing":
            continue

        if case.trigger.source != "ids":
            continue

        if case.expires_at is None:
            continue

        if case.expires_at > current:
            continue

        removed = False

        with source_operation_lock(
            case.source_ip
        ):
            try:
                removed = remove_source(
                    source_ip=case.source_ip,
                    case_id=case.case_id,
                )

                if removed:
                    reconcile()

                stop_observe_case_action(
                    case_id=case.case_id,
                    case_store=store,
                )

                store.append_timeline(
                    case.case_id,
                    {
                        "timestamp": current.isoformat(),
                        "event": "quarantine_expired",
                        "source_ip": case.source_ip,
                    },
                )

                expired.append(case.case_id)

            except Exception as error:
                if removed:
                    try:
                        add_source(
                            source_ip=case.source_ip,
                            case_id=case.case_id,
                        )
                        reconcile()
                    except Exception:
                        pass

                errors.append(
                    {
                        "case_id": case.case_id,
                        "error": str(error),
                    }
                )

    if errors:
        raise DeceptionActionError(
            f"deception expiry cleanup failed: {errors}"
        )

    return {
        "expired_count": len(expired),
        "expired_cases": expired,
    }


def list_deception_quarantine_action(
    *,
    case_store: DeceptionCaseStore | None = None,
) -> dict[str, object]:
    """Return sources currently present in Deception steering state."""

    from secbox.modules.deception.steering import (
        load_state,
    )

    now = datetime.now(UTC)
    store = case_store or DeceptionCaseStore()

    state = load_state()

    sources = state["sources"]

    if not isinstance(
        sources,
        dict,
    ):
        raise DeceptionActionError(
            "invalid deception quarantine state"
        )

    items: list[dict[str, object]] = []

    for source_ip in sorted(
        sources
    ):
        entry = sources[source_ip]

        if not isinstance(
            entry,
            dict,
        ):
            continue

        case_ids = entry.get(
            "cases"
        )

        if not isinstance(
            case_ids,
            list,
        ):
            continue

        for case_id in case_ids:
            if not isinstance(
                case_id,
                str,
            ):
                continue

            try:
                case = store.load(
                    case_id
                )

            except DeceptionStoreError:
                items.append(
                    {
                        "case_id": case_id,
                        "source_ip": source_ip,
                        "status": "stale",
                        "created_at": None,
                        "expires_at": None,
                        "remaining_seconds": None,
                        "trigger": None,
                        "metadata_missing": True,
                    }
                )

                continue

            remaining = None

            if case.expires_at is not None:
                remaining = max(
                    0,
                    int(
                        (
                            case.expires_at
                            - now
                        ).total_seconds()
                    ),
                )

            items.append(
                {
                    "case_id":
                        case.case_id,
                    "source_ip":
                        source_ip,
                    "status":
                        case.status,
                    "created_at":
                        case.created_at.isoformat(),
                    "expires_at":
                        (
                            case.expires_at.isoformat()
                            if case.expires_at
                            else None
                        ),
                    "remaining_seconds":
                        remaining,
                    "trigger":
                        case.trigger.model_dump(
                            mode="json"
                        ),
                    "metadata_missing":
                        False,
                }
            )

    return {
        "quarantine_count":
            len(items),
        "quarantine":
            items,
    }


def release_deception_quarantine_action(
    *,
    case_id: str,
    case_store: DeceptionCaseStore | None = None,
) -> dict[str, object]:
    """Release one case from Deception quarantine."""

    from secbox.modules.deception.runtime import (
        reconcile,
    )
    from secbox.modules.deception.steering import (
        add_source,
        load_state,
        remove_source,
        source_operation_lock,
    )

    try:
        validate_case_id(
            case_id
        )

    except DeceptionStoreError as error:
        raise DeceptionActionError(
            str(error)
        ) from error

    store = (
        case_store
        or DeceptionCaseStore()
    )

    def find_sources() -> list[str]:
        state = load_state()

        sources = state["sources"]

        if not isinstance(
            sources,
            dict,
        ):
            raise DeceptionActionError(
                "invalid deception quarantine state"
            )

        matches: list[str] = []

        for source_ip, entry in (
            sources.items()
        ):
            if not isinstance(
                source_ip,
                str,
            ):
                continue

            if not isinstance(
                entry,
                dict,
            ):
                continue

            raw_cases = entry.get(
                "cases"
            )

            if not isinstance(
                raw_cases,
                list,
            ):
                continue

            if case_id in raw_cases:
                matches.append(
                    source_ip
                )

        return matches

    matches = find_sources()

    if not matches:
        try:
            case = store.load(
                case_id
            )

            source_ip = (
                case.source_ip
            )

            case_status = (
                case.status
            )

        except DeceptionStoreError:
            source_ip = None
            case_status = "unknown"

        return {
            "status":
                "already_released",
            "case_id":
                case_id,
            "source_ip":
                source_ip,
            "case_status":
                case_status,
        }

    if len(matches) != 1:
        raise DeceptionActionError(
            "deception case is referenced "
            "by multiple quarantine sources"
        )

    source_ip = matches[0]

    with source_operation_lock(
        source_ip
    ):
        matches = find_sources()

        if source_ip not in matches:
            return {
                "status":
                    "already_released",
                "case_id":
                    case_id,
                "source_ip":
                    source_ip,
            }

        try:
            case = store.load(
                case_id
            )

        except DeceptionStoreError:
            case = None

        removed = remove_source(
            source_ip=source_ip,
            case_id=case_id,
        )

        if not removed:
            return {
                "status":
                    "already_released",
                "case_id":
                    case_id,
                "source_ip":
                    source_ip,
            }

        try:
            runtime = reconcile()

            if (
                case is not None
                and case.status
                == "observing"
            ):
                stopped = (
                    stop_observe_case_action(
                        case_id=case_id,
                        case_store=store,
                    )
                )

                case_status = (
                    stopped.get(
                        "status",
                        "stopped",
                    )
                )

            elif case is not None:
                case_status = case.status

            else:
                case_status = "missing"

        except Exception as error:
            rollback_error = None

            try:
                add_source(
                    source_ip=source_ip,
                    case_id=case_id,
                )

                reconcile()

            except Exception as rollback:
                rollback_error = rollback

            detail = (
                "failed to release deception "
                f"quarantine: {error}"
            )

            if rollback_error is not None:
                detail += (
                    "; rollback failed: "
                    f"{rollback_error}"
                )

            raise DeceptionActionError(
                detail
            ) from error

        if case is not None:
            try:
                store.append_timeline(
                    case_id,
                    {
                        "timestamp":
                            datetime.now(
                                UTC
                            ).isoformat(),
                        "event":
                            "quarantine_released",
                        "source_ip":
                            source_ip,
                        "release_source":
                            "web",
                    },
                )

            except DeceptionStoreError:
                # Release itself has already
                # completed successfully.
                pass

        return {
            "status":
                "released",
            "case_id":
                case_id,
            "source_ip":
                source_ip,
            "case_status":
                case_status,
            "runtime":
                runtime,
        }
