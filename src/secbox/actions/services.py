"""Strictly allowlisted systemd service management."""

from __future__ import annotations

from dataclasses import dataclass
import subprocess
from typing import Literal


ServiceOperation = Literal[
    "start",
    "stop",
    "restart",
]


class ServiceActionError(RuntimeError):
    """A managed systemd operation failed."""


@dataclass(frozen=True)
class ServicePolicy:
    label: str
    kind: str
    allowed_actions: tuple[ServiceOperation, ...]
    note: str


SERVICE_POLICIES: dict[str, ServicePolicy] = {
    "secbox-web.service": ServicePolicy(
        label="SecBox Web",
        kind="critical",
        allowed_actions=(),
        note=(
            "Web management is read-only here to prevent "
            "locking the administrator out."
        ),
    ),
    "secbox-vpn.service": ServicePolicy(
        label="VPN Failover Controller",
        kind="critical",
        allowed_actions=("start", "restart"),
        note=(
            "Stop is blocked because the current VPN service "
            "does not perform runtime route cleanup on shutdown."
        ),
    ),
    "secbox-firewall.service": ServicePolicy(
        label="SecBox Firewall",
        kind="critical",
        allowed_actions=("start", "restart"),
        note=(
            "Stopping the firewall from Web UI is prohibited."
        ),
    ),
    "secbox-ids.service": ServicePolicy(
        label="SecBox IDS Processor",
        kind="security",
        allowed_actions=("start", "stop", "restart"),
        note="Stopping disables SecBox IDS event processing.",
    ),
    "suricata.service": ServicePolicy(
        label="Suricata",
        kind="security",
        allowed_actions=("start", "stop", "restart"),
        note=(
            "Stopping Suricata also affects secbox-ids.service."
        ),
    ),
    "dnsmasq.service": ServicePolicy(
        label="DNS / DHCP",
        kind="critical",
        allowed_actions=("start", "restart"),
        note=(
            "Stop is blocked because DNS/DHCP clients may "
            "immediately lose service."
        ),
    ),
    "secbox-doh-feed.service": ServicePolicy(
        label="Managed DoH Feed Update",
        kind="oneshot",
        allowed_actions=("start", "restart"),
        note=(
            "This is a oneshot unit. inactive/dead after a "
            "successful update is normal."
        ),
    ),
}


def _systemctl(
    arguments: list[str],
    *,
    timeout: float = 30.0,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            [
                "/usr/bin/systemctl",
                *arguments,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    except (
        OSError,
        subprocess.TimeoutExpired,
    ) as error:
        raise ServiceActionError(
            f"systemctl failed: {error}"
        ) from error


def _properties(unit: str) -> dict[str, str]:
    result = _systemctl(
        [
            "show",
            unit,
            "--no-pager",
            "--property=Description",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=UnitFileState",
        ],
        timeout=5.0,
    )

    if result.returncode != 0:
        message = (
            result.stderr.strip()
            or result.stdout.strip()
            or f"exit code {result.returncode}"
        )

        raise ServiceActionError(
            f"cannot read {unit}: {message}"
        )

    values: dict[str, str] = {}

    for line in result.stdout.splitlines():
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        values[key] = value

    return values


def get_service_status(unit: str) -> dict[str, object]:
    policy = SERVICE_POLICIES.get(unit)

    if policy is None:
        raise ServiceActionError(
            f"service is not allowlisted: {unit}"
        )

    values = _properties(unit)

    load_state = values.get(
        "LoadState",
        "unknown",
    )

    active_state = values.get(
        "ActiveState",
        "unknown",
    )

    sub_state = values.get(
        "SubState",
        "unknown",
    )

    if load_state == "not-found":
        health = "error"

    elif active_state == "failed":
        health = "error"

    elif active_state == "active":
        health = "ok"

    elif (
        policy.kind == "oneshot"
        and active_state == "inactive"
        and sub_state == "dead"
    ):
        health = "idle"

    else:
        health = "warning"

    return {
        "unit": unit,
        "label": policy.label,
        "description": (
            values.get("Description")
            or policy.label
        ),
        "kind": policy.kind,
        "load_state": load_state,
        "active_state": active_state,
        "sub_state": sub_state,
        "unit_file_state": values.get(
            "UnitFileState",
            "unknown",
        ),
        "health": health,
        "allowed_actions": list(
            policy.allowed_actions
        ),
        "note": policy.note,
    }


def get_managed_services_action() -> list[dict[str, object]]:
    return [
        get_service_status(unit)
        for unit in SERVICE_POLICIES
    ]


def service_action(
    unit: str,
    operation: str,
) -> dict[str, object]:
    policy = SERVICE_POLICIES.get(unit)

    if policy is None:
        raise ServiceActionError(
            f"service is not allowlisted: {unit}"
        )

    if operation not in {
        "start",
        "stop",
        "restart",
    }:
        raise ServiceActionError(
            f"unsupported service operation: {operation}"
        )

    if operation not in policy.allowed_actions:
        raise ServiceActionError(
            f"{operation} is not permitted for {unit}"
        )

    result = _systemctl(
        [
            operation,
            unit,
        ]
    )

    if result.returncode != 0:
        message = (
            result.stderr.strip()
            or result.stdout.strip()
            or f"exit code {result.returncode}"
        )

        raise ServiceActionError(
            f"{operation} {unit} failed: {message}"
        )

    return get_service_status(unit)
