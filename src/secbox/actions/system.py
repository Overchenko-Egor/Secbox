"""Privileged and sanitized SecBox system operations."""

from __future__ import annotations

import logging
import os
import platform
import re
import socket
import subprocess
import time

from pathlib import Path

from secbox.core.version import __version__


logger = logging.getLogger(__name__)


SYSTEMCTL = "/usr/bin/systemctl"
JOURNALCTL = "/usr/bin/journalctl"

POWER_OPERATIONS = {
    "reboot": "REBOOT",
    "poweroff": "POWEROFF",
}


class SystemActionError(RuntimeError):
    """System operation failed."""


def _read_text(
    path: Path,
) -> str:
    try:
        return path.read_text(
            encoding="utf-8"
        ).strip()

    except OSError:
        return ""


def _proc_meminfo() -> dict[str, int]:
    values: dict[str, int] = {}

    raw = _read_text(
        Path("/proc/meminfo")
    )

    for line in raw.splitlines():
        if ":" not in line:
            continue

        key, rest = line.split(
            ":",
            1,
        )

        fields = rest.strip().split()

        if not fields:
            continue

        try:
            value = int(
                fields[0]
            )

        except ValueError:
            continue

        # /proc/meminfo uses kB.
        values[key] = (
            value * 1024
        )

    return values


def _cpu_sample() -> tuple[int, int]:
    raw = _read_text(
        Path("/proc/stat")
    )

    first = (
        raw.splitlines()[0]
        if raw
        else ""
    )

    fields = first.split()

    if (
        not fields
        or fields[0] != "cpu"
    ):
        raise SystemActionError(
            "CPU statistics are unavailable"
        )

    try:
        values = [
            int(value)
            for value
            in fields[1:]
        ]

    except ValueError as error:
        raise SystemActionError(
            "CPU statistics are invalid"
        ) from error

    total = sum(values)

    idle = sum(
        values[index]
        for index
        in (3, 4)
        if index < len(values)
    )

    return total, idle


def _cpu_percent() -> float | None:
    try:
        total1, idle1 = (
            _cpu_sample()
        )

        time.sleep(
            0.12
        )

        total2, idle2 = (
            _cpu_sample()
        )

    except SystemActionError:
        return None

    total_delta = (
        total2 - total1
    )

    idle_delta = (
        idle2 - idle1
    )

    if total_delta <= 0:
        return None

    used = (
        total_delta
        - idle_delta
    )

    return round(
        max(
            0.0,
            min(
                100.0,
                (
                    used
                    / total_delta
                    * 100.0
                ),
            ),
        ),
        1,
    )


def _load_average() -> list[float]:
    try:
        return [
            round(
                float(value),
                2,
            )
            for value
            in os.getloadavg()
        ]

    except OSError:
        return []


def _uptime_seconds() -> int:
    raw = _read_text(
        Path("/proc/uptime")
    )

    if not raw:
        return 0

    try:
        return int(
            float(
                raw.split()[0]
            )
        )

    except (
        ValueError,
        IndexError,
    ):
        return 0


def _filesystem_usage(
    path: str,
) -> dict[str, object]:
    try:
        stats = os.statvfs(
            path
        )

    except OSError as error:
        raise SystemActionError(
            f"filesystem statistics unavailable: {error}"
        ) from error

    total = (
        stats.f_blocks
        * stats.f_frsize
    )

    available = (
        stats.f_bavail
        * stats.f_frsize
    )

    used = max(
        0,
        total - (
            stats.f_bfree
            * stats.f_frsize
        ),
    )

    percent = (
        round(
            used
            / total
            * 100.0,
            1,
        )
        if total > 0
        else 0.0
    )

    return {
        "path":
            path,
        "total_bytes":
            total,
        "used_bytes":
            used,
        "available_bytes":
            available,
        "used_percent":
            percent,
    }


def _os_release() -> dict[str, str]:
    result: dict[str, str] = {}

    raw = _read_text(
        Path("/etc/os-release")
    )

    for line in raw.splitlines():
        if (
            not line
            or "=" not in line
        ):
            continue

        key, value = line.split(
            "=",
            1,
        )

        result[key] = (
            value.strip()
            .strip('"')
        )

    return result


def _failed_units() -> list[dict[str, str]]:
    try:
        result = subprocess.run(
            [
                SYSTEMCTL,
                "--failed",
                "--no-legend",
                "--plain",
                "--no-pager",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )

    except (
        OSError,
        subprocess.TimeoutExpired,
    ):
        return []

    if result.returncode not in {
        0,
        1,
    }:
        return []

    units: list[
        dict[str, str]
    ] = []

    for line in result.stdout.splitlines():
        fields = line.split(
            None,
            4,
        )

        if len(fields) < 4:
            continue

        units.append(
            {
                "unit":
                    fields[0],
                "load":
                    fields[1],
                "active":
                    fields[2],
                "sub":
                    fields[3],
                "description":
                    (
                        fields[4]
                        if len(fields) > 4
                        else ""
                    ),
            }
        )

    return units


def _journal_usage_bytes(
) -> int | None:
    try:
        result = subprocess.run(
            [
                JOURNALCTL,
                "--disk-usage",
                "--quiet",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )

    except (
        OSError,
        subprocess.TimeoutExpired,
    ):
        return None

    if result.returncode != 0:
        return None

    text = (
        result.stdout.strip()
        or result.stderr.strip()
    )

    # Example:
    # "Archived and active journals take up 53.2M in the file system."
    match = re.search(
        r"take up\s+([0-9.]+)([KMGTP]?)",
        text,
        flags=re.IGNORECASE,
    )

    if match is None:
        return None

    value = float(
        match.group(1)
    )

    suffix = (
        match.group(2)
        .upper()
    )

    multiplier = {
        "": 1,
        "K": 1024,
        "M": 1024 ** 2,
        "G": 1024 ** 3,
        "T": 1024 ** 4,
        "P": 1024 ** 5,
    }.get(
        suffix,
        1,
    )

    return int(
        value
        * multiplier
    )


def _temperatures(
) -> list[dict[str, object]]:
    readings: list[
        dict[str, object]
    ] = []

    seen: set[
        tuple[str, str]
    ] = set()

    candidates = list(
        Path(
            "/sys/class/thermal"
        ).glob(
            "thermal_zone*/temp"
        )
    )

    candidates.extend(
        Path(
            "/sys/class/hwmon"
        ).glob(
            "hwmon*/temp*_input"
        )
    )

    for path in candidates:
        raw = _read_text(
            path
        )

        if not raw:
            continue

        try:
            value = float(
                raw
            )

        except ValueError:
            continue

        if abs(value) > 1000:
            value /= 1000.0

        if (
            value < -100
            or value > 250
        ):
            continue

        label = ""

        if "thermal_zone" in str(
            path
        ):
            label = _read_text(
                path.parent / "type"
            )

        else:
            stem = (
                path.name
                .replace(
                    "_input",
                    "",
                )
            )

            label = _read_text(
                path.parent
                / f"{stem}_label"
            )

            if not label:
                label = _read_text(
                    path.parent
                    / "name"
                )

        label = (
            label
            or path.parent.name
        )

        key = (
            label,
            str(path),
        )

        if key in seen:
            continue

        seen.add(
            key
        )

        readings.append(
            {
                "label":
                    label,
                "celsius":
                    round(
                        value,
                        1,
                    ),
            }
        )

    readings.sort(
        key=lambda item:
            str(
                item["label"]
            )
    )

    return readings[:32]


def get_system_runtime_action(
) -> dict[str, object]:
    """Return sanitized host runtime information."""

    memory = _proc_meminfo()

    total = memory.get(
        "MemTotal",
        0,
    )

    available = memory.get(
        "MemAvailable",
        memory.get(
            "MemFree",
            0,
        ),
    )

    used = max(
        0,
        total - available,
    )

    swap_total = memory.get(
        "SwapTotal",
        0,
    )

    swap_free = memory.get(
        "SwapFree",
        0,
    )

    swap_used = max(
        0,
        swap_total - swap_free,
    )

    release = _os_release()

    failed = (
        _failed_units()
    )

    reboot_required = Path(
        "/var/run/reboot-required"
    ).exists()

    return {
        "hostname":
            socket.gethostname(),
        "secbox_version":
            __version__,
        "os": {
            "name":
                release.get(
                    "PRETTY_NAME",
                    platform.system(),
                ),
            "id":
                release.get(
                    "ID",
                    "",
                ),
            "version_id":
                release.get(
                    "VERSION_ID",
                    "",
                ),
        },
        "kernel": {
            "release":
                platform.release(),
            "machine":
                platform.machine(),
        },
        "uptime_seconds":
            _uptime_seconds(),
        "cpu": {
            "logical_count":
                os.cpu_count(),
            "used_percent":
                _cpu_percent(),
            "load_average":
                _load_average(),
        },
        "memory": {
            "total_bytes":
                total,
            "used_bytes":
                used,
            "available_bytes":
                available,
            "used_percent":
                (
                    round(
                        used
                        / total
                        * 100.0,
                        1,
                    )
                    if total
                    else 0.0
                ),
        },
        "swap": {
            "total_bytes":
                swap_total,
            "used_bytes":
                swap_used,
            "free_bytes":
                swap_free,
            "used_percent":
                (
                    round(
                        swap_used
                        / swap_total
                        * 100.0,
                        1,
                    )
                    if swap_total
                    else 0.0
                ),
        },
        "root_filesystem":
            _filesystem_usage(
                "/"
            ),
        "reboot_required":
            reboot_required,
        "failed_units":
            failed,
        "failed_unit_count":
            len(failed),
        "journal_bytes":
            _journal_usage_bytes(),
        "temperatures":
            _temperatures(),
        "observed_at":
            time.time(),
    }


def system_power_action(
    *,
    operation: str,
    confirmation: str,
) -> dict[str, object]:
    """Perform one explicitly allowlisted host power operation."""

    expected = (
        POWER_OPERATIONS
        .get(
            operation
        )
    )

    if expected is None:
        raise SystemActionError(
            "unsupported system power operation"
        )

    if confirmation != expected:
        raise SystemActionError(
            f"confirmation must be exactly {expected}"
        )

    logger.warning(
        "SecBox system power action requested: %s",
        operation,
    )

    command = [
        SYSTEMCTL,
        "--no-block",
        operation,
    ]

    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

    except OSError as error:
        raise SystemActionError(
            f"failed to request {operation}: {error}"
        ) from error

    return {
        "accepted":
            True,
        "operation":
            operation,
        "pid":
            process.pid,
    }
