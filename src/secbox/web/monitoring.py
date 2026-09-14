"""Unprivileged, bounded observations of the gateway."""

import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel


SERVICE_UNITS = (
    "systemd-networkd.service",
    "dnsmasq.service",
    "secbox-firewall.service",
    "suricata.service",
    "secbox-ids.service",
    "secbox-vpn.service",
)


class ServiceStatus(BaseModel):
    name: str
    load_state: str = "unknown"
    active_state: str = "unknown"
    sub_state: str = "unknown"
    error: str | None = None


class SystemStatus(BaseModel):
    observed_at: datetime
    hostname: str
    kernel: str
    uptime_seconds: float | None
    load_average: list[float]
    memory_total_bytes: int | None
    memory_available_bytes: int | None


def system_status(proc_root: Path = Path("/proc")) -> SystemStatus:
    uptime: float | None = None
    total: int | None = None
    available: int | None = None
    try:
        uptime = float((proc_root / "uptime").read_text().split()[0])
    except (OSError, ValueError, IndexError):
        pass
    try:
        memory = {}
        for line in (proc_root / "meminfo").read_text().splitlines():
            key, value = line.split(":", 1)
            if key in {"MemTotal", "MemAvailable"}:
                memory[key] = int(value.split()[0]) * 1024
        total = memory.get("MemTotal")
        available = memory.get("MemAvailable")
    except (OSError, ValueError, IndexError):
        pass
    try:
        load_average = list(os.getloadavg())
    except (OSError, AttributeError):
        load_average = []
    return SystemStatus(
        observed_at=datetime.now(UTC),
        hostname=platform.node(),
        kernel=platform.release(),
        uptime_seconds=uptime,
        load_average=load_average,
        memory_total_bytes=total,
        memory_available_bytes=available,
    )


def service_statuses() -> list[ServiceStatus]:
    try:
        result = subprocess.run(
            ["systemctl", "show", "--no-pager", "--property=Id,LoadState,ActiveState,SubState", *SERVICE_UNITS],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return [ServiceStatus(name=name, error="systemd status unavailable") for name in SERVICE_UNITS]

    observed: dict[str, dict[str, str]] = {}
    for block in result.stdout.strip().split("\n\n"):
        properties = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        if "Id" in properties:
            observed[properties["Id"]] = properties

    statuses = []
    for name in SERVICE_UNITS:
        properties = observed.get(name)
        if properties is None:
            statuses.append(ServiceStatus(name=name, error="systemd returned no status for this unit"))
        else:
            statuses.append(ServiceStatus(
                name=name,
                load_state=properties.get("LoadState", "unknown"),
                active_state=properties.get("ActiveState", "unknown"),
                sub_state=properties.get("SubState", "unknown"),
            ))
    return statuses
