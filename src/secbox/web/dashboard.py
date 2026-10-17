"""Read-only operational dashboard aggregation."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from secbox.core.models import SecBoxConfig
from secbox.modules.blacklist.store import (
    BlacklistStore,
    BlacklistStoreError,
)
from secbox.modules.content_filter.validator import (
    ContentFilterValidationError,
    validate_content_filter_config,
)
from secbox.modules.network.discovery import (
    NetworkDiscoveryError,
    discover_interfaces,
)
from secbox.modules.network.runtime import (
    NetworkRuntimeError,
    NetworkRuntimeStore,
    build_network_status,
)

from secbox.web.monitoring import (
    ServiceStatus,
    service_statuses,
    system_status,
)


DashboardSeverity = Literal[
    "ok",
    "warning",
    "error",
    "unknown",
]


VPN_RUNTIME_PATH = Path(
    "/var/lib/secbox/vpn-runtime.json"
)
NETWORK_RUNTIME_PATH = Path(
    "/var/lib/secbox/network-runtime.json"
)


class DashboardComponent(BaseModel):
    """Health and compact runtime information for one subsystem."""

    model_config = ConfigDict(extra="forbid")

    status: DashboardSeverity
    message: str
    details: dict[str, Any] = Field(
        default_factory=dict
    )


class DashboardSummary(BaseModel):
    """Number of dashboard components in each health state."""

    model_config = ConfigDict(extra="forbid")

    ok: int = 0
    warning: int = 0
    error: int = 0
    unknown: int = 0


class DashboardResponse(BaseModel):
    """Aggregated operational state."""

    model_config = ConfigDict(extra="forbid")

    status: DashboardSeverity
    updated_at: datetime
    summary: DashboardSummary
    components: dict[str, DashboardComponent]


def _read_json(
    path: Path,
) -> tuple[dict[str, Any] | None, str | None]:
    """Read an optional JSON runtime snapshot."""

    try:
        if not path.exists():
            return None, "runtime snapshot is not available"

        payload = json.loads(
            path.read_text(
                encoding="utf-8",
            )
        )

        if not isinstance(payload, dict):
            return None, "runtime snapshot is not a JSON object"

        return payload, None

    except (
        OSError,
        json.JSONDecodeError,
    ) as error:
        return None, str(error)


def _service_map(
    services: list[ServiceStatus],
) -> dict[str, ServiceStatus]:
    return {
        service.name: service
        for service in services
    }


def _service_component(
    services: dict[str, ServiceStatus],
    unit: str,
    *,
    label: str,
) -> DashboardComponent:
    service = services.get(unit)

    if service is None:
        return DashboardComponent(
            status="unknown",
            message=f"{label} service status unavailable",
        )

    details = {
        "unit": service.name,
        "load_state": service.load_state,
        "active_state": service.active_state,
        "sub_state": service.sub_state,
    }

    if service.error:
        details["error"] = service.error

        return DashboardComponent(
            status="unknown",
            message=f"{label} service status unavailable",
            details=details,
        )

    if (
        service.load_state == "loaded"
        and service.active_state == "active"
    ):
        return DashboardComponent(
            status="ok",
            message=f"{label} service is active",
            details=details,
        )

    if service.load_state == "not-found":
        return DashboardComponent(
            status="error",
            message=f"{label} service is not installed",
            details=details,
        )

    return DashboardComponent(
        status="error",
        message=f"{label} service is not active",
        details=details,
    )


def _system_component() -> DashboardComponent:
    try:
        state = system_status()
    except Exception as error:
        return DashboardComponent(
            status="unknown",
            message="System status unavailable",
            details={
                "error": str(error),
            },
        )

    details = state.model_dump(
        mode="json",
    )

    if (
        state.memory_total_bytes
        and state.memory_available_bytes is not None
    ):
        used_ratio = (
            1
            - state.memory_available_bytes
            / state.memory_total_bytes
        )

        details["memory_used_percent"] = round(
            used_ratio * 100,
            1,
        )

        if used_ratio >= 0.95:
            return DashboardComponent(
                status="error",
                message="System memory is critically low",
                details=details,
            )

        if used_ratio >= 0.85:
            return DashboardComponent(
                status="warning",
                message="System memory pressure is high",
                details=details,
            )

    return DashboardComponent(
        status="ok",
        message="System metrics are available",
        details=details,
    )


def _runtime_component(
    path: Path,
    *,
    label: str,
) -> DashboardComponent:
    payload, error = _read_json(
        path
    )

    if payload is None:
        return DashboardComponent(
            status="unknown",
            message=f"{label} runtime state unavailable",
            details={
                "path": str(path),
                "error": error,
            },
        )

    return DashboardComponent(
        status="ok",
        message=f"{label} runtime state available",
        details=payload,
    )



def _run_command(
    command: list[str],
) -> tuple[str | None, str | None]:
    """Run one bounded read-only system command."""

    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (
        OSError,
        subprocess.TimeoutExpired,
    ) as error:
        return None, str(error)

    if result.returncode != 0:
        error = (
            result.stderr.strip()
            or result.stdout.strip()
            or f"exit code {result.returncode}"
        )
        return None, error

    return result.stdout, None


def _link_state(
    interface: str,
) -> tuple[bool | None, dict[str, Any]]:
    """Return existence/admin state for one kernel interface."""

    output, error = _run_command(
        [
            "/usr/sbin/ip",
            "-j",
            "link",
            "show",
            "dev",
            interface,
        ]
    )

    if output is None:
        return False, {
            "interface": interface,
            "error": error,
        }

    try:
        payload = json.loads(output)

        if (
            not isinstance(payload, list)
            or not payload
            or not isinstance(payload[0], dict)
        ):
            raise ValueError(
                "unexpected ip link JSON"
            )

        state = payload[0]
        flags = state.get("flags", [])

        return True, {
            "interface": interface,
            "operstate": state.get(
                "operstate",
                "UNKNOWN",
            ),
            "admin_up": "UP" in flags,
            "flags": flags,
            "master": state.get("master"),
        }

    except (
        json.JSONDecodeError,
        ValueError,
    ) as error:
        return None, {
            "interface": interface,
            "error": str(error),
        }


def _bridge_members(
    bridge: str,
) -> tuple[set[str] | None, str | None]:
    """Return interfaces currently enslaved to a bridge."""

    output, error = _run_command(
        [
            "/usr/sbin/ip",
            "-j",
            "link",
            "show",
            "master",
            bridge,
        ]
    )

    if output is None:
        return None, error

    try:
        payload = json.loads(output)

        members = {
            str(item["ifname"])
            for item in payload
            if isinstance(item, dict)
            and item.get("ifname")
        }

        return members, None

    except (
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as error:
        return None, str(error)


def _wireguard_handshake_age(
    interface: str,
) -> tuple[int | None, str | None]:
    """Return age of the newest WireGuard handshake."""

    output, error = _run_command(
        [
            "/usr/bin/wg",
            "show",
            interface,
            "latest-handshakes",
        ]
    )

    if output is None:
        return None, error

    handshakes: list[int] = []

    for line in output.splitlines():
        fields = line.split()

        if len(fields) < 2:
            continue

        try:
            timestamp = int(fields[-1])
        except ValueError:
            continue

        handshakes.append(timestamp)

    if not handshakes:
        return None, "WireGuard peer is not available"

    latest = max(handshakes)

    if latest <= 0:
        return None, "WireGuard handshake has not occurred yet"

    return max(
        0,
        int(time.time()) - latest,
    ), None



def _network_operational_component(
    runtime_path: Path,
) -> DashboardComponent:
    """Build network health from managed metadata and live interface state."""

    store = NetworkRuntimeStore(runtime_path)

    try:
        metadata = store.load()
    except NetworkRuntimeError as error:
        return DashboardComponent(
            status="unknown",
            message="Network runtime unavailable",
            details={"error": str(error)},
        )

    if metadata is None:
        return DashboardComponent(
            status="unknown",
            message="Network runtime unavailable",
            details={},
        )

    try:
        runtime_interfaces = discover_interfaces()
    except NetworkDiscoveryError as error:
        return DashboardComponent(
            status="unknown",
            message="Network interface discovery failed",
            details={"error": str(error)},
        )

    status = build_network_status(
        metadata,
        runtime_interfaces,
    )

    interfaces = [
        interface.model_dump(mode="json")
        for interface in status.interfaces
    ]

    errors: list[str] = []
    warnings: list[str] = []

    for interface in status.interfaces:
        if not interface.configured:
            continue

        state = interface.operstate.upper()

        if state == "MISSING":
            errors.append(
                f"{interface.name} is missing"
            )
            continue

        if state == "DOWN":
            errors.append(
                f"{interface.name} is down"
            )
            continue

        if not interface.addresses:
            warnings.append(
                f"{interface.name} has no IPv4 address"
            )

    details = {
        "interfaces": interfaces,
        "errors": errors,
        "warnings": warnings,
    }

    if errors:
        return DashboardComponent(
            status="error",
            message="Network has failed interfaces",
            details=details,
        )

    if warnings:
        return DashboardComponent(
            status="warning",
            message="Network is partially operational",
            details=details,
        )

    return DashboardComponent(
        status="ok",
        message="Network interfaces are operational",
        details=details,
    )



def _l3_vpn_operational_component(
    runtime_path: Path,
) -> DashboardComponent:
    """Build L3 VPN health from vpn-runtime.json."""

    payload, error = _read_json(runtime_path)

    if error:
        return DashboardComponent(
            status="unknown",
            message="VPN runtime unavailable",
            details={"error": error},
        )

    active_interface = payload.get("active_interface")
    tunnels = payload.get("tunnels", [])

    if not isinstance(tunnels, list):
        return DashboardComponent(
            status="error",
            message="VPN runtime is invalid",
            details={},
        )

    if not active_interface:
        return DashboardComponent(
            status="warning",
            message="No active VPN tunnel",
            details={
                "active_interface": None,
                "tunnels": tunnels,
            },
        )

    active = next(
        (
            tunnel
            for tunnel in tunnels
            if isinstance(tunnel, dict)
            and tunnel.get("interface") == active_interface
        ),
        None,
    )

    if active is None:
        return DashboardComponent(
            status="error",
            message=(
                f"Active VPN interface {active_interface} "
                "is missing from runtime"
            ),
            details={
                "active_interface": active_interface,
                "tunnels": tunnels,
            },
        )

    tunnel_status = active.get("status")

    details = {
        "active_name": active.get("name"),
        "active_interface": active_interface,
        "handshake_age_seconds": active.get(
            "handshake_age_seconds"
        ),
        "probe_ok": active.get("probe_ok"),
        "latency_ms": active.get("latency_ms"),
        "rx_bytes": active.get("rx_bytes"),
        "tx_bytes": active.get("tx_bytes"),
        "reason": active.get("reason"),
        "tunnels": tunnels,
    }

    if tunnel_status == "healthy":
        return DashboardComponent(
            status="ok",
            message=(
                f"VPN tunnel "
                f"{active.get('name') or active_interface} "
                "is operational"
            ),
            details=details,
        )

    if tunnel_status in {
        "degraded",
        "unknown",
    }:
        return DashboardComponent(
            status="warning",
            message=(
                active.get("reason")
                or "VPN tunnel requires attention"
            ),
            details=details,
        )

    return DashboardComponent(
        status="error",
        message=(
            active.get("reason")
            or "VPN tunnel is unavailable"
        ),
        details=details,
    )



def _l2_vpn_component(
    config: SecBoxConfig | None,
    l2_handshakes: dict[str, dict[str, object]] | None = None,
) -> DashboardComponent:
    """Inspect configured L2 VPN overlays against live kernel state."""

    if config is None:
        return DashboardComponent(
            status="unknown",
            message="L2 VPN configuration is unavailable",
            details={
                "enabled_tunnels": 0,
                "tunnels": [],
            },
        )

    if (
        config.vpn is None
        or not config.vpn.enabled
    ):
        return DashboardComponent(
            status="ok",
            message="L2 VPN is disabled",
            details={
                "enabled_tunnels": 0,
                "tunnels": [],
            },
        )

    tunnels = [
        tunnel
        for tunnel in config.vpn.l2_tunnels
        if tunnel.enabled
    ]

    if not tunnels:
        return DashboardComponent(
            status="ok",
            message="No enabled L2 VPN tunnels",
            details={
                "enabled_tunnels": 0,
                "tunnels": [],
            },
        )

    result_tunnels: list[dict[str, Any]] = []

    has_error = False
    has_warning = False

    for tunnel in tunnels:
        tunnel_errors: list[str] = []
        tunnel_warnings: list[str] = []

        interfaces: dict[str, Any] = {}

        expected_interfaces = {
            "transport": tunnel.transport.interface,
            "bridge": tunnel.bridge.interface,
            "gretap": tunnel.encapsulation.interface,
        }

        for role, interface in expected_interfaces.items():
            exists, state = _link_state(
                interface
            )

            interfaces[role] = state

            if exists is False:
                tunnel_errors.append(
                    f"{role} interface "
                    f"{interface} is missing"
                )
                continue

            if exists is None:
                tunnel_warnings.append(
                    f"{role} interface "
                    f"{interface} state is unavailable"
                )
                continue

            if not state.get("admin_up", False):
                tunnel_errors.append(
                    f"{role} interface "
                    f"{interface} is administratively down"
                )

        for port in tunnel.bridge.ports:
            exists, state = _link_state(
                port
            )

            interfaces[
                f"access:{port}"
            ] = state

            if exists is False:
                tunnel_errors.append(
                    f"access port {port} is missing"
                )
            elif exists is None:
                tunnel_warnings.append(
                    f"access port {port} state is unavailable"
                )

        members, members_error = _bridge_members(
            tunnel.bridge.interface
        )

        expected_members = {
            tunnel.encapsulation.interface,
            *tunnel.bridge.ports,
        }

        if members is None:
            tunnel_warnings.append(
                "bridge membership cannot be read: "
                f"{members_error}"
            )
        else:
            missing_members = (
                expected_members - members
            )

            if missing_members:
                tunnel_errors.append(
                    "bridge is missing members: "
                    + ", ".join(
                        sorted(missing_members)
                    )
                )

        handshake = (
            l2_handshakes.get(
                tunnel.transport.interface
            )
            if l2_handshakes is not None
            else None
        )

        handshake_age: float | None = None
        handshake_error: str | None = None

        if handshake is None:
            handshake_error = (
                "privileged L2 VPN health is unavailable"
            )
        else:
            raw_age = handshake.get(
                "handshake_age_seconds"
            )
            raw_error = handshake.get("error")

            if isinstance(raw_age, (int, float)):
                handshake_age = float(raw_age)

            if isinstance(raw_error, str) and raw_error:
                handshake_error = raw_error

        if handshake_age is None:
            tunnel_warnings.append(
                handshake_error
                or "WireGuard handshake unavailable"
            )
        elif handshake_age > 180:
            tunnel_warnings.append(
                "WireGuard handshake is stale "
                f"({int(handshake_age)}s)"
            )

        if tunnel_errors:
            status = "error"
            has_error = True
        elif tunnel_warnings:
            status = "warning"
            has_warning = True
        else:
            status = "ok"

        result_tunnels.append(
            {
                "name": tunnel.name,
                "status": status,
                "transport_interface": (
                    tunnel.transport.interface
                ),
                "gretap_interface": (
                    tunnel.encapsulation.interface
                ),
                "bridge_interface": (
                    tunnel.bridge.interface
                ),
                "access_ports": list(
                    tunnel.bridge.ports
                ),
                "bridge_members": (
                    sorted(members)
                    if members is not None
                    else None
                ),
                "handshake_age_seconds": (
                    handshake_age
                ),
                "interfaces": interfaces,
                "errors": tunnel_errors,
                "warnings": tunnel_warnings,
            }
        )

    if has_error:
        return DashboardComponent(
            status="error",
            message="L2 VPN runtime has failed components",
            details={
                "enabled_tunnels": len(tunnels),
                "tunnels": result_tunnels,
            },
        )

    if has_warning:
        return DashboardComponent(
            status="warning",
            message="L2 VPN runtime requires attention",
            details={
                "enabled_tunnels": len(tunnels),
                "tunnels": result_tunnels,
            },
        )

    return DashboardComponent(
        status="ok",
        message="L2 VPN overlays are operational",
        details={
            "enabled_tunnels": len(tunnels),
            "tunnels": result_tunnels,
        },
    )


def _content_filter_component(
    config: SecBoxConfig | None,
    services: dict[str, ServiceStatus],
    doh_feed: dict[str, object] | None = None,
) -> DashboardComponent:
    """Evaluate configured content filtering and required services."""

    if config is None:
        return DashboardComponent(
            status="unknown",
            message="Content Filter configuration is unavailable",
            details={
                "enabled": None,
            },
        )

    if (
        config.content_filter is None
        or not config.content_filter.enabled
    ):
        return DashboardComponent(
            status="ok",
            message="Content Filter is disabled",
            details={
                "enabled": False,
            },
        )

    content_filter = config.content_filter

    details: dict[str, Any] = {
        "enabled": True,
        "dns_enabled": content_filter.dns.enabled,
        "listen_interface": (
            content_filter.dns.listen_interface
        ),
        "listen_address": str(
            content_filter.dns.listen_address
        ),
        "blocked_domains": len(
            content_filter.policy.blocked_domains
        ),
        "allowed_domains": len(
            content_filter.policy.allowed_domains
        ),
        "block_dot": (
            content_filter.encrypted_dns.block_dot
        ),
        "block_doq": (
            content_filter.encrypted_dns.block_doq
        ),
        "doh_enabled": (
            content_filter.encrypted_dns.doh.enabled
        ),
        "managed_doh_feed": (
            content_filter.encrypted_dns.doh.managed_feed_enabled
        ),
    }

    try:
        validate_content_filter_config(
            config
        )
    except ContentFilterValidationError as error:
        details["validation_error"] = str(
            error
        )

        return DashboardComponent(
            status="error",
            message="Content Filter configuration is invalid",
            details=details,
        )

    firewall = services.get(
        "secbox-firewall.service"
    )

    if (
        firewall is None
        or firewall.error
        or firewall.load_state != "loaded"
        or firewall.active_state != "active"
    ):
        return DashboardComponent(
            status="error",
            message=(
                "Content Filter firewall dependency "
                "is not active"
            ),
            details=details,
        )

    if content_filter.dns.enabled:
        dnsmasq = services.get(
            "dnsmasq.service"
        )

        if (
            dnsmasq is None
            or dnsmasq.error
            or dnsmasq.load_state != "loaded"
            or dnsmasq.active_state != "active"
        ):
            return DashboardComponent(
                status="error",
                message=(
                    "Content Filter DNS service "
                    "is not active"
                ),
                details=details,
            )

    doh = content_filter.encrypted_dns.doh

    if doh.enabled and doh.managed_feed_enabled:
        if doh_feed is None:
            return DashboardComponent(
                status="warning",
                message="Managed DoH feed state is unavailable",
                details=details,
            )

        feed_error = doh_feed.get("error")
        address_count = doh_feed.get(
            "address_count"
        )
        updated_at = doh_feed.get(
            "updated_at"
        )

        details["managed_doh_addresses"] = (
            address_count
        )
        details["managed_doh_updated_at"] = (
            updated_at
        )

        if isinstance(feed_error, str) and feed_error:
            details["managed_doh_error"] = feed_error

            return DashboardComponent(
                status="warning",
                message="Managed DoH feed state is unavailable",
                details=details,
            )

        if not isinstance(address_count, int):
            return DashboardComponent(
                status="warning",
                message="Managed DoH feed state is invalid",
                details=details,
            )

        if address_count < doh.managed_feed_min_addresses:
            return DashboardComponent(
                status="error",
                message="Managed DoH feed has too few addresses",
                details=details,
            )

    return DashboardComponent(
        status="ok",
        message="Content Filter is operational",
        details=details,
    )



def _interface_state(name: str) -> dict[str, Any]:
    """Read one interface state from sysfs."""

    root = Path("/sys/class/net") / name

    if not root.exists():
        return {
            "exists": False,
            "operstate": None,
        }

    try:
        operstate = (
            root / "operstate"
        ).read_text(
            encoding="utf-8"
        ).strip()
    except OSError:
        operstate = "unknown"

    return {
        "exists": True,
        "operstate": operstate,
    }


def _bridge_has_member(
    bridge: str,
    interface: str,
) -> bool:
    return (
        Path("/sys/class/net")
        / bridge
        / "brif"
        / interface
    ).exists()


def _wireguard_handshake_age(
    interface: str,
) -> tuple[int | None, str | None]:
    wg = shutil.which("wg")

    if wg is None:
        return None, "wg command is not available"

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
        return None, str(error)

    if result.returncode != 0:
        return None, (
            result.stderr.strip()
            or f"wg exited with {result.returncode}"
        )

    timestamps: list[int] = []

    for line in result.stdout.splitlines():
        fields = line.split()

        if len(fields) < 2:
            continue

        try:
            timestamps.append(
                int(fields[-1])
            )
        except ValueError:
            continue

    if not timestamps or max(timestamps) <= 0:
        return None, "no WireGuard handshake"

    return (
        max(0, int(time.time()) - max(timestamps)),
        None,
    )



def _blacklist_component(
    store: BlacklistStore | None = None,
) -> DashboardComponent:
    store = store or BlacklistStore()

    try:
        entries = store.load()
    except BlacklistStoreError as error:
        return DashboardComponent(
            status="unknown",
            message="Blacklist state unavailable",
            details={
                "error": str(error),
            },
        )

    active = 0
    permanent = 0
    now = datetime.now(UTC)

    for entry in entries:
        expires_at = getattr(
            entry,
            "expires_at",
            None,
        )

        if expires_at is None:
            permanent += 1
            active += 1
            continue

        if (
            expires_at.tzinfo is None
        ):
            expires_at = expires_at.replace(
                tzinfo=UTC
            )

        if expires_at > now:
            active += 1

    return DashboardComponent(
        status="ok",
        message=(
            f"{active} active blacklist "
            f"{'entry' if active == 1 else 'entries'}"
        ),
        details={
            "stored_entries": len(entries),
            "active_entries": active,
            "permanent_entries": permanent,
        },
    )


def _overall_status(
    components: dict[str, DashboardComponent],
) -> DashboardSeverity:
    states = {
        component.status
        for component in components.values()
    }

    if "error" in states:
        return "error"

    if "warning" in states:
        return "warning"

    if "unknown" in states:
        return "warning"

    return "ok"


def build_dashboard(
    *,
    vpn_runtime_path: Path = VPN_RUNTIME_PATH,
    network_runtime_path: Path = NETWORK_RUNTIME_PATH,
    blacklist_store: BlacklistStore | None = None,
    config: SecBoxConfig | None = None,
    l2_handshakes: dict[str, dict[str, object]] | None = None,
    doh_feed: dict[str, object] | None = None,
) -> DashboardResponse:
    """Build the read-only operational dashboard."""

    services_list = service_statuses()
    services = _service_map(
        services_list
    )

    components = {
        "system": _system_component(),
        "network": _network_operational_component(
            network_runtime_path,
        ),
        "vpn": _l3_vpn_operational_component(
            vpn_runtime_path,
        ),
        "l2_vpn": _l2_vpn_component(
            config,
            l2_handshakes,
        ),
        "dhcp": _service_component(
            services,
            "dnsmasq.service",
            label="DHCP",
        ),
        "firewall": _service_component(
            services,
            "secbox-firewall.service",
            label="Firewall",
        ),
        "ids": _service_component(
            services,
            "secbox-ids.service",
            label="IDS",
        ),
        "suricata": _service_component(
            services,
            "suricata.service",
            label="Suricata",
        ),
        "blacklist": _blacklist_component(
            blacklist_store
        ),
        "content_filter": _content_filter_component(
            config,
            services,
            doh_feed,
        ),
    }

    summary = DashboardSummary()

    for component in components.values():
        setattr(
            summary,
            component.status,
            getattr(
                summary,
                component.status,
            )
            + 1,
        )

    return DashboardResponse(
        status=_overall_status(
            components
        ),
        updated_at=datetime.now(UTC),
        summary=summary,
        components=components,
    )
