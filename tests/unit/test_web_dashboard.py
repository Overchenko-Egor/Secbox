"""Tests for the SecBox operational dashboard."""

import json
from pathlib import Path
from unittest.mock import patch

from secbox.modules.blacklist.store import BlacklistStore
from secbox.modules.network.state import (
    NetworkAddress,
    NetworkInterfaceState,
)
from secbox.web.dashboard import (
    DashboardComponent,
    _overall_status,
    build_dashboard,
)
from secbox.web.monitoring import (
    ServiceStatus,
    SystemStatus,
)

from datetime import UTC, datetime
from secbox.core.models import SecBoxConfig


def services(
    *,
    dnsmasq: str = "active",
    firewall: str = "active",
    ids: str = "active",
    suricata: str = "active",
) -> list[ServiceStatus]:
    def make(
        name: str,
        state: str,
    ) -> ServiceStatus:
        return ServiceStatus(
            name=name,
            load_state="loaded",
            active_state=state,
            sub_state=(
                "running"
                if state == "active"
                else "dead"
            ),
        )

    return [
        make(
            "systemd-networkd.service",
            "active",
        ),
        make(
            "dnsmasq.service",
            dnsmasq,
        ),
        make(
            "secbox-firewall.service",
            firewall,
        ),
        make(
            "suricata.service",
            suricata,
        ),
        make(
            "secbox-ids.service",
            ids,
        ),
        make(
            "secbox-vpn.service",
            "active",
        ),
    ]


def fake_system() -> SystemStatus:
    return SystemStatus(
        observed_at=datetime.now(UTC),
        hostname="secbox-test",
        kernel="test",
        uptime_seconds=123.0,
        load_average=[
            0.1,
            0.2,
            0.3,
        ],
        memory_total_bytes=1024,
        memory_available_bytes=512,
    )


def test_dashboard_healthy(
    tmp_path: Path,
) -> None:
    vpn = tmp_path / "vpn.json"
    network = tmp_path / "network.json"

    vpn.write_text(
        json.dumps(
            {
                "observed_at": "2026-10-12T14:53:48Z",
                "active_interface": "wg0",
                "reason": "Active VPN tunnel remains unchanged",
                "tunnels": [
                    {
                        "name": "primary",
                        "interface": "wg0",
                        "status": "healthy",
                        "peer_present": True,
                        "handshake_age_seconds": 10.0,
                        "rx_bytes": 1000,
                        "tx_bytes": 2000,
                        "probe_ok": True,
                        "latency_ms": 1.2,
                        "reason": "VPN tunnel is healthy",
                    },
                    {
                        "name": "backup",
                        "interface": "wg1",
                        "status": "healthy",
                        "peer_present": True,
                        "handshake_age_seconds": 12.0,
                        "rx_bytes": 900,
                        "tx_bytes": 1800,
                        "probe_ok": True,
                        "latency_ms": 1.5,
                        "reason": "VPN tunnel is healthy",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    network.write_text(
        json.dumps(
            {
                "interfaces": [
                    {
                        "name": "ens38",
                        "role": "mgmt",
                        "ipv4_method": "static",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    store = BlacklistStore(
        tmp_path / "blacklist.json"
    )
    store.save([])

    with (
        patch(
            "secbox.web.dashboard.service_statuses",
            return_value=services(),
        ),
        patch(
            "secbox.web.dashboard.system_status",
            return_value=fake_system(),
        ),
        patch(
            "secbox.web.dashboard.discover_interfaces",
            return_value=[
                NetworkInterfaceState(
                    name="ens38",
                    mac="00:11:22:33:44:55",
                    mtu=1500,
                    operstate="UP",
                    flags=["BROADCAST", "UP", "LOWER_UP"],
                    addresses=[
                        NetworkAddress(
                            family="inet",
                            address="192.168.100.2",
                            prefixlen=24,
                            scope="global",
                        )
                    ],
                    is_loopback=False,
                )
            ],
        ),
    ):
        result = build_dashboard(
            vpn_runtime_path=vpn,
            network_runtime_path=network,
            blacklist_store=store,
            config=SecBoxConfig(),
        )

    assert result.status == "ok"
    assert result.summary.error == 0
    assert result.summary.warning == 0
    assert result.summary.unknown == 0

    assert result.components["vpn"].status == "ok"
    assert result.components["network"].status == "ok"

    assert (
        result.components["vpn"].details[
            "active_interface"
        ]
        == "wg0"
    )

    assert (
        result.components["vpn"].details[
            "probe_ok"
        ]
        is True
    )

    assert (
        result.components["blacklist"].details[
            "active_entries"
        ]
        == 0
    )



def test_dashboard_missing_runtime_is_warning(
    tmp_path: Path,
) -> None:
    store = BlacklistStore(
        tmp_path / "blacklist.json"
    )
    store.save([])

    with (
        patch(
            "secbox.web.dashboard.service_statuses",
            return_value=services(),
        ),
        patch(
            "secbox.web.dashboard.system_status",
            return_value=fake_system(),
        ),
    ):
        result = build_dashboard(
            vpn_runtime_path=tmp_path / "missing-vpn.json",
            network_runtime_path=tmp_path / "missing-network.json",
            blacklist_store=store,
            config=SecBoxConfig(),
        )

    assert result.status == "warning"

    assert (
        result.components["vpn"].status
        == "unknown"
    )

    assert (
        result.components["network"].status
        == "unknown"
    )

    assert result.summary.unknown == 2


def test_dashboard_inactive_service_is_error(
    tmp_path: Path,
) -> None:
    vpn = tmp_path / "vpn.json"
    network = tmp_path / "network.json"

    vpn.write_text(
        "{}",
        encoding="utf-8",
    )

    network.write_text(
        "{}",
        encoding="utf-8",
    )

    store = BlacklistStore(
        tmp_path / "blacklist.json"
    )
    store.save([])

    with (
        patch(
            "secbox.web.dashboard.service_statuses",
            return_value=services(
                dnsmasq="inactive",
            ),
        ),
        patch(
            "secbox.web.dashboard.system_status",
            return_value=fake_system(),
        ),
    ):
        result = build_dashboard(
            vpn_runtime_path=vpn,
            network_runtime_path=network,
            blacklist_store=store,
        )

    assert result.status == "error"

    assert (
        result.components["dhcp"].status
        == "error"
    )


def test_overall_status_priority() -> None:
    assert (
        _overall_status(
            {
                "a": DashboardComponent(
                    status="ok",
                    message="ok",
                ),
            }
        )
        == "ok"
    )

    assert (
        _overall_status(
            {
                "a": DashboardComponent(
                    status="unknown",
                    message="unknown",
                ),
            }
        )
        == "warning"
    )

    assert (
        _overall_status(
            {
                "a": DashboardComponent(
                    status="warning",
                    message="warning",
                ),
                "b": DashboardComponent(
                    status="error",
                    message="error",
                ),
            }
        )
        == "error"
    )


def test_dashboard_disabled_l2_and_content_filter_are_ok(
    tmp_path: Path,
) -> None:
    """Disabled optional subsystems must not make Dashboard unhealthy."""

    vpn = tmp_path / "vpn.json"
    network = tmp_path / "network.json"

    vpn.write_text(
        "{}",
        encoding="utf-8",
    )

    network.write_text(
        "{}",
        encoding="utf-8",
    )

    store = BlacklistStore(
        tmp_path / "blacklist.json"
    )
    store.save([])

    from secbox.core.models import SecBoxConfig

    config = SecBoxConfig()

    with (
        patch(
            "secbox.web.dashboard.service_statuses",
            return_value=services(),
        ),
        patch(
            "secbox.web.dashboard.system_status",
            return_value=fake_system(),
        ),
    ):
        result = build_dashboard(
            vpn_runtime_path=vpn,
            network_runtime_path=network,
            blacklist_store=store,
            config=config,
        )

    assert (
        result.components["l2_vpn"].status
        == "ok"
    )
    assert (
        result.components["content_filter"].status
        == "ok"
    )
    assert (
        result.components["l2_vpn"].details[
            "enabled_tunnels"
        ]
        == 0
    )
    assert (
        result.components["content_filter"].details[
            "enabled"
        ]
        is False
    )



def test_dashboard_optional_components_disabled_are_ok(
    tmp_path: Path,
) -> None:
    from secbox.core.models import SecBoxConfig

    vpn = tmp_path / "vpn.json"
    network = tmp_path / "network.json"

    vpn.write_text("{}", encoding="utf-8")
    network.write_text("{}", encoding="utf-8")

    store = BlacklistStore(
        tmp_path / "blacklist.json"
    )
    store.save([])

    config = SecBoxConfig()

    with (
        patch(
            "secbox.web.dashboard.service_statuses",
            return_value=services(),
        ),
        patch(
            "secbox.web.dashboard.system_status",
            return_value=fake_system(),
        ),
    ):
        result = build_dashboard(
            vpn_runtime_path=vpn,
            network_runtime_path=network,
            blacklist_store=store,
            config=config,
        )

    assert result.components["l2_vpn"].status == "ok"
    assert (
        result.components["content_filter"].status
        == "ok"
    )
