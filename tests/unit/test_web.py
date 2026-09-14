"""HTTP boundary tests: authentication, preview isolation and failure states."""

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from pytest import MonkeyPatch

from secbox.core.config_store import ConfigStore
from secbox.core.models import SecBoxConfig
from secbox.modules.network.discovery import NetworkDiscoveryError
from secbox.modules.network.state import NetworkInterfaceState
from secbox.modules.vpn.runtime import (
    VpnEventStore,
    VpnRuntimeError,
    VpnRuntimeState,
    VpnRuntimeStore,
    VpnSwitchEvent,
)
from secbox.web.app import MAX_BODY_BYTES, create_app
from secbox.web.settings import WebSettings

PASSWORD = "test-password-for-secbox-web"


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    path = tmp_path / "config.yml"
    ConfigStore(path).save(SecBoxConfig())
    return path


@pytest.fixture
def client(config_path: Path, monkeypatch: MonkeyPatch) -> Iterator[TestClient]:
    interfaces = [NetworkInterfaceState(
        name=name, mtu=1500, operstate="UP", flags=["UP"], addresses=[], is_loopback=False,
    ) for name in ["wan0", "lan0", "mgmt0"]]
    monkeypatch.setattr("secbox.web.app.discover_interfaces", lambda: interfaces)
    monkeypatch.setattr("secbox.web.app.discover_ipv4_routes", lambda: [])
    monkeypatch.setattr("secbox.web.app.service_statuses", lambda: [])
    with TestClient(create_app(WebSettings(config_path, PASSWORD)), base_url="http://localhost") as session:
        session.auth = ("admin", PASSWORD)
        yield session


@pytest.mark.parametrize("path", [
    "/", "/assets/app.js", "/assets/style.css", "/api/v1/config", "/api/v1/config/export",
    "/api/v1/network/interfaces", "/api/v1/network/routes", "/api/v1/services",
    "/api/v1/system", "/api/v1/vpn/status", "/api/v1/vpn/events",
    "/api/v1/openapi.json",
])
def test_endpoints_require_auth(client: TestClient, path: str) -> None:
    response = client.get(path, auth=None)
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Basic")
    assert response.headers["cache-control"] == "no-store"


def test_wrong_credentials_and_public_health(client: TestClient) -> None:
    assert client.get("/api/v1/config", auth=("admin", "wrong")).status_code == 401
    assert client.get("/api/v1/config", auth=("wrong", PASSWORD)).status_code == 401
    assert client.get("/healthz", auth=None).json() == {"status": "ok"}
    assert client.post("/api/v1/config/preview", json={}, auth=None).status_code == 401


def test_config_export_roundtrip(client: TestClient, config_path: Path) -> None:
    config = client.get("/api/v1/config").json()
    exported = client.get("/api/v1/config/export")
    assert exported.status_code == 200
    assert yaml.safe_load(exported.text) == config
    assert "attachment" in exported.headers["content-disposition"]
    assert ConfigStore(config_path).load().model_dump(mode="json") == config


def test_missing_invalid_and_unreadable_config(
    client: TestClient, config_path: Path, monkeypatch: MonkeyPatch,
) -> None:
    config_path.unlink()
    assert client.get("/api/v1/config").status_code == 404
    config_path.write_text("schema_version: 22\n", encoding="utf-8")
    assert client.get("/api/v1/config").status_code == 409
    from secbox.core.config_store import ConfigStoreError

    def fail_load(self: ConfigStore) -> SecBoxConfig:
        raise ConfigStoreError("private filesystem detail")

    monkeypatch.setattr(ConfigStore, "load", fail_load)
    response = client.get("/api/v1/config")
    assert response.status_code == 503
    assert "private filesystem detail" not in response.text


def candidate_config() -> dict[str, object]:
    return {
        "network": {"interfaces": [
            {"name": "wan0", "role": "wan", "ipv4_method": "dhcp"},
            {"name": "lan0", "role": "lan", "ipv4_method": "static", "ipv4_address": "192.168.50.1/24"},
            {"name": "mgmt0", "role": "mgmt", "ipv4_method": "dhcp"},
        ]},
        "dhcp": [{
            "enabled": True, "interface": "lan0", "network": "192.168.50.0/24",
            "range_start": "192.168.50.100", "range_end": "192.168.50.150",
            "gateway": "192.168.50.1", "dns_servers": ["192.168.50.1"], "lease_time": "12h",
        }],
        "firewall": {"wan_interface": "wan0", "lan_interface": "lan0", "management_interface": "mgmt0"},
    }


def test_preview_renders_all_modules_without_saving_or_running_commands(
    client: TestClient, config_path: Path, monkeypatch: MonkeyPatch,
) -> None:
    import subprocess

    before = config_path.read_bytes()

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("Preview must not execute system commands after interface discovery")

    monkeypatch.setattr(subprocess, "run", forbidden)
    result = client.post("/api/v1/config/preview", json=candidate_config())
    assert result.status_code == 200, result.text
    preview = result.json()
    assert preview["applied"] is False
    assert "Address=192.168.50.1/24" in preview["files"]["networkd/10-secbox-lan0.network"]
    assert "dhcp-range=" in preview["files"]["dnsmasq.conf"]
    assert "masquerade" in preview["files"]["nftables.conf"]
    assert config_path.read_bytes() == before
    assert not config_path.with_suffix(".yml.bak").exists()


@pytest.mark.parametrize("candidate", [
    {"unknown": True},
    {"system": {"hostname": "bad hostname"}},
    {"network": {"interfaces": [{"name": "missing0", "role": "wan", "ipv4_method": "dhcp"}]}},
    {"network": {"interfaces": [{"name": "mgmt0", "role": "mgmt", "ipv4_method": "disabled"}]}},
    {"network": {"interfaces": [
        {"name": "lan0", "role": "lan", "ipv4_method": "static", "ipv4_address": "10.0.0.1/24"},
        {"name": "mgmt0", "role": "mgmt", "ipv4_method": "static", "ipv4_address": "10.0.0.2/24"},
    ]}},
    {"firewall": {"wan_interface": "wan0", "lan_interface": "lan0", "management_interface": "mgmt0"}},
])
def test_preview_rejects_invalid_candidates(client: TestClient, candidate: dict[str, object]) -> None:
    response = client.post("/api/v1/config/preview", json=candidate)
    assert response.status_code == 422, response.text


def test_preview_checks_dhcp_relationship(client: TestClient) -> None:
    candidate = candidate_config()
    candidate["dhcp"] = [{
        "enabled": True, "interface": "wan0", "network": "10.0.0.0/24",
        "range_start": "10.0.0.10", "range_end": "10.0.0.20", "gateway": "10.0.0.1",
    }]
    assert client.post("/api/v1/config/preview", json=candidate).status_code == 422


def test_discovery_failure_is_not_reported_as_empty_or_valid(client: TestClient, monkeypatch: MonkeyPatch) -> None:
    def fail() -> list[NetworkInterfaceState]:
        raise NetworkDiscoveryError("ip command failed")

    monkeypatch.setattr("secbox.web.app.discover_interfaces", fail)
    assert client.get("/api/v1/network/interfaces").status_code == 503
    assert client.post("/api/v1/config/preview", json={}).status_code == 503


def test_body_limit_including_chunked_requests(client: TestClient) -> None:
    def chunks() -> Iterator[bytes]:
        yield b" " * MAX_BODY_BYTES
        yield b"{}"

    response = client.post("/api/v1/config/preview", content=chunks(), headers={"Content-Type": "application/json"})
    assert response.status_code == 413


def test_no_config_mutation_endpoint_and_no_unprotected_docs(client: TestClient) -> None:
    assert client.put("/api/v1/config", json={}).status_code == 405
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/healthz", headers={"Host": "attacker.example"}).status_code == 400


def test_panel_assets_and_api_schema(client: TestClient) -> None:
    assert "SecBox" in client.get("/").text
    for path in ["/assets/app.js", "/assets/style.css"]:
        response = client.get(path)
        assert response.status_code == 200
        assert response.headers["x-content-type-options"] == "nosniff"
    schema = client.get("/api/v1/openapi.json").json()
    assert "post" in schema["paths"]["/api/v1/config/preview"]
    assert schema["paths"]["/api/v1/config"]["get"]["security"]


def test_settings_reject_missing_or_ambiguous_password(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("SECBOX_WEB_PASSWORD", raising=False)
    monkeypatch.delenv("SECBOX_WEB_PASSWORD_FILE", raising=False)
    with pytest.raises(ValueError, match="set SECBOX"):
        WebSettings.from_environment()
    path = tmp_path / "password"
    path.write_text(PASSWORD + "\n")
    monkeypatch.setenv("SECBOX_WEB_PASSWORD_FILE", str(path))
    assert WebSettings.from_environment().password == PASSWORD
    assert PASSWORD not in repr(WebSettings.from_environment())
    monkeypatch.setenv("SECBOX_WEB_PASSWORD", PASSWORD)
    with pytest.raises(ValueError, match="only one"):
        WebSettings.from_environment()
    with pytest.raises(ValueError, match="at least 16"):
        WebSettings(tmp_path / "config", "11111")


def test_vpn_status_returns_runtime_snapshot(
    client: TestClient,
    monkeypatch: MonkeyPatch,
) -> None:
    observed_at = datetime(
        2026,
        9,
        14,
        12,
        0,
        tzinfo=UTC,
    )

    state = VpnRuntimeState(
        observed_at=observed_at,
        active_interface="wg0",
        reason="Active VPN tunnel remains unchanged",
        tunnels=[],
    )

    monkeypatch.setattr(
        VpnRuntimeStore,
        "load",
        lambda self: state,
    )

    response = client.get(
        "/api/v1/vpn/status"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["active_interface"] == "wg0"
    assert data["reason"] == (
        "Active VPN tunnel remains unchanged"
    )
    assert data["tunnels"] == []
    assert data["observed_at"].startswith(
        "2026-09-14T12:00:00"
    )


def test_vpn_status_missing_returns_404(
    client: TestClient,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        VpnRuntimeStore,
        "load",
        lambda self: None,
    )

    response = client.get(
        "/api/v1/vpn/status"
    )

    assert response.status_code == 404
    assert "not available yet" in response.text


def test_vpn_status_read_failure_returns_503(
    client: TestClient,
    monkeypatch: MonkeyPatch,
) -> None:
    def fail(self):
        raise VpnRuntimeError(
            "private filesystem detail"
        )

    monkeypatch.setattr(
        VpnRuntimeStore,
        "load",
        fail,
    )

    response = client.get(
        "/api/v1/vpn/status"
    )

    assert response.status_code == 503
    assert "private filesystem detail" not in response.text


def test_vpn_events_returns_newest_events(
    client: TestClient,
    monkeypatch: MonkeyPatch,
) -> None:
    event = VpnSwitchEvent(
        occurred_at=datetime(
            2026,
            9,
            14,
            12,
            5,
            tzinfo=UTC,
        ),
        from_interface="wg0",
        to_interface="wg1",
        reason="primary failed",
    )

    observed_limits = []

    def fake_load_recent(self, limit=50):
        observed_limits.append(limit)
        return [event]

    monkeypatch.setattr(
        VpnEventStore,
        "load_recent",
        fake_load_recent,
    )

    response = client.get(
        "/api/v1/vpn/events?limit=25"
    )

    assert response.status_code == 200
    assert observed_limits == [25]

    data = response.json()

    assert len(data) == 1
    assert data[0]["from_interface"] == "wg0"
    assert data[0]["to_interface"] == "wg1"
    assert data[0]["reason"] == "primary failed"


def test_vpn_events_empty_history(
    client: TestClient,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        VpnEventStore,
        "load_recent",
        lambda self, limit=50: [],
    )

    response = client.get(
        "/api/v1/vpn/events"
    )

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.parametrize(
    "limit",
    [0, 501],
)
def test_vpn_events_rejects_invalid_limit(
    client: TestClient,
    limit: int,
) -> None:
    response = client.get(
        f"/api/v1/vpn/events?limit={limit}"
    )

    assert response.status_code == 422


def test_vpn_events_read_failure_returns_503(
    client: TestClient,
    monkeypatch: MonkeyPatch,
) -> None:
    def fail(self, limit=50):
        raise VpnRuntimeError(
            "private event filesystem detail"
        )

    monkeypatch.setattr(
        VpnEventStore,
        "load_recent",
        fail,
    )

    response = client.get(
        "/api/v1/vpn/events"
    )

    assert response.status_code == 503
    assert (
        "private event filesystem detail"
        not in response.text
    )


def test_panel_contains_vpn_dashboard(client: TestClient) -> None:
    html = client.get("/").text
    javascript = client.get("/assets/app.js").text

    assert 'id="vpn"' in html
    assert 'id="vpn-active"' in html
    assert 'id="vpn-tunnels"' in html
    assert 'id="vpn-events"' in html

    assert 'api("vpn/status")' not in javascript
    assert '"vpn/status"' in javascript
    assert '"vpn/events?limit=10"' in javascript
    assert "drawVpnStatus" in javascript
    assert "drawVpnEvents" in javascript
