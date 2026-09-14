import subprocess
from pathlib import Path

from pytest import MonkeyPatch

from secbox.web.monitoring import SERVICE_UNITS, service_statuses, system_status


def test_proc_metrics_and_missing_proc(tmp_path: Path) -> None:
    (tmp_path / "uptime").write_text("120.5 80.0\n")
    (tmp_path / "meminfo").write_text("MemTotal: 2048 kB\nMemAvailable: 1024 kB\n")
    metrics = system_status(tmp_path)
    assert metrics.uptime_seconds == 120.5
    assert metrics.memory_total_bytes == 2048 * 1024
    assert metrics.memory_available_bytes == 1024 * 1024
    assert system_status(tmp_path / "missing").uptime_seconds is None


def test_service_states_distinguish_missing_and_inactive(monkeypatch: MonkeyPatch) -> None:
    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert kwargs["timeout"] == 5
        assert command[-len(SERVICE_UNITS):] == list(SERVICE_UNITS)
        return subprocess.CompletedProcess(command, 0, stdout=(
            "Id=systemd-networkd.service\nLoadState=loaded\nActiveState=active\nSubState=running\n\n"
            "Id=dnsmasq.service\nLoadState=not-found\nActiveState=inactive\nSubState=dead\n\n"
            "Id=nftables.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\n"
        ))

    monkeypatch.setattr(subprocess, "run", fake_run)
    statuses = service_statuses()
    assert statuses[0].active_state == "active"
    assert statuses[1].load_state == "not-found"
    assert statuses[2].load_state == "loaded"
    assert statuses[2].active_state == "inactive"
    assert statuses[3].error is not None


def test_systemd_timeout_yields_unknown(monkeypatch: MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired("systemctl", 5)

    monkeypatch.setattr(subprocess, "run", fail)
    assert all(item.active_state == "unknown" and item.error for item in service_statuses())


def test_vpn_service_is_monitored() -> None:
    assert "secbox-vpn.service" in SERVICE_UNITS
