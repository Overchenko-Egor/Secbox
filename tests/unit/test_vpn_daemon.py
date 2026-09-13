from pathlib import Path
from threading import Event

import pytest

import secbox.modules.vpn.daemon as daemon_module
from secbox.modules.vpn.controller import ControllerResult
from secbox.modules.vpn.daemon import (
    VpnDaemon,
    VpnDaemonError,
)
from secbox.modules.vpn.models import VpnConfig


def make_result(*, switched=False):
    return ControllerResult(
        active_before="wg0",
        active_after="wg1" if switched else "wg0",
        switched=switched,
        reason="test",
        health={},
    )


def test_interval_must_be_positive():
    with pytest.raises(ValueError):
        VpnDaemon(
            VpnConfig(),
            state_path=Path("/tmp/state"),
            interval=0,
        )


def test_process_once_updates_stats(monkeypatch):
    monkeypatch.setattr(
        daemon_module,
        "evaluate_once",
        lambda vpn, state_path: make_result(
            switched=True
        ),
    )

    daemon = VpnDaemon(
        VpnConfig(),
        state_path=Path("/tmp/state"),
    )

    result = daemon.process_once()
    stats = daemon.stats()

    assert result.switched is True
    assert stats.iterations == 1
    assert stats.switches == 1


def test_run_stops_with_event(monkeypatch):
    stop_event = Event()
    calls = []

    def fake_evaluate(vpn, state_path):
        calls.append(True)
        stop_event.set()
        return make_result()

    monkeypatch.setattr(
        daemon_module,
        "evaluate_once",
        fake_evaluate,
    )

    daemon = VpnDaemon(
        VpnConfig(),
        state_path=Path("/tmp/state"),
        interval=0.01,
    )

    daemon.run(stop_event)

    assert len(calls) == 1
    assert daemon.stats().iterations == 1


def test_controller_error_is_wrapped(monkeypatch):
    def fail(vpn, state_path):
        raise RuntimeError("boom")

    monkeypatch.setattr(
        daemon_module,
        "evaluate_once",
        fail,
    )

    daemon = VpnDaemon(
        VpnConfig(),
        state_path=Path("/tmp/state"),
    )

    with pytest.raises(
        VpnDaemonError,
        match="boom",
    ):
        daemon.process_once()
