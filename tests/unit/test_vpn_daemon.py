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
from secbox.modules.vpn.runtime import (
    VpnEventStore,
    VpnRuntimeStore,
)


def make_result(*, switched=False):
    return ControllerResult(
        active_before="wg0",
        active_after="wg1" if switched else "wg0",
        switched=switched,
        reason="test",
        health={},
    )


def make_daemon(
    tmp_path,
    *,
    interval=3.0,
):
    return VpnDaemon(
        VpnConfig(),
        state_path=tmp_path / "controller-state.json",
        interval=interval,
        runtime_store=VpnRuntimeStore(
            tmp_path / "runtime.json"
        ),
        event_store=VpnEventStore(
            tmp_path / "events.jsonl"
        ),
    )


def test_interval_must_be_positive(tmp_path):
    with pytest.raises(ValueError):
        make_daemon(
            tmp_path,
            interval=0,
        )


def test_process_once_updates_stats(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(
        daemon_module,
        "evaluate_once",
        lambda vpn, state_path: make_result(
            switched=True
        ),
    )

    daemon = make_daemon(tmp_path)

    result = daemon.process_once()
    stats = daemon.stats()

    assert result.switched is True
    assert stats.iterations == 1
    assert stats.switches == 1


def test_process_once_publishes_runtime(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(
        daemon_module,
        "evaluate_once",
        lambda vpn, state_path: make_result(
            switched=False
        ),
    )

    daemon = make_daemon(tmp_path)

    daemon.process_once()

    runtime_path = tmp_path / "runtime.json"
    events_path = tmp_path / "events.jsonl"

    assert runtime_path.exists()
    assert not events_path.exists()


def test_switch_appends_event(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(
        daemon_module,
        "evaluate_once",
        lambda vpn, state_path: make_result(
            switched=True
        ),
    )

    daemon = make_daemon(tmp_path)

    daemon.process_once()

    events_path = tmp_path / "events.jsonl"

    assert events_path.exists()

    events = VpnEventStore(
        events_path
    ).load_recent()

    assert len(events) == 1
    assert events[0].from_interface == "wg0"
    assert events[0].to_interface == "wg1"


def test_run_stops_with_event(
    monkeypatch,
    tmp_path,
):
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

    daemon = make_daemon(
        tmp_path,
        interval=0.01,
    )

    daemon.run(stop_event)

    assert len(calls) == 1
    assert daemon.stats().iterations == 1


def test_controller_error_is_wrapped(
    monkeypatch,
    tmp_path,
):
    def fail(vpn, state_path):
        raise RuntimeError("boom")

    monkeypatch.setattr(
        daemon_module,
        "evaluate_once",
        fail,
    )

    daemon = make_daemon(tmp_path)

    with pytest.raises(
        VpnDaemonError,
        match="boom",
    ):
        daemon.process_once()
