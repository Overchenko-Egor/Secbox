from datetime import UTC, datetime

import pytest

from secbox.modules.vpn.controller import ControllerResult
from secbox.modules.vpn.health import (
    VpnHealthStatus,
    VpnTunnelHealth,
)
from secbox.modules.vpn.runtime import (
    VpnEventStore,
    VpnRuntimeStore,
    runtime_from_result,
    switch_event_from_result,
)


NOW = datetime(
    2026,
    9,
    14,
    12,
    0,
    tzinfo=UTC,
)


def health(interface: str) -> VpnTunnelHealth:
    return VpnTunnelHealth(
        name=interface,
        interface=interface,
        status=VpnHealthStatus.HEALTHY,
        peer_present=True,
        handshake_age_seconds=10,
        rx_bytes=100,
        tx_bytes=200,
        probe_ok=True,
        latency_ms=1.5,
        reason="healthy",
    )


def result(*, switched: bool) -> ControllerResult:
    return ControllerResult(
        active_before="wg0",
        active_after=(
            "wg1"
            if switched
            else "wg0"
        ),
        switched=switched,
        reason="test reason",
        health={
            "wg0": health("wg0"),
            "wg1": health("wg1"),
        },
    )


def test_runtime_store_round_trip(tmp_path):
    path = tmp_path / "runtime.json"
    store = VpnRuntimeStore(path)

    state = runtime_from_result(
        result(switched=False),
        observed_at=NOW,
    )

    store.save(state)

    loaded = store.load()

    assert loaded is not None
    assert loaded.observed_at == NOW
    assert loaded.active_interface == "wg0"
    assert len(loaded.tunnels) == 2
    assert loaded.tunnels[0].interface == "wg0"


def test_runtime_store_missing_returns_none(tmp_path):
    store = VpnRuntimeStore(
        tmp_path / "missing.json"
    )

    assert store.load() is None


def test_event_store_returns_newest_first(tmp_path):
    store = VpnEventStore(
        tmp_path / "events.jsonl"
    )

    first = switch_event_from_result(
        result(switched=True),
        occurred_at=NOW,
    )

    second_result = ControllerResult(
        active_before="wg1",
        active_after="wg0",
        switched=True,
        reason="failback",
        health={},
    )

    second = switch_event_from_result(
        second_result,
        occurred_at=NOW,
    )

    store.append(first)
    store.append(second)

    events = store.load_recent()

    assert len(events) == 2
    assert events[0].from_interface == "wg1"
    assert events[0].to_interface == "wg0"
    assert events[1].from_interface == "wg0"
    assert events[1].to_interface == "wg1"


def test_event_store_rejects_invalid_limit(tmp_path):
    store = VpnEventStore(
        tmp_path / "events.jsonl"
    )

    with pytest.raises(ValueError):
        store.load_recent(0)


def test_switch_event_requires_real_switch():
    with pytest.raises(ValueError):
        switch_event_from_result(
            result(switched=False),
            occurred_at=NOW,
        )
