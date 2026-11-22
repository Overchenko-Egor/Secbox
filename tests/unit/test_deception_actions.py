from types import SimpleNamespace

import ipaddress

import pytest

from secbox.actions import deception


def test_reason_rejects_control_chars():
    with pytest.raises(
        deception.DeceptionActionError
    ):
        deception._sanitize_reason(
            "bad\nreason"
        )


def test_protected_source_rejected(
    monkeypatch,
):
    config = SimpleNamespace()

    monkeypatch.setattr(
        deception,
        "discover_interfaces",
        lambda: [],
    )

    monkeypatch.setattr(
        deception,
        "build_protected_networks",
        lambda config, interfaces: (
            ipaddress.ip_network(
                "192.168.100.0/24"
            ),
        ),
    )

    with pytest.raises(
        deception.DeceptionActionError,
        match="protected",
    ):
        deception._validate_source(
            source_ip="192.168.100.2",
            config=config,
        )


def test_external_source_allowed(
    monkeypatch,
):
    config = SimpleNamespace()

    monkeypatch.setattr(
        deception,
        "discover_interfaces",
        lambda: [],
    )

    monkeypatch.setattr(
        deception,
        "build_protected_networks",
        lambda config, interfaces: (
            ipaddress.ip_network(
                "192.168.100.0/24"
            ),
        ),
    )

    result = (
        deception._validate_source(
            source_ip="203.0.113.10",
            config=config,
        )
    )

    assert result == (
        "203.0.113.10"
    )


def test_release_quarantine_success(
    monkeypatch,
):
    from contextlib import contextmanager

    from secbox.modules.deception import (
        runtime,
        steering,
    )

    case_id = (
        "case-20261025T120000Z-acde1234"
    )

    case = SimpleNamespace(
        case_id=case_id,
        source_ip="198.18.0.60",
        status="observing",
    )

    class FakeStore:
        def load(
            self,
            requested,
        ):
            assert requested == case_id
            return case

        def append_timeline(
            self,
            requested,
            event,
        ):
            assert requested == case_id

    state = {
        "version": 1,
        "sources": {
            "198.18.0.60": {
                "cases": [
                    case_id
                ]
            }
        },
    }

    calls = []

    monkeypatch.setattr(
        steering,
        "load_state",
        lambda: state,
    )

    monkeypatch.setattr(
        steering,
        "remove_source",
        lambda **kwargs: (
            calls.append("remove")
            or True
        ),
    )

    monkeypatch.setattr(
        steering,
        "add_source",
        lambda **kwargs: (
            calls.append("add")
            or True
        ),
    )

    @contextmanager
    def fake_lock(source_ip):
        assert source_ip == (
            "198.18.0.60"
        )

        yield source_ip

    monkeypatch.setattr(
        steering,
        "source_operation_lock",
        fake_lock,
    )

    monkeypatch.setattr(
        runtime,
        "reconcile",
        lambda: (
            calls.append("reconcile")
            or {
                "source_count": 0,
            }
        ),
    )

    monkeypatch.setattr(
        deception,
        "stop_observe_case_action",
        lambda **kwargs: (
            calls.append("stop")
            or {
                "status": "stopped",
            }
        ),
    )

    result = (
        deception
        .release_deception_quarantine_action(
            case_id=case_id,
            case_store=FakeStore(),
        )
    )

    assert result["status"] == "released"

    assert calls == [
        "remove",
        "reconcile",
        "stop",
    ]


def test_release_quarantine_rolls_back(
    monkeypatch,
):
    from contextlib import contextmanager

    from secbox.modules.deception import (
        runtime,
        steering,
    )

    case_id = (
        "case-20261025T120001Z-acde5678"
    )

    case = SimpleNamespace(
        case_id=case_id,
        source_ip="198.18.0.61",
        status="observing",
    )

    class FakeStore:
        def load(
            self,
            requested,
        ):
            return case

    state = {
        "version": 1,
        "sources": {
            "198.18.0.61": {
                "cases": [
                    case_id
                ]
            }
        },
    }

    calls = []

    monkeypatch.setattr(
        steering,
        "load_state",
        lambda: state,
    )

    monkeypatch.setattr(
        steering,
        "remove_source",
        lambda **kwargs: (
            calls.append("remove")
            or True
        ),
    )

    monkeypatch.setattr(
        steering,
        "add_source",
        lambda **kwargs: (
            calls.append("add")
            or True
        ),
    )

    @contextmanager
    def fake_lock(source_ip):
        yield source_ip

    monkeypatch.setattr(
        steering,
        "source_operation_lock",
        fake_lock,
    )

    reconcile_calls = 0

    def fake_reconcile():
        nonlocal reconcile_calls

        reconcile_calls += 1

        calls.append(
            f"reconcile-{reconcile_calls}"
        )

        if reconcile_calls == 1:
            raise RuntimeError(
                "simulated failure"
            )

        return {
            "source_count": 1,
        }

    monkeypatch.setattr(
        runtime,
        "reconcile",
        fake_reconcile,
    )

    with pytest.raises(
        deception.DeceptionActionError,
        match="failed to release",
    ):
        (
            deception
            .release_deception_quarantine_action(
                case_id=case_id,
                case_store=FakeStore(),
            )
        )

    assert calls == [
        "remove",
        "reconcile-1",
        "add",
        "reconcile-2",
    ]
