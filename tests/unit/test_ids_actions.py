"""Tests for privileged IDS actions."""

import json

from pathlib import Path

import pytest

from secbox.actions import ids as ids_actions
from secbox.core.config_store import ConfigStore
from secbox.core.models import SecBoxConfig
from secbox.modules.firewall.models import FirewallConfig
from secbox.modules.ids.config import IdsConfig


def make_store(
    tmp_path: Path,
    *,
    ids: IdsConfig | None = None,
) -> ConfigStore:
    store = ConfigStore(
        tmp_path / "config.yml"
    )

    config = SecBoxConfig(
        ids=ids or IdsConfig(),
        firewall=FirewallConfig(
            wan_interface="wan0",
            lan_interface="lan0",
            management_interface="mgmt0",
            dynamic_blacklist_enabled=True,
        ),
    )

    store.save(config)

    return store


def test_get_ids_returns_model(
    tmp_path: Path,
) -> None:
    store = make_store(
        tmp_path
    )

    ids = ids_actions.get_ids_action(
        store=store
    )

    assert ids.enabled is True
    assert (
        ids.nat_correlation_window_ms
        == 10
    )


def test_runtime_parser_is_bounded_and_sanitized(
    tmp_path: Path,
    monkeypatch,
) -> None:
    eve = tmp_path / "eve.json"

    events = [
        {
            "timestamp":
                "2026-10-17T10:00:00+00:00",
            "event_type": "alert",
            "in_iface": "ens33",
            "src_ip": "203.0.113.5",
            "src_port": 50000,
            "dest_ip": "192.168.1.63",
            "dest_port": 443,
            "proto": "TCP",
            "payload": "MUST_NOT_LEAK",
            "alert": {
                "action": "allowed",
                "signature_id": 12345,
                "signature": "TEST ALERT",
                "category": "Test",
                "severity": 1,
            },
        },
        {
            "timestamp":
                "2026-10-17T10:00:01+00:00",
            "event_type": "stats",
            "stats": {
                "capture": {
                    "kernel_packets": 1000,
                    "kernel_drops": 2,
                    "errors": 0,
                },
                "detect": {
                    "alert": 10,
                    "alerts_suppressed": 20,
                    "engines": [
                        {
                            "rules_loaded": 50000,
                            "rules_failed": 0,
                            "rules_skipped": 0,
                            "last_reload":
                                "2026-10-17T09:00:00+00:00",
                        }
                    ],
                },
            },
        },
    ]

    eve.write_text(
        "\n".join(
            json.dumps(event)
            for event in events
        )
        + "\n",
        encoding="utf-8",
    )

    store = make_store(
        tmp_path,
        ids=IdsConfig(
            eve_path=eve
        ),
    )

    monkeypatch.setattr(
        ids_actions,
        "_service_state",
        lambda unit: {
            "unit": unit,
            "available": True,
            "active_state": "active",
            "sub_state": "running",
        },
    )

    runtime = (
        ids_actions
        .get_ids_runtime_action(
            store=store
        )
    )

    assert (
        runtime["sampled_alert_count"]
        == 1
    )

    assert (
        runtime["stats"]["rules_loaded"]
        == 50000
    )

    assert (
        runtime["stats"]["kernel_drop_percent"]
        == 0.2
    )

    alert = runtime[
        "recent_alerts"
    ][0]

    assert (
        alert["signature"]
        == "TEST ALERT"
    )

    assert "payload" not in alert


def test_automatic_blackhole_requires_dynamic_blacklist(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = ConfigStore(
        tmp_path / "config.yml"
    )

    config = SecBoxConfig(
        ids=IdsConfig.model_validate(
            {
                "automatic_blackhole": {
                    "enabled": False,
                    "timeout": "15m",
                }
            }
        ),
        firewall=FirewallConfig(
            wan_interface="wan0",
            lan_interface="lan0",
            management_interface="mgmt0",
            dynamic_blacklist_enabled=False,
        ),
    )

    store.save(config)

    candidate = config.ids.model_copy(
        update={
            "automatic_blackhole":
                config.ids
                .automatic_blackhole
                .model_copy(
                    update={
                        "enabled": True
                    }
                )
        }
    )

    with pytest.raises(
        ids_actions.IdsActionError,
        match="dynamic blacklist",
    ):
        ids_actions.validate_ids_action(
            candidate,
            store=store,
        )


def make_blackhole_config(
    tmp_path: Path,
    *,
    automatic_enabled: bool = True,
    dynamic_blacklist_enabled: bool = True,
) -> ConfigStore:
    store = ConfigStore(
        tmp_path / "blackhole-config.yml"
    )

    config = SecBoxConfig.model_validate(
        {
            "ids": {
                "enabled": True,
                "policy": {
                    "minimum_alert_count": 2,
                    "minimum_block_count": 5,
                    "maximum_alert_severity": 2,
                    "maximum_block_severity": 1,
                },
                "automatic_blackhole": {
                    "enabled":
                        automatic_enabled,
                    "timeout": "15m",
                },
            },
            "firewall": {
                "enabled": True,
                "wan_interface": "wan0",
                "lan_interface": "lan0",
                "management_interface":
                    "mgmt0",
                "dynamic_blacklist_enabled":
                    dynamic_blacklist_enabled,
                "dynamic_blacklist_protected_networks": [
                    "192.168.100.0/24"
                ],
            },
        }
    )

    store.save(config)

    return store


def test_ids_blackhole_uses_root_config_and_runtime_protection(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from secbox.modules.network.state import (
        NetworkAddress,
        NetworkInterfaceState,
    )

    store = make_blackhole_config(
        tmp_path
    )

    interfaces = [
        NetworkInterfaceState(
            name="wan0",
            mac=None,
            mtu=1500,
            operstate="UP",
            flags=["UP"],
            addresses=[
                NetworkAddress(
                    family="inet",
                    address="192.168.1.63",
                    prefixlen=24,
                    scope="global",
                )
            ],
            is_loopback=False,
        ),
        NetworkInterfaceState(
            name="lan0",
            mac=None,
            mtu=1500,
            operstate="UP",
            flags=["UP"],
            addresses=[
                NetworkAddress(
                    family="inet",
                    address="192.168.50.1",
                    prefixlen=24,
                    scope="global",
                )
            ],
            is_loopback=False,
        ),
        NetworkInterfaceState(
            name="mgmt0",
            mac=None,
            mtu=1500,
            operstate="UP",
            flags=["UP"],
            addresses=[
                NetworkAddress(
                    family="inet",
                    address="192.168.100.2",
                    prefixlen=24,
                    scope="global",
                )
            ],
            is_loopback=False,
        ),
    ]

    observed = {}

    monkeypatch.setattr(
        "secbox.modules.network.discovery.discover_interfaces",
        lambda: interfaces,
    )

    def fake_add(
        **kwargs,
    ) -> None:
        observed.update(kwargs)

    monkeypatch.setattr(
        "secbox.modules.blacklist.service.add_blacklist_entry",
        fake_add,
    )

    result = (
        ids_actions
        .add_ids_blackhole_action(
            address="203.0.113.50",
            signature_id=100001,
            severity=1,
            count=5,
            store=store,
        )
    )

    assert (
        result["address"]
        == "203.0.113.50"
    )

    assert result["timeout"] == "15m"
    assert result["source"] == "ids"

    assert (
        observed["timeout"]
        == "15m"
    )

    assert (
        observed["source"]
        == "ids"
    )

    protected = set(
        observed[
            "protected_networks"
        ]
    )

    assert (
        "192.168.100.0/24"
        in protected
    )

    assert (
        "192.168.1.63/32"
        in protected
    )

    assert (
        "192.168.50.1/32"
        in protected
    )

    assert (
        "192.168.100.2/32"
        in protected
    )


def test_ids_blackhole_rejects_policy_bypass(
    tmp_path: Path,
) -> None:
    store = make_blackhole_config(
        tmp_path
    )

    with pytest.raises(
        ids_actions.IdsActionError,
        match="severity",
    ):
        (
            ids_actions
            .add_ids_blackhole_action(
                address="203.0.113.50",
                signature_id=100001,
                severity=2,
                count=5,
                store=store,
            )
        )

    with pytest.raises(
        ids_actions.IdsActionError,
        match="count",
    ):
        (
            ids_actions
            .add_ids_blackhole_action(
                address="203.0.113.50",
                signature_id=100001,
                severity=1,
                count=4,
                store=store,
            )
        )


def test_ids_blackhole_rejects_disabled_automatic_response(
    tmp_path: Path,
) -> None:
    store = make_blackhole_config(
        tmp_path,
        automatic_enabled=False,
    )

    with pytest.raises(
        ids_actions.IdsActionError,
        match="disabled",
    ):
        (
            ids_actions
            .add_ids_blackhole_action(
                address="203.0.113.50",
                signature_id=100001,
                severity=1,
                count=5,
                store=store,
            )
        )


def test_ids_blackhole_rejects_disabled_dynamic_blacklist(
    tmp_path: Path,
) -> None:
    store = make_blackhole_config(
        tmp_path,
        dynamic_blacklist_enabled=False,
    )

    with pytest.raises(
        ids_actions.IdsActionError,
        match="dynamic blacklist",
    ):
        (
            ids_actions
            .add_ids_blackhole_action(
                address="203.0.113.50",
                signature_id=100001,
                severity=1,
                count=5,
                store=store,
            )
        )


def test_ids_deception_rolls_back_source_when_reconcile_fails(
    monkeypatch,
) -> None:
    from secbox.actions import deception as deception_actions
    from secbox.modules.deception import runtime as deception_runtime
    from secbox.modules.deception import steering

    calls = []

    ids = IdsConfig.model_validate(
        {
            "enabled": True,
            "policy": {
                "minimum_alert_count": 2,
                "minimum_block_count": 5,
                "maximum_alert_severity": 2,
                "maximum_block_severity": 1,
            },
            "automatic_blackhole": {
                "enabled": False,
                "timeout": "15m",
            },
            "automatic_deception": {
                "enabled": True,
            },
        }
    )

    monkeypatch.setattr(
        ids_actions,
        "get_ids_action",
        lambda: ids,
    )

    monkeypatch.setattr(
        steering,
        "source_is_active",
        lambda source_ip: False,
    )

    from contextlib import contextmanager

    @contextmanager
    def fake_source_operation_lock(
        source_ip,
    ):
        yield source_ip

    monkeypatch.setattr(
        steering,
        "source_operation_lock",
        fake_source_operation_lock,
    )

    monkeypatch.setattr(
        deception_actions,
        "start_observe_case_action",
        lambda **kwargs: {
            "case_id": "case-test-rollback",
            "source_ip": kwargs["source_ip"],
        },
    )

    def fake_add_source(
        *,
        source_ip,
        case_id,
    ):
        calls.append(
            (
                "add",
                source_ip,
                case_id,
            )
        )
        return True

    def fake_remove_source(
        *,
        source_ip,
        case_id,
    ):
        calls.append(
            (
                "remove",
                source_ip,
                case_id,
            )
        )
        return True

    reconcile_calls = 0

    def fake_reconcile():
        nonlocal reconcile_calls

        reconcile_calls += 1
        calls.append(
            (
                "reconcile",
                reconcile_calls,
            )
        )

        if reconcile_calls == 1:
            raise RuntimeError(
                "simulated reconcile failure"
            )

        return {
            "source_count": 0,
        }

    def fake_stop(
        *,
        case_id,
    ):
        calls.append(
            (
                "stop",
                case_id,
            )
        )

        return {
            "case_id": case_id,
            "status": "stopped",
        }

    monkeypatch.setattr(
        steering,
        "add_source",
        fake_add_source,
    )

    monkeypatch.setattr(
        steering,
        "remove_source",
        fake_remove_source,
    )

    monkeypatch.setattr(
        deception_runtime,
        "reconcile",
        fake_reconcile,
    )

    monkeypatch.setattr(
        deception_actions,
        "stop_observe_case_action",
        fake_stop,
    )

    with pytest.raises(
        ids_actions.IdsActionError,
        match="failed to activate deception quarantine",
    ):
        ids_actions.add_ids_deception_action(
            address="198.18.0.3",
            signature_id=900001,
            severity=1,
            count=5,
        )

    assert (
        "add",
        "198.18.0.3",
        "case-test-rollback",
    ) in calls

    assert (
        "remove",
        "198.18.0.3",
        "case-test-rollback",
    ) in calls

    assert (
        "stop",
        "case-test-rollback",
    ) in calls

    assert reconcile_calls == 2
