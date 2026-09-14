from pathlib import Path

import pytest

import secbox.core.transactions.vpn as transaction
from secbox.core.config_store import ConfigStore
from secbox.core.models import SecBoxConfig
from secbox.modules.vpn.models import VpnConfig
from secbox.modules.vpn.service import (
    VpnTransitionResult,
)


def make_vpn(
    *,
    name: str,
    interface: str,
    table: int,
) -> VpnConfig:
    return VpnConfig.model_validate(
        {
            "enabled": True,
            "tunnels": [
                {
                    "name": name,
                    "interface": interface,
                    "address": "10.200.0.2/30",
                    "private_key_file": (
                        f"/etc/secbox/vpn/{interface}.key"
                    ),
                    "priority": 100,
                    "routing_table": table,
                    "source_networks": [
                        "192.168.50.0/24"
                    ],
                    "peer": {
                        "public_key": f"{name}-peer",
                        "endpoint": "192.0.2.1:51820",
                        "allowed_ips": [
                            "0.0.0.0/0"
                        ],
                    },
                }
            ],
        }
    )


def make_store(
    tmp_path: Path,
) -> tuple[ConfigStore, VpnConfig]:
    store = ConfigStore(
        tmp_path / "config.yml"
    )

    old_vpn = make_vpn(
        name="old",
        interface="wg0",
        table=200,
    )

    store.save(
        SecBoxConfig(
            vpn=old_vpn,
        )
    )

    return store, old_vpn


def result_for(
    config: SecBoxConfig,
) -> VpnTransitionResult:
    tunnels = (
        config.vpn.tunnels
        if config.vpn is not None
        and config.vpn.enabled
        else []
    )

    active = (
        tunnels[0]
        if tunnels
        else None
    )

    return VpnTransitionResult(
        applied_tunnels=len(tunnels),
        removed_tunnels=0,
        active_name=(
            active.name
            if active is not None
            else None
        ),
        active_interface=(
            active.interface
            if active is not None
            else None
        ),
    )


def test_successful_transaction_commits_new_vpn(
    tmp_path: Path,
    monkeypatch,
):
    store, _ = make_store(
        tmp_path
    )

    new_vpn = make_vpn(
        name="new",
        interface="wg1",
        table=201,
    )

    monkeypatch.setattr(
        transaction,
        "validate_vpn_key_paths",
        lambda config: None,
    )

    transitions = []

    def fake_reconcile(
        old,
        new,
        **kwargs,
    ):
        transitions.append(
            (
                old.vpn.tunnels[0].interface,
                new.vpn.tunnels[0].interface,
            )
        )

        return result_for(
            new
        )

    monkeypatch.setattr(
        transaction,
        "reconcile_vpn_config",
        fake_reconcile,
    )

    result = transaction.apply_vpn_transaction(
        store,
        new_vpn,
    )

    assert store.load().vpn == new_vpn
    assert result.config.vpn == new_vpn
    assert result.apply_result.active_interface == "wg1"
    assert transitions == [
        ("wg0", "wg1")
    ]


def test_failed_apply_reconciles_back_to_old_state(
    tmp_path: Path,
    monkeypatch,
):
    store, old_vpn = make_store(
        tmp_path
    )

    new_vpn = make_vpn(
        name="new",
        interface="wg1",
        table=201,
    )

    monkeypatch.setattr(
        transaction,
        "validate_vpn_key_paths",
        lambda config: None,
    )

    transitions = []

    def fake_reconcile(
        old,
        new,
        **kwargs,
    ):
        old_interface = (
            old.vpn.tunnels[0].interface
        )
        new_interface = (
            new.vpn.tunnels[0].interface
        )

        transitions.append(
            (
                old_interface,
                new_interface,
            )
        )

        if (
            old_interface == "wg0"
            and new_interface == "wg1"
        ):
            raise RuntimeError(
                "simulated apply failure"
            )

        return result_for(
            new
        )

    monkeypatch.setattr(
        transaction,
        "reconcile_vpn_config",
        fake_reconcile,
    )

    with pytest.raises(
        transaction.VpnTransactionError,
        match="simulated apply failure",
    ):
        transaction.apply_vpn_transaction(
            store,
            new_vpn,
        )

    assert store.load().vpn == old_vpn

    assert transitions == [
        ("wg0", "wg1"),
        ("wg1", "wg0"),
    ]


def test_validation_failure_does_not_change_config(
    tmp_path: Path,
    monkeypatch,
):
    store, old_vpn = make_store(
        tmp_path
    )

    new_vpn = make_vpn(
        name="new",
        interface="wg1",
        table=201,
    )

    def fail_validation(config):
        raise RuntimeError(
            "invalid key"
        )

    monkeypatch.setattr(
        transaction,
        "validate_vpn_key_paths",
        fail_validation,
    )

    before = store.config_path.read_bytes()

    with pytest.raises(
        transaction.VpnTransactionError,
        match="invalid key",
    ):
        transaction.apply_vpn_transaction(
            store,
            new_vpn,
        )

    assert store.config_path.read_bytes() == before
    assert store.load().vpn == old_vpn
