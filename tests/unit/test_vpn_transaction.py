from pathlib import Path

import pytest

import secbox.core.transactions.vpn as transaction
from secbox.core.config_store import ConfigStore
from secbox.core.models import SecBoxConfig
from secbox.modules.vpn.models import VpnConfig
from secbox.modules.vpn.service import VpnApplyResult


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
                    "private_key_file": f"/etc/secbox/vpn/{interface}.key",
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


def successful_result(
    interface: str,
    name: str,
) -> VpnApplyResult:
    return VpnApplyResult(
        applied_tunnels=1,
        active_name=name,
        active_interface=interface,
    )


def test_successful_transaction_commits_new_vpn(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store, _ = make_store(tmp_path)

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

    monkeypatch.setattr(
        transaction,
        "apply_vpn_config",
        lambda config, **kwargs: successful_result(
            config.vpn.tunnels[0].interface,
            config.vpn.tunnels[0].name,
        ),
    )

    result = transaction.apply_vpn_transaction(
        store,
        new_vpn,
    )

    loaded = store.load()

    assert loaded.vpn == new_vpn
    assert result.config.vpn == new_vpn
    assert result.apply_result.active_interface == "wg1"
    assert store.backup_path.exists()


def test_failed_apply_restores_old_config_and_runtime(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store, old_vpn = make_store(tmp_path)

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

    applied: list[str] = []

    def fake_apply(config, **kwargs):
        interface = config.vpn.tunnels[0].interface
        applied.append(interface)

        if interface == "wg1":
            raise RuntimeError(
                "simulated apply failure"
            )

        return successful_result(
            interface,
            config.vpn.tunnels[0].name,
        )

    monkeypatch.setattr(
        transaction,
        "apply_vpn_config",
        fake_apply,
    )

    with pytest.raises(
        transaction.VpnTransactionError,
        match="simulated apply failure",
    ):
        transaction.apply_vpn_transaction(
            store,
            new_vpn,
        )

    loaded = store.load()

    assert loaded.vpn == old_vpn
    assert applied == ["wg1", "wg0"]


def test_validation_failure_does_not_change_config(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store, old_vpn = make_store(tmp_path)

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


def test_failed_rollback_is_reported(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store, _ = make_store(tmp_path)

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

    monkeypatch.setattr(
        transaction,
        "apply_vpn_config",
        lambda config, **kwargs: (
            (_ for _ in ()).throw(
                RuntimeError("apply exploded")
            )
        ),
    )

    monkeypatch.setattr(
        store,
        "rollback",
        lambda: (
            (_ for _ in ()).throw(
                RuntimeError("rollback exploded")
            )
        ),
    )

    with pytest.raises(
        transaction.VpnTransactionError,
        match="configuration rollback failed",
    ):
        transaction.apply_vpn_transaction(
            store,
            new_vpn,
        )
