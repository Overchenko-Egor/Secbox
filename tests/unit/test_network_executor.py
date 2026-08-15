from pathlib import Path

import pytest

from secbox.modules.network.executor import (
    NetworkApplyError,
    apply_networkd_config,
)
from secbox.modules.network.models import (
    NetworkConfig,
    NetworkInterfaceConfig,
)


def test_apply_rejects_inactive_networkd(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens33",
                role="wan",
                ipv4_method="dhcp",
            )
        ]
    )

    def fake_run_command(
        command: list[str],
    ) -> object:
        raise NetworkApplyError(
            f"command failed: {' '.join(command)}"
        )

    monkeypatch.setattr(
        "secbox.modules.network.executor.run_command",
        fake_run_command,
    )

    with pytest.raises(
        NetworkApplyError,
        match="systemctl is-active systemd-networkd",
    ):
        apply_networkd_config(
            config=config,
            staging_dir=tmp_path / "stage",
            target_dir=tmp_path / "network",
            backup_dir=tmp_path / "backup",
        )


def test_apply_calls_reload_and_reconfigure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens33",
                role="wan",
                ipv4_method="dhcp",
            )
        ]
    )

    commands: list[list[str]] = []

    class Result:
        stdout = "active\n"

    def fake_run_command(
        command: list[str],
    ) -> Result:
        commands.append(command)
        return Result()

    monkeypatch.setattr(
        "secbox.modules.network.executor.run_command",
        fake_run_command,
    )

    monkeypatch.setattr(
        "secbox.modules.network.executor.verify_applied_config",
        lambda config: None,
    )

    apply_networkd_config(
        config=config,
        staging_dir=tmp_path / "stage",
        target_dir=tmp_path / "network",
        backup_dir=tmp_path / "backup",
    )

    assert [
        "systemctl",
        "is-active",
        "systemd-networkd",
    ] in commands

    assert [
        "networkctl",
        "reload",
    ] in commands

    assert [
        "networkctl",
        "reconfigure",
        "ens33",
    ] in commands

def test_verification_failure_triggers_rollback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens33",
                role="wan",
                ipv4_method="dhcp",
            )
        ]
    )

    commands: list[list[str]] = []

    class Result:
        stdout = "active\n"

    def fake_run_command(
        command: list[str],
    ) -> Result:
        commands.append(command)
        return Result()

    def failed_verification(
        config: NetworkConfig,
    ) -> None:
        raise NetworkApplyError(
            "post-apply verification failed"
        )

    rollback_called = False

    def fake_restore(
        target_dir: Path,
        backup_dir: Path,
    ) -> list[Path]:
        nonlocal rollback_called
        rollback_called = True
        return []

    monkeypatch.setattr(
        "secbox.modules.network.executor.run_command",
        fake_run_command,
    )

    monkeypatch.setattr(
        "secbox.modules.network.executor.verify_applied_config",
        failed_verification,
    )

    monkeypatch.setattr(
        "secbox.modules.network.executor.restore_networkd_backup",
        fake_restore,
    )

    with pytest.raises(
        NetworkApplyError,
        match="post-apply verification failed",
    ):
        apply_networkd_config(
            config=config,
            staging_dir=tmp_path / "stage",
            target_dir=tmp_path / "network",
            backup_dir=tmp_path / "backup",
        )

    assert rollback_called is True
