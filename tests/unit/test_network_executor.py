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
