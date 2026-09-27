from pathlib import Path

from secbox.modules.network.installer import (
    install_networkd_files,
    restore_networkd_backup,
)


def _mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def test_installed_network_files_are_world_readable(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    backup = tmp_path / "backup"

    source.mkdir()

    network_file = source / "10-secbox-ens33.network"
    network_file.write_text(
        "[Match]\nName=ens33\n",
        encoding="utf-8",
    )

    # Имитируем строгий umask privileged worker.
    network_file.chmod(0o600)

    installed = install_networkd_files(
        source_dir=source,
        target_dir=target,
        backup_dir=backup,
    )

    assert len(installed) == 1
    assert _mode(installed[0]) == 0o644


def test_restored_network_files_are_world_readable(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    backup = tmp_path / "backup"

    target.mkdir()
    backup.mkdir()

    current = target / "10-secbox-ens33.network"
    current.write_text(
        "broken\n",
        encoding="utf-8",
    )

    saved = backup / "10-secbox-ens33.network"
    saved.write_text(
        "[Match]\nName=ens33\n",
        encoding="utf-8",
    )
    saved.chmod(0o600)

    restored = restore_networkd_backup(
        target_dir=target,
        backup_dir=backup,
    )

    assert len(restored) == 1
    assert _mode(restored[0]) == 0o644
