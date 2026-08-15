from pathlib import Path

from secbox.modules.dhcp.installer import (
    install_dnsmasq_config,
    restore_dnsmasq_backup,
)


def test_install_dnsmasq_config(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.conf"
    target = tmp_path / "target.conf"
    backup = tmp_path / "backup.conf"

    source.write_text(
        "new config",
        encoding="utf-8",
    )

    install_dnsmasq_config(
        source_file=source,
        target_file=target,
        backup_file=backup,
    )

    assert target.read_text(
        encoding="utf-8",
    ) == "new config"


def test_existing_config_is_backed_up(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.conf"
    target = tmp_path / "target.conf"
    backup = tmp_path / "backup.conf"

    source.write_text(
        "new config",
        encoding="utf-8",
    )

    target.write_text(
        "old config",
        encoding="utf-8",
    )

    install_dnsmasq_config(
        source_file=source,
        target_file=target,
        backup_file=backup,
    )

    assert backup.read_text(
        encoding="utf-8",
    ) == "old config"


def test_restore_backup(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.conf"
    backup = tmp_path / "backup.conf"

    target.write_text(
        "broken config",
        encoding="utf-8",
    )

    backup.write_text(
        "working config",
        encoding="utf-8",
    )

    restore_dnsmasq_backup(
        target_file=target,
        backup_file=backup,
    )

    assert target.read_text(
        encoding="utf-8",
    ) == "working config"
