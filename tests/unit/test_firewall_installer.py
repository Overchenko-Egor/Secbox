from pathlib import Path

from secbox.modules.firewall.installer import (
    install_firewall_config,
    restore_firewall_backup,
)


def test_install_firewall_config(tmp_path: Path) -> None:
    source = tmp_path / "source.nft"
    target = tmp_path / "target.nft"
    backup = tmp_path / "backup.nft"

    source.write_text("new config", encoding="utf-8")

    install_firewall_config(
        source_file=source,
        target_file=target,
        backup_file=backup,
    )

    assert target.read_text(encoding="utf-8") == "new config"


def test_existing_firewall_is_backed_up(tmp_path: Path) -> None:
    source = tmp_path / "source.nft"
    target = tmp_path / "target.nft"
    backup = tmp_path / "backup.nft"

    source.write_text("new", encoding="utf-8")
    target.write_text("old", encoding="utf-8")

    install_firewall_config(
        source_file=source,
        target_file=target,
        backup_file=backup,
    )

    assert backup.read_text(encoding="utf-8") == "old"


def test_restore_firewall_backup(tmp_path: Path) -> None:
    target = tmp_path / "target.nft"
    backup = tmp_path / "backup.nft"

    target.write_text("broken", encoding="utf-8")
    backup.write_text("working", encoding="utf-8")

    restore_firewall_backup(
        target_file=target,
        backup_file=backup,
    )

    assert target.read_text(encoding="utf-8") == "working"
