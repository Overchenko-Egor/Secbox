from pathlib import Path

import pytest

from secbox.modules.network.installer import (
    NetworkInstallError,
    install_networkd_files,
    restore_networkd_backup,
)


def test_install_networkd_files(tmp_path: Path) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    backup = tmp_path / "backup"

    source.mkdir()

    source_file = source / "10-secbox-ens33.network"
    source_file.write_text(
        "new configuration",
        encoding="utf-8",
    )

    installed = install_networkd_files(
        source,
        target,
        backup,
    )

    assert len(installed) == 1
    assert installed[0].read_text(
        encoding="utf-8"
    ) == "new configuration"


def test_existing_configuration_is_backed_up(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    backup = tmp_path / "backup"

    source.mkdir()
    target.mkdir()

    existing = target / "10-secbox-ens33.network"
    existing.write_text(
        "old configuration",
        encoding="utf-8",
    )

    new_file = source / "10-secbox-ens33.network"
    new_file.write_text(
        "new configuration",
        encoding="utf-8",
    )

    install_networkd_files(
        source,
        target,
        backup,
    )

    backup_file = backup / existing.name

    assert backup_file.read_text(
        encoding="utf-8"
    ) == "old configuration"

    assert existing.read_text(
        encoding="utf-8"
    ) == "new configuration"


def test_restore_networkd_backup(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    backup = tmp_path / "backup"

    target.mkdir()
    backup.mkdir()

    current = target / "10-secbox-ens33.network"
    current.write_text(
        "broken configuration",
        encoding="utf-8",
    )

    previous = backup / "10-secbox-ens33.network"
    previous.write_text(
        "working configuration",
        encoding="utf-8",
    )

    restored = restore_networkd_backup(
        target,
        backup,
    )

    assert len(restored) == 1

    assert current.read_text(
        encoding="utf-8"
    ) == "working configuration"


def test_unrelated_network_files_are_preserved(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    backup = tmp_path / "backup"

    source.mkdir()
    target.mkdir()

    unrelated = target / "20-vendor.network"
    unrelated.write_text(
        "vendor configuration",
        encoding="utf-8",
    )

    secbox_file = source / "10-secbox-ens33.network"
    secbox_file.write_text(
        "secbox configuration",
        encoding="utf-8",
    )

    install_networkd_files(
        source,
        target,
        backup,
    )

    assert unrelated.exists()
    assert unrelated.read_text(
        encoding="utf-8"
    ) == "vendor configuration"


def test_empty_source_is_rejected(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    backup = tmp_path / "backup"

    source.mkdir()

    with pytest.raises(
        NetworkInstallError,
        match="no SecBox network files",
    ):
        install_networkd_files(
            source,
            target,
            backup,
        )
