"""Installation and backup of SecBox systemd-networkd files."""

import shutil
from pathlib import Path


class NetworkInstallError(Exception):
    """Raised when networkd configuration installation fails."""


SECBOX_FILE_PATTERN = "*-secbox-*.network"


def install_networkd_files(
    source_dir: Path,
    target_dir: Path,
    backup_dir: Path,
) -> list[Path]:
    """Install rendered SecBox networkd files with backup."""

    source_files = sorted(
        source_dir.glob(SECBOX_FILE_PATTERN)
    )

    if not source_files:
        raise NetworkInstallError(
            f"no SecBox network files found in {source_dir}"
        )

    target_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    backup_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    _clear_directory(backup_dir)

    for existing_file in target_dir.glob(SECBOX_FILE_PATTERN):
        shutil.copy2(
            existing_file,
            backup_dir / existing_file.name,
        )

    installed: list[Path] = []

    try:
        for existing_file in target_dir.glob(SECBOX_FILE_PATTERN):
            existing_file.unlink()

        for source_file in source_files:
            destination = target_dir / source_file.name

            shutil.copy2(
                source_file,
                destination,
            )
            destination.chmod(0o644)

            installed.append(destination)

    except OSError as error:
        raise NetworkInstallError(
            f"failed to install network configuration: {error}"
        ) from error

    return installed


def restore_networkd_backup(
    target_dir: Path,
    backup_dir: Path,
) -> list[Path]:
    """Restore the previous SecBox networkd configuration."""

    target_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    for current_file in target_dir.glob(SECBOX_FILE_PATTERN):
        current_file.unlink()

    restored: list[Path] = []

    if not backup_dir.exists():
        return restored

    for backup_file in sorted(
        backup_dir.glob(SECBOX_FILE_PATTERN)
    ):
        destination = target_dir / backup_file.name

        shutil.copy2(
            backup_file,
            destination,
        )
        destination.chmod(0o644)

        restored.append(destination)

    return restored


def _clear_directory(directory: Path) -> None:
    """Remove files from a SecBox-controlled backup directory."""

    for path in directory.iterdir():
        if path.is_file():
            path.unlink()
