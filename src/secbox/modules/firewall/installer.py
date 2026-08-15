"""Install and restore SecBox nftables configuration."""

import shutil
from pathlib import Path


class FirewallInstallError(Exception):
    """Raised when firewall configuration installation fails."""


def install_firewall_config(
    source_file: Path,
    target_file: Path,
    backup_file: Path,
) -> None:
    """Install rendered nftables configuration with backup."""

    if not source_file.exists():
        raise FirewallInstallError(
            f"rendered firewall configuration does not exist: {source_file}"
        )

    target_file.parent.mkdir(parents=True, exist_ok=True)
    backup_file.parent.mkdir(parents=True, exist_ok=True)

    try:
        if target_file.exists():
            shutil.copy2(target_file, backup_file)

        shutil.copy2(source_file, target_file)

    except OSError as error:
        raise FirewallInstallError(
            f"failed to install firewall configuration: {error}"
        ) from error


def restore_firewall_backup(
    target_file: Path,
    backup_file: Path,
) -> None:
    """Restore previous nftables configuration."""

    try:
        if backup_file.exists():
            shutil.copy2(backup_file, target_file)
        elif target_file.exists():
            target_file.unlink()

    except OSError as error:
        raise FirewallInstallError(
            f"failed to restore firewall configuration: {error}"
        ) from error
