"""Install and restore SecBox dnsmasq configuration."""

import shutil
from pathlib import Path


class DhcpInstallError(Exception):
    """Raised when DHCP configuration installation fails."""


def install_dnsmasq_config(
    source_file: Path,
    target_file: Path,
    backup_file: Path,
) -> None:
    """Install rendered dnsmasq configuration with backup."""

    if not source_file.exists():
        raise DhcpInstallError(
            f"rendered DHCP configuration does not exist: {source_file}"
        )

    target_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    backup_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    try:
        if target_file.exists():
            shutil.copy2(
                target_file,
                backup_file,
            )

        shutil.copy2(
            source_file,
            target_file,
        )

    except OSError as error:
        raise DhcpInstallError(
            f"failed to install DHCP configuration: {error}"
        ) from error


def restore_dnsmasq_backup(
    target_file: Path,
    backup_file: Path,
) -> None:
    """Restore previous dnsmasq configuration."""

    try:
        if backup_file.exists():
            shutil.copy2(
                backup_file,
                target_file,
            )
        elif target_file.exists():
            target_file.unlink()

    except OSError as error:
        raise DhcpInstallError(
            f"failed to restore DHCP configuration: {error}"
        ) from error
