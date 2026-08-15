"""Apply and verify systemd-networkd configuration."""

import subprocess
from pathlib import Path

from secbox.modules.network.installer import (
    NetworkInstallError,
    install_networkd_files,
    restore_networkd_backup,
)
from secbox.modules.network.models import NetworkConfig
from secbox.modules.network.renderer import render_networkd


class NetworkApplyError(Exception):
    """Raised when applying network configuration fails."""


def run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    """Run a system command and return its result."""

    try:
        return subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise NetworkApplyError(
            f"command failed: {' '.join(command)}: {error}"
        ) from error


def apply_networkd_config(
    config: NetworkConfig,
    staging_dir: Path,
    target_dir: Path,
    backup_dir: Path,
) -> None:
    """Render, install and reconfigure interfaces."""

    ensure_networkd_available()

    render_networkd(
        config=config,
        output_dir=staging_dir,
    )

    try:
        install_networkd_files(
            source_dir=staging_dir,
            target_dir=target_dir,
            backup_dir=backup_dir,
        )
    except NetworkInstallError as error:
        raise NetworkApplyError(str(error)) from error

    try:
        run_command(["networkctl", "reload"])

        for interface in config.interfaces:
            run_command(
                [
                    "networkctl",
                    "reconfigure",
                    interface.name,
                ]
            )

    except NetworkApplyError:
        restore_networkd_backup(
            target_dir=target_dir,
            backup_dir=backup_dir,
        )

        try:
            run_command(["networkctl", "reload"])

            for interface in config.interfaces:
                run_command(
                    [
                        "networkctl",
                        "reconfigure",
                        interface.name,
                    ]
                )
        except NetworkApplyError:
            pass

        raise


def ensure_networkd_available() -> None:
    """Ensure systemd-networkd is running before applying configuration."""

    result = run_command(
        [
            "systemctl",
            "is-active",
            "systemd-networkd",
        ]
    )

    if result.stdout.strip() != "active":
        raise NetworkApplyError(
            "systemd-networkd is not active"
        )
