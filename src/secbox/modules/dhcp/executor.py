"""Apply and verify SecBox DHCP configuration."""

import subprocess
from pathlib import Path

from secbox.modules.dhcp.installer import (
    DhcpInstallError,
    install_dnsmasq_config,
    restore_dnsmasq_backup,
)


class DhcpApplyError(Exception):
    """Raised when DHCP configuration cannot be applied."""


def run_command(
    command: list[str],
) -> subprocess.CompletedProcess[str]:
    """Run a system command."""

    try:
        return subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise DhcpApplyError(
            f"command failed: {' '.join(command)}: {error}"
        ) from error


def apply_dnsmasq_config(
    rendered_file: Path,
    target_file: Path,
    backup_file: Path,
) -> None:
    """Validate, install and restart dnsmasq."""

    run_command(
        [
            "dnsmasq",
            "--test",
            f"--conf-file={rendered_file}",
        ]
    )

    try:
        install_dnsmasq_config(
            source_file=rendered_file,
            target_file=target_file,
            backup_file=backup_file,
        )
    except DhcpInstallError as error:
        raise DhcpApplyError(str(error)) from error

    try:
        run_command(
            [
                "systemctl",
                "restart",
                "dnsmasq",
            ]
        )

        run_command(
            [
                "systemctl",
                "is-active",
                "dnsmasq",
            ]
        )

    except DhcpApplyError:
        try:
            restore_dnsmasq_backup(
                target_file=target_file,
                backup_file=backup_file,
            )

            run_command(
                [
                    "systemctl",
                    "restart",
                    "dnsmasq",
                ]
            )
        except (
            DhcpInstallError,
            DhcpApplyError,
        ):
            pass

        raise
