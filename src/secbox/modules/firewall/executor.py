"""Apply SecBox nftables configuration."""

import subprocess
from pathlib import Path

from secbox.modules.firewall.installer import (
    FirewallInstallError,
    install_firewall_config,
    restore_firewall_backup,
)


NFT_BIN = "/usr/sbin/nft"


class FirewallApplyError(Exception):
    """Raised when firewall configuration cannot be applied."""


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
        raise FirewallApplyError(
            f"command failed: {' '.join(command)}: {error}"
        ) from error


def apply_firewall_config(
    rendered_file: Path,
    target_file: Path,
    backup_file: Path,
) -> None:
    """Validate, install and apply nftables ruleset."""

    run_command(
        [
            NFT_BIN,
            "--check",
            "--file",
            str(rendered_file),
        ]
    )

    try:
        install_firewall_config(
            source_file=rendered_file,
            target_file=target_file,
            backup_file=backup_file,
        )
    except FirewallInstallError as error:
        raise FirewallApplyError(str(error)) from error

    try:
        run_command(
            [
                NFT_BIN,
                "--file",
                str(target_file),
            ]
        )

    except FirewallApplyError:
        try:
            restore_firewall_backup(
                target_file=target_file,
                backup_file=backup_file,
            )

            if target_file.exists():
                run_command(
                    [
                        NFT_BIN,
                        "--file",
                        str(target_file),
                    ]
                )
            else:
                run_command(
                    [
                        NFT_BIN,
                        "flush",
                        "ruleset",
                    ]
                )

        except (
            FirewallInstallError,
            FirewallApplyError,
        ):
            pass

        raise
