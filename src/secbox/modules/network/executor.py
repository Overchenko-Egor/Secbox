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
import time

from secbox.modules.network.discovery import (
    NetworkDiscoveryError,
    discover_manageable_interfaces,
)
from secbox.modules.network.verifier import (
    NetworkVerificationError,
    verify_network_config,
)
from secbox.modules.network.routes import (
    RouteDiscoveryError,
    discover_ipv4_routes,
)


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
            if interface.role == "l2":
                continue

            run_command(
                [
                    "networkctl",
                    "reconfigure",
                    interface.name,
                ]
            )

        verify_applied_config(config)

    except NetworkApplyError:
        restore_networkd_backup(
            target_dir=target_dir,
            backup_dir=backup_dir,
        )

        try:
            run_command(["networkctl", "reload"])

            for interface in config.interfaces:
                if interface.role == "l2":
                    continue

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


def verify_applied_config(
    config: NetworkConfig,
    attempts: int = 10,
    delay_seconds: float = 1.0,
) -> None:
    """Wait for runtime network state to match desired configuration."""

    last_error: Exception | None = None

    for _ in range(attempts):
        try:
            runtime_interfaces = discover_manageable_interfaces()
            runtime_routes = discover_ipv4_routes()

            verify_network_config(
                config,
                runtime_interfaces,
                runtime_routes,
            )

            return

        except (
            NetworkDiscoveryError,
            RouteDiscoveryError,
            NetworkVerificationError,
        ) as error:
            last_error = error
            time.sleep(delay_seconds)

    raise NetworkApplyError(
        f"post-apply verification failed: {last_error}"
    )
