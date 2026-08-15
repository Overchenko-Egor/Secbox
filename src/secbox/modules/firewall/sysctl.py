"""Kernel forwarding configuration for SecBox."""

import subprocess


SYSCTL_BIN = "/usr/sbin/sysctl"


class ForwardingError(Exception):
    """Raised when IPv4 forwarding cannot be configured."""


def set_ipv4_forwarding(enabled: bool) -> None:
    """Enable or disable kernel IPv4 forwarding."""

    value = "1" if enabled else "0"

    try:
        subprocess.run(
            [
                SYSCTL_BIN,
                "-w",
                f"net.ipv4.ip_forward={value}",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ForwardingError(
            f"failed to configure IPv4 forwarding: {error}"
        ) from error
