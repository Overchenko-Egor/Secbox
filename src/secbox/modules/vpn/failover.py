"""Runtime VPN failover management."""

import subprocess

from secbox.modules.vpn.models import WireGuardTunnelConfig
from secbox.modules.vpn.routing import ACTIVE_TABLE




class VpnFailoverError(RuntimeError):
    """Raised when active VPN routing cannot be changed."""


def _run_ip(*args: str, check: bool = True):
    try:
        return subprocess.run(
            ["/usr/sbin/ip", *args],
            check=check,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as error:
        message = error.stderr.strip() or error.stdout.strip()
        raise VpnFailoverError(message) from error


def activate_tunnel(
    tunnel: WireGuardTunnelConfig,
) -> None:
    """Route VPN-managed LAN traffic through tunnel."""

    _run_ip(
        "route",
        "replace",
        "default",
        "dev",
        tunnel.interface,
        "table",
        str(ACTIVE_TABLE),
    )


def get_active_interface() -> str | None:
    """Return interface currently selected in active table."""

    result = _run_ip(
        "route",
        "show",
        "table",
        str(ACTIVE_TABLE),
    )

    for line in result.stdout.splitlines():
        fields = line.split()

        if not fields or fields[0] != "default":
            continue

        if "dev" not in fields:
            continue

        index = fields.index("dev")

        if index + 1 < len(fields):
            return fields[index + 1]

    return None
