"""Policy routing helpers for SecBox VPN pool."""

import subprocess

from secbox.modules.vpn.models import WireGuardTunnelConfig


ACTIVE_TABLE = 250
MAIN_RULE_PRIORITY = 99
VPN_RULE_PRIORITY = 100


class VpnRoutingError(RuntimeError):
    """Raised when VPN policy routing cannot be configured."""


def _run_ip(
    *arguments: str,
    check: bool = True,
) -> subprocess.CompletedProcess:
    command = ["/usr/sbin/ip", *arguments]

    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
    )

    if check and result.returncode != 0:
        message = (
            result.stderr.strip()
            or result.stdout.strip()
            or f"exit code {result.returncode}"
        )
        raise VpnRoutingError(
            f"ip command failed: {' '.join(command)}: {message}"
        )

    return result


def configure_tunnel_route(
    tunnel: WireGuardTunnelConfig,
) -> None:
    """Install the tunnel's own routing table."""

    _run_ip(
        "route",
        "replace",
        "default",
        "dev",
        tunnel.interface,
        "table",
        str(tunnel.routing_table),
    )


def configure_pool_policy(
    tunnels: list[WireGuardTunnelConfig],
) -> None:
    """Route VPN-managed source networks through active table."""

    source_networks = {
        str(network)
        for tunnel in tunnels
        if tunnel.enabled
        for network in tunnel.source_networks
    }

    for source in sorted(source_networks):
        _run_ip(
            "rule", "del",
            "from", source,
            "priority", str(MAIN_RULE_PRIORITY),
            "table", "main",
            "suppress_prefixlength", "0",
            check=False,
        )

        _run_ip(
            "rule", "del",
            "from", source,
            "priority", str(VPN_RULE_PRIORITY),
            check=False,
        )

        _run_ip(
            "rule", "add",
            "from", source,
            "priority", str(MAIN_RULE_PRIORITY),
            "table", "main",
            "suppress_prefixlength", "0",
        )

        _run_ip(
            "rule", "add",
            "from", source,
            "priority", str(VPN_RULE_PRIORITY),
            "table", str(ACTIVE_TABLE),
        )


def remove_tunnel_route(
    tunnel: WireGuardTunnelConfig,
) -> None:
    """Remove the tunnel's own routing table."""

    _run_ip(
        "route",
        "flush",
        "table",
        str(tunnel.routing_table),
        check=False,
    )


