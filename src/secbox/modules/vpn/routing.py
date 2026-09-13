"""Policy routing helpers for SecBox VPN tunnels."""

import subprocess

from secbox.modules.vpn.models import WireGuardTunnelConfig


class VpnRoutingError(RuntimeError):
    """Raised when VPN policy routing cannot be configured."""


def _run_ip(
    *arguments: str,
    check: bool = True,
) -> subprocess.CompletedProcess:
    command = [
        "/usr/sbin/ip",
        *arguments,
    ]

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


def configure_policy_routing(
    tunnel: WireGuardTunnelConfig,
) -> None:
    """Install source-based policy routing for one VPN tunnel."""

    table = str(tunnel.routing_table)
    priority = tunnel.priority

    if priority <= 1:
        raise VpnRoutingError(
            "VPN routing priority must be greater than 1"
        )

    main_priority = str(priority - 1)
    vpn_priority = str(priority)

    _run_ip(
        "route",
        "replace",
        "default",
        "dev",
        tunnel.interface,
        "table",
        table,
    )

    for source_network in tunnel.source_networks:
        source = str(source_network)

        _run_ip(
            "rule",
            "del",
            "from",
            source,
            "priority",
            main_priority,
            "table",
            "main",
            "suppress_prefixlength",
            "0",
            check=False,
        )

        _run_ip(
            "rule",
            "del",
            "from",
            source,
            "priority",
            vpn_priority,
            "table",
            table,
            check=False,
        )

        _run_ip(
            "rule",
            "add",
            "from",
            source,
            "priority",
            main_priority,
            "table",
            "main",
            "suppress_prefixlength",
            "0",
        )

        _run_ip(
            "rule",
            "add",
            "from",
            source,
            "priority",
            vpn_priority,
            "table",
            table,
        )


def remove_policy_routing(
    tunnel: WireGuardTunnelConfig,
) -> None:
    """Remove policy routing for one VPN tunnel."""

    table = str(tunnel.routing_table)
    priority = tunnel.priority

    if priority <= 1:
        raise VpnRoutingError(
            "VPN routing priority must be greater than 1"
        )

    main_priority = str(priority - 1)
    vpn_priority = str(priority)

    for source_network in tunnel.source_networks:
        source = str(source_network)

        _run_ip(
            "rule",
            "del",
            "from",
            source,
            "priority",
            main_priority,
            "table",
            "main",
            "suppress_prefixlength",
            "0",
            check=False,
        )

        _run_ip(
            "rule",
            "del",
            "from",
            source,
            "priority",
            vpn_priority,
            "table",
            table,
            check=False,
        )

    _run_ip(
        "route",
        "flush",
        "table",
        table,
        check=False,
    )
