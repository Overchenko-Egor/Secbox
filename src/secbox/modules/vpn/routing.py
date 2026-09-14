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


def remove_tunnel_route(
    tunnel: WireGuardTunnelConfig,
) -> None:
    """Remove the tunnel's routing table."""

    _run_ip(
        "route",
        "flush",
        "table",
        str(tunnel.routing_table),
        check=False,
    )


def _source_networks(
    tunnels: list[WireGuardTunnelConfig],
) -> set[str]:
    """Return unique source networks managed by a tunnel set."""

    return {
        str(network)
        for tunnel in tunnels
        if tunnel.enabled
        for network in tunnel.source_networks
    }


def _remove_source_policy(
    source: str,
) -> None:
    """Remove both SecBox rules associated with one source network."""

    _run_ip(
        "rule",
        "del",
        "from",
        source,
        "priority",
        str(MAIN_RULE_PRIORITY),
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
        str(VPN_RULE_PRIORITY),
        check=False,
    )


def configure_pool_policy(
    tunnels: list[WireGuardTunnelConfig],
) -> None:
    """Route VPN-managed source networks through active table."""

    source_networks = _source_networks(tunnels)

    for source in sorted(source_networks):
        _remove_source_policy(source)

        _run_ip(
            "rule",
            "add",
            "from",
            source,
            "priority",
            str(MAIN_RULE_PRIORITY),
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
            str(VPN_RULE_PRIORITY),
            "table",
            str(ACTIVE_TABLE),
        )


def reconcile_pool_policy(
    previous_tunnels: list[WireGuardTunnelConfig],
    desired_tunnels: list[WireGuardTunnelConfig],
) -> None:
    """Replace old SecBox VPN policy rules with desired rules."""

    previous_sources = _source_networks(
        previous_tunnels
    )
    desired_sources = _source_networks(
        desired_tunnels
    )

    all_sources = (
        previous_sources
        | desired_sources
    )

    for source in sorted(all_sources):
        _remove_source_policy(source)

    for source in sorted(desired_sources):
        _run_ip(
            "rule",
            "add",
            "from",
            source,
            "priority",
            str(MAIN_RULE_PRIORITY),
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
            str(VPN_RULE_PRIORITY),
            "table",
            str(ACTIVE_TABLE),
        )


def flush_active_table() -> None:
    """Remove the selected VPN route from the active routing table."""

    _run_ip(
        "route",
        "flush",
        "table",
        str(ACTIVE_TABLE),
        check=False,
    )
