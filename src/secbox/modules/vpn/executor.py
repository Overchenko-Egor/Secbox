"""WireGuard runtime management."""

import subprocess

from secbox.modules.vpn.models import WireGuardTunnelConfig
from secbox.modules.vpn.routing import (
    VpnRoutingError,
    configure_tunnel_route,
    remove_tunnel_route,
)


class VpnApplyError(RuntimeError):
    """Raised when a VPN tunnel cannot be applied."""


def _run(
    command: list[str],
    *,
    input_text: str | None = None,
) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            command,
            input=input_text,
            text=True,
            check=True,
            capture_output=True,
        )

    except subprocess.CalledProcessError as error:
        message = (
            error.stderr.strip()
            or error.stdout.strip()
        )

        raise VpnApplyError(
            f"command failed: {' '.join(command)}: {message}"
        ) from error


def _interface_exists(
    interface: str,
) -> bool:
    result = subprocess.run(
        [
            "/usr/sbin/ip",
            "link",
            "show",
            "dev",
            interface,
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    return result.returncode == 0


def _reconcile_wireguard_peers(
    interface: str,
    desired_public_key: str,
) -> None:
    """Remove peers not present in desired configuration."""

    result = _run(
        [
            "/usr/bin/wg",
            "show",
            interface,
            "peers",
        ]
    )

    current_peers = {
        peer.strip()
        for peer in result.stdout.splitlines()
        if peer.strip()
    }

    stale_peers = (
        current_peers
        - {desired_public_key}
    )

    for public_key in sorted(stale_peers):
        _run(
            [
                "/usr/bin/wg",
                "set",
                interface,
                "peer",
                public_key,
                "remove",
            ]
        )


def apply_wireguard_tunnel(
    tunnel: WireGuardTunnelConfig,
) -> None:
    """Create or update one WireGuard tunnel."""

    if not _interface_exists(
        tunnel.interface
    ):
        _run(
            [
                "/usr/sbin/ip",
                "link",
                "add",
                "dev",
                tunnel.interface,
                "type",
                "wireguard",
            ]
        )

    _run(
        [
            "/usr/sbin/ip",
            "address",
            "replace",
            str(tunnel.address),
            "dev",
            tunnel.interface,
        ]
    )

    if tunnel.mtu is not None:
        _run(
            [
                "/usr/sbin/ip",
                "link",
                "set",
                "dev",
                tunnel.interface,
                "mtu",
                str(tunnel.mtu),
            ]
        )

    command = [
        "/usr/bin/wg",
        "set",
        tunnel.interface,
        "private-key",
        str(tunnel.private_key_file),
        "peer",
        tunnel.peer.public_key,
        "endpoint",
        tunnel.peer.endpoint,
        "allowed-ips",
        ",".join(
            str(network)
            for network
            in tunnel.peer.allowed_ips
        ),
    ]

    if (
        tunnel.peer.preshared_key_file
        is not None
    ):
        command.extend(
            [
                "preshared-key",
                str(
                    tunnel.peer.preshared_key_file
                ),
            ]
        )

    if (
        tunnel.peer.persistent_keepalive
        is not None
    ):
        command.extend(
            [
                "persistent-keepalive",
                str(
                    tunnel.peer.persistent_keepalive
                ),
            ]
        )

    _run(command)

    _reconcile_wireguard_peers(
        tunnel.interface,
        tunnel.peer.public_key,
    )

    _run(
        [
            "/usr/sbin/ip",
            "link",
            "set",
            "dev",
            tunnel.interface,
            "up",
        ]
    )

    try:
        configure_tunnel_route(
            tunnel
        )
    except VpnRoutingError as error:
        raise VpnApplyError(
            str(error)
        ) from error


def remove_wireguard_tunnel(
    tunnel: WireGuardTunnelConfig,
    *,
    remove_route: bool = True,
) -> None:
    """Remove a WireGuard interface and its obsolete routing table."""

    if _interface_exists(
        tunnel.interface
    ):
        _run(
            [
                "/usr/sbin/ip",
                "link",
                "delete",
                "dev",
                tunnel.interface,
            ]
        )

    if remove_route:
        try:
            remove_tunnel_route(
                tunnel
            )
        except VpnRoutingError as error:
            raise VpnApplyError(
                str(error)
            ) from error
