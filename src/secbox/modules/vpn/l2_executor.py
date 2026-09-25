"""Runtime management for Ethernet-over-WireGuard VPN overlays."""

import subprocess

from secbox.modules.vpn.models import L2VpnTunnelConfig


class L2VpnApplyError(RuntimeError):
    """Raised when an L2 VPN overlay cannot be reconciled."""


def _run(
    command: list[str],
    *,
    check: bool = True,
) -> subprocess.CompletedProcess:
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

        raise L2VpnApplyError(
            f"command failed: {' '.join(command)}: {message}"
        )

    return result


def _interface_exists(interface: str) -> bool:
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


def _delete_interface(interface: str) -> None:
    if not _interface_exists(interface):
        return

    _run(
        [
            "/usr/sbin/ip",
            "link",
            "delete",
            "dev",
            interface,
        ]
    )


def _configure_wireguard_transport(
    tunnel: L2VpnTunnelConfig,
) -> None:
    transport = tunnel.transport

    if not _interface_exists(transport.interface):
        _run(
            [
                "/usr/sbin/ip",
                "link",
                "add",
                "dev",
                transport.interface,
                "type",
                "wireguard",
            ]
        )

    _run(
        [
            "/usr/sbin/ip",
            "address",
            "replace",
            str(transport.address),
            "dev",
            transport.interface,
        ]
    )

    _run(
        [
            "/usr/sbin/ip",
            "link",
            "set",
            "dev",
            transport.interface,
            "mtu",
            str(transport.mtu),
        ]
    )

    command = [
        "/usr/bin/wg",
        "set",
        transport.interface,
        "private-key",
        str(transport.private_key_file),
    ]

    if transport.listen_port is not None:
        command.extend(
            [
                "listen-port",
                str(transport.listen_port),
            ]
        )

    command.extend(
        [
            "peer",
            transport.peer.public_key,
            "endpoint",
            transport.peer.endpoint,
            "allowed-ips",
            ",".join(
                str(network)
                for network in transport.peer.allowed_ips
            ),
        ]
    )

    if transport.peer.preshared_key_file is not None:
        command.extend(
            [
                "preshared-key",
                str(transport.peer.preshared_key_file),
            ]
        )

    if transport.peer.persistent_keepalive is not None:
        command.extend(
            [
                "persistent-keepalive",
                str(transport.peer.persistent_keepalive),
            ]
        )

    _run(command)

    peers = _run(
        [
            "/usr/bin/wg",
            "show",
            transport.interface,
            "peers",
        ]
    )

    desired_peer = transport.peer.public_key

    for public_key in peers.stdout.splitlines():
        public_key = public_key.strip()

        if not public_key or public_key == desired_peer:
            continue

        _run(
            [
                "/usr/bin/wg",
                "set",
                transport.interface,
                "peer",
                public_key,
                "remove",
            ]
        )

    _run(
        [
            "/usr/sbin/ip",
            "link",
            "set",
            "dev",
            transport.interface,
            "up",
        ]
    )


def _configure_bridge(
    tunnel: L2VpnTunnelConfig,
) -> None:
    bridge = tunnel.bridge

    if not _interface_exists(bridge.interface):
        _run(
            [
                "/usr/sbin/ip",
                "link",
                "add",
                "name",
                bridge.interface,
                "type",
                "bridge",
            ]
        )

    if bridge.address is not None:
        _run(
            [
                "/usr/sbin/ip",
                "address",
                "replace",
                str(bridge.address),
                "dev",
                bridge.interface,
            ]
        )

    _run(
        [
            "/usr/sbin/ip",
            "link",
            "set",
            "dev",
            bridge.interface,
            "up",
        ]
    )


def _configure_gretap(
    tunnel: L2VpnTunnelConfig,
) -> None:
    encapsulation = tunnel.encapsulation

    #
    # GRETAP local/remote cannot be changed reliably with the same
    # simplicity as normal link properties. Recreate the managed
    # overlay interface on every reconciliation.
    #
    _delete_interface(encapsulation.interface)

    _run(
        [
            "/usr/sbin/ip",
            "link",
            "add",
            encapsulation.interface,
            "type",
            "gretap",
            "local",
            str(encapsulation.local),
            "remote",
            str(encapsulation.remote),
            "ttl",
            str(encapsulation.ttl),
        ]
    )

    _run(
        [
            "/usr/sbin/ip",
            "link",
            "set",
            "dev",
            encapsulation.interface,
            "mtu",
            str(encapsulation.mtu),
        ]
    )

    _run(
        [
            "/usr/sbin/ip",
            "link",
            "set",
            "dev",
            encapsulation.interface,
            "master",
            tunnel.bridge.interface,
        ]
    )

    _run(
        [
            "/usr/sbin/ip",
            "link",
            "set",
            "dev",
            encapsulation.interface,
            "up",
        ]
    )


def _configure_bridge_ports(
    tunnel: L2VpnTunnelConfig,
) -> None:
    for interface in tunnel.bridge.ports:
        if not _interface_exists(interface):
            raise L2VpnApplyError(
                f"L2 bridge port does not exist: {interface}"
            )

        _run(
            [
                "/usr/sbin/ip",
                "link",
                "set",
                "dev",
                interface,
                "master",
                tunnel.bridge.interface,
            ]
        )

        _run(
            [
                "/usr/sbin/ip",
                "link",
                "set",
                "dev",
                interface,
                "up",
            ]
        )


def apply_l2_vpn_tunnel(
    tunnel: L2VpnTunnelConfig,
) -> None:
    """Create or reconcile one L2 VPN overlay."""

    _configure_wireguard_transport(tunnel)
    _configure_bridge(tunnel)
    _configure_gretap(tunnel)
    _configure_bridge_ports(tunnel)


def remove_l2_vpn_tunnel(
    tunnel: L2VpnTunnelConfig,
) -> None:
    """Remove one managed L2 VPN overlay."""

    for interface in tunnel.bridge.ports:
        if _interface_exists(interface):
            _run(
                [
                    "/usr/sbin/ip",
                    "link",
                    "set",
                    "dev",
                    interface,
                    "nomaster",
                ],
                check=False,
            )

    _delete_interface(
        tunnel.encapsulation.interface
    )

    _delete_interface(
        tunnel.bridge.interface
    )

    _delete_interface(
        tunnel.transport.interface
    )
