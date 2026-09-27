"""Cross-module validation for SecBox VPN configuration."""

from collections.abc import Collection
from pathlib import Path

from secbox.core.models import SecBoxConfig
from secbox.modules.vpn.models import VpnConfig


VPN_KEY_ROOT = Path("/etc/secbox/vpn")


class VpnValidationError(ValueError):
    """Raised when VPN configuration conflicts with SecBox configuration."""


def _validate_managed_key_path(
    path: Path,
    description: str,
) -> None:
    """Require VPN secret paths to live under the SecBox VPN key directory."""

    if not path.is_absolute():
        raise VpnValidationError(
            f"{description} path must be absolute"
        )

    normalized = path.resolve(
        strict=False
    )

    try:
        normalized.relative_to(
            VPN_KEY_ROOT
        )
    except ValueError as error:
        raise VpnValidationError(
            f"{description} must be stored under {VPN_KEY_ROOT}"
        ) from error

    if normalized == VPN_KEY_ROOT:
        raise VpnValidationError(
            f"{description} must reference a file under {VPN_KEY_ROOT}"
        )


def validate_l2_access_ports(config: SecBoxConfig) -> None:
    """Validate ownership and network roles of L2 VPN access ports."""

    vpn = config.vpn

    if vpn is None or not vpn.enabled:
        return

    interfaces_by_name = {
        interface.name: interface
        for interface in config.network.interfaces
    }

    used_ports: dict[str, str] = {}

    for tunnel in vpn.l2_tunnels:
        if not tunnel.enabled:
            continue

        for port in tunnel.bridge.ports:
            interface = interfaces_by_name.get(port)

            if interface is None:
                raise VpnValidationError(
                    f"L2 VPN bridge port {port!r} is not present "
                    "in network configuration"
                )

            if interface.role != "l2":
                raise VpnValidationError(
                    f"L2 VPN bridge port {port!r} must have role 'l2'"
                )

            owner = used_ports.get(port)

            if owner is not None:
                raise VpnValidationError(
                    f"L2 VPN bridge port {port!r} is used by "
                    f"multiple tunnels: {owner!r} and {tunnel.name!r}"
                )

            used_ports[port] = tunnel.name


def validate_vpn_against_interfaces(
    vpn: VpnConfig | None,
    physical_interfaces: Collection[str],
) -> None:
    """Validate VPN configuration against known physical interfaces."""

    if vpn is None or not vpn.enabled:
        return

    interfaces = set(
        physical_interfaces
    )

    for tunnel in vpn.tunnels:
        if not tunnel.enabled:
            continue

        if tunnel.interface in interfaces:
            raise VpnValidationError(
                f"VPN interface {tunnel.interface!r} conflicts "
                "with a configured physical interface"
            )

        _validate_managed_key_path(
            tunnel.private_key_file,
            f"private key for tunnel {tunnel.name!r}",
        )

        if (
            tunnel.peer.preshared_key_file
            is not None
        ):
            _validate_managed_key_path(
                tunnel.peer.preshared_key_file,
                f"preshared key for tunnel {tunnel.name!r}",
            )


    for tunnel in vpn.l2_tunnels:
        if not tunnel.enabled:
            continue

        managed_interfaces = {
            tunnel.transport.interface,
            tunnel.bridge.interface,
            tunnel.encapsulation.interface,
        }

        conflicts = managed_interfaces & interfaces

        if conflicts:
            raise VpnValidationError(
                "L2 VPN interfaces conflict with configured "
                f"physical interfaces: {sorted(conflicts)}"
            )

        for port in tunnel.bridge.ports:
            if port not in interfaces:
                raise VpnValidationError(
                    f"L2 bridge port {port!r} is not a "
                    "configured physical interface"
                )

        _validate_managed_key_path(
            tunnel.transport.private_key_file,
            f"private key for L2 tunnel {tunnel.name!r}",
        )

        if (
            tunnel.transport.peer.preshared_key_file
            is not None
        ):
            _validate_managed_key_path(
                tunnel.transport.peer.preshared_key_file,
                f"preshared key for L2 tunnel {tunnel.name!r}",
            )


def validate_vpn_config(
    config: SecBoxConfig,
) -> None:
    """Validate VPN configuration against full SecBox configuration."""

    validate_vpn_against_interfaces(
        config.vpn,
        {
            interface.name
            for interface
            in config.network.interfaces
        },
    )


def validate_vpn_key_paths(
    config: SecBoxConfig,
) -> None:
    vpn = config.vpn

    if vpn is None or not vpn.enabled:
        return

    for tunnel in vpn.tunnels:
        if not tunnel.enabled:
            continue

        _require_secure_key_file(
            tunnel.private_key_file,
            f"private key for tunnel {tunnel.name!r}",
        )

        if (
            tunnel.peer.preshared_key_file
            is not None
        ):
            _require_secure_key_file(
                tunnel.peer.preshared_key_file,
                f"preshared key for tunnel {tunnel.name!r}",
            )


    for tunnel in vpn.l2_tunnels:
        if not tunnel.enabled:
            continue

        _require_secure_key_file(
            tunnel.transport.private_key_file,
            f"private key for L2 tunnel {tunnel.name!r}",
        )

        if (
            tunnel.transport.peer.preshared_key_file
            is not None
        ):
            _require_secure_key_file(
                tunnel.transport.peer.preshared_key_file,
                f"preshared key for L2 tunnel {tunnel.name!r}",
            )


def _require_secure_key_file(
    path: Path,
    description: str,
) -> None:
    _validate_managed_key_path(
        path,
        description,
    )

    if not path.is_file():
        raise VpnValidationError(
            f"{description} does not exist: {path}"
        )

    mode = (
        path.stat().st_mode
        & 0o777
    )

    if mode & 0o077:
        raise VpnValidationError(
            f"{description} must not be accessible by group or others: "
            f"{path} has mode {mode:04o}"
        )
