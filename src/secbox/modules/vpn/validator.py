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
