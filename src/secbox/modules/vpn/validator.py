"""Cross-module validation for SecBox VPN configuration."""

from collections.abc import Collection
from pathlib import Path

from secbox.core.models import SecBoxConfig
from secbox.modules.vpn.models import VpnConfig


class VpnValidationError(ValueError):
    """Raised when VPN configuration conflicts with SecBox configuration."""


def validate_vpn_against_interfaces(
    vpn: VpnConfig | None,
    physical_interfaces: Collection[str],
) -> None:
    """Validate VPN configuration against known physical interfaces.

    This function intentionally does not access the filesystem except for
    syntactic Path checks. It is safe to use for Web configuration previews.
    """

    if vpn is None or not vpn.enabled:
        return

    interfaces = set(physical_interfaces)

    for tunnel in vpn.tunnels:
        if not tunnel.enabled:
            continue

        if tunnel.interface in interfaces:
            raise VpnValidationError(
                f"VPN interface {tunnel.interface!r} conflicts "
                "with a configured physical interface"
            )

        if not tunnel.private_key_file.is_absolute():
            raise VpnValidationError(
                f"private key path for tunnel {tunnel.name!r} "
                "must be absolute"
            )

        if (
            tunnel.peer.preshared_key_file is not None
            and not tunnel.peer.preshared_key_file.is_absolute()
        ):
            raise VpnValidationError(
                f"preshared key path for tunnel {tunnel.name!r} "
                "must be absolute"
            )


def validate_vpn_config(config: SecBoxConfig) -> None:
    """Validate VPN configuration against the full SecBox configuration."""

    validate_vpn_against_interfaces(
        config.vpn,
        {
            interface.name
            for interface in config.network.interfaces
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

        if tunnel.peer.preshared_key_file is not None:
            _require_secure_key_file(
                tunnel.peer.preshared_key_file,
                f"preshared key for tunnel {tunnel.name!r}",
            )


def _require_secure_key_file(
    path: Path,
    description: str,
) -> None:
    if not path.is_file():
        raise VpnValidationError(
            f"{description} does not exist: {path}"
        )

    mode = path.stat().st_mode & 0o777

    if mode & 0o077:
        raise VpnValidationError(
            f"{description} must not be accessible by group or others: "
            f"{path} has mode {mode:04o}"
        )
