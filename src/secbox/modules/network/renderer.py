"""Render SecBox network configuration into systemd-networkd files."""

from pathlib import Path

from secbox.modules.network.models import (
    NetworkConfig,
    NetworkInterfaceConfig,
)


class NetworkRenderError(Exception):
    """Raised when network configuration cannot be rendered."""


def render_networkd(
    config: NetworkConfig,
    output_dir: Path,
) -> list[Path]:
    """Render systemd-networkd configuration files.

    Existing *.network files in output_dir are removed before rendering.
    Only files inside output_dir are touched.
    """

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    for existing_file in output_dir.glob("*.network"):
        existing_file.unlink()

    rendered_files: list[Path] = []

    for index, interface in enumerate(config.interfaces, start=10):
        rendered_file = output_dir / _network_filename(
            index,
            interface,
        )

        rendered_file.write_text(
            _render_interface(interface),
            encoding="utf-8",
        )

        rendered_files.append(rendered_file)

    return rendered_files


def _network_filename(
    index: int,
    interface: NetworkInterfaceConfig,
) -> str:
    """Generate deterministic systemd-networkd filename."""

    return f"{index:02d}-secbox-{interface.name}.network"


def _render_interface(
    interface: NetworkInterfaceConfig,
) -> str:
    """Render one interface into systemd-networkd syntax."""

    lines = [
        "[Match]",
        f"Name={interface.name}",
        "",
        "[Network]",
    ]

    if interface.ipv4_method == "dhcp":
        lines.extend(
            [
                "DHCP=ipv4",
                "IPv6AcceptRA=no",
            ]
        )

    elif interface.ipv4_method == "static":
        if interface.ipv4_address is None:
            raise NetworkRenderError(
                f"static interface {interface.name} has no IPv4 address"
            )

        lines.extend(
            [
                f"Address={interface.ipv4_address}",
                "DHCP=no",
                "IPv6AcceptRA=no",
            ]
        )

    elif interface.ipv4_method == "disabled":
        lines.extend(
            [
                "DHCP=no",
                "IPv6AcceptRA=no",
                "LinkLocalAddressing=no",
            ]
        )

    else:
        raise NetworkRenderError(
            f"unsupported IPv4 method: {interface.ipv4_method}"
        )

    lines.append("")

    return "\n".join(lines)
