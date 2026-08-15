"""Render SecBox network configuration into systemd-networkd files."""

from pathlib import Path

from secbox.modules.network.models import (
    NetworkConfig,
    NetworkInterfaceConfig,
    RoutingPolicyConfig,
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

    for interface in sorted(
        config.interfaces,
        key=lambda item: item.name,
    ):
        rendered_file = output_dir / _network_filename(interface)

        rendered_file.write_text(
            _render_interface(
                interface,
                config.routing_policy,
            ),
            encoding="utf-8",
        )

        rendered_files.append(rendered_file)

    return rendered_files


def _network_filename(
    interface: NetworkInterfaceConfig,
) -> str:
    """Generate deterministic systemd-networkd filename."""

    return f"10-secbox-{interface.name}.network"


def _render_interface(
    interface: NetworkInterfaceConfig,
    routing_policies: list[RoutingPolicyConfig],
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

        if interface.routing_table is not None:
            lines.extend(
                [
                    "",
                    "[DHCPv4]",
                    f"RouteTable={interface.routing_table}",
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

    for policy in routing_policies:
        if policy.incoming_interface != interface.name:
            continue

        lines.extend(
            [
                "",
                "[RoutingPolicyRule]",
                f"IncomingInterface={policy.incoming_interface}",
                f"Table={policy.table}",
                f"Priority={policy.priority}",
            ]
        )

    lines.append("")

    return "\n".join(lines)
