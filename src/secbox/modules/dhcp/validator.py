"""DHCP preflight validation."""

from secbox.modules.dhcp.models import DhcpServerConfig
from secbox.modules.network.models import NetworkConfig


class DhcpPreflightError(Exception):
    """Raised when DHCP configuration is unsafe or inconsistent."""


def validate_dhcp_preflight(
    dhcp_configs: list[DhcpServerConfig],
    network_config: NetworkConfig,
) -> None:
    """Validate DHCP configuration against SecBox network roles."""

    interfaces_by_name = {
        interface.name: interface
        for interface in network_config.interfaces
    }

    for dhcp in dhcp_configs:
        if not dhcp.enabled:
            continue

        interface = interfaces_by_name.get(dhcp.interface)

        if interface is None:
            raise DhcpPreflightError(
                f"DHCP interface is not present in network config: "
                f"{dhcp.interface}"
            )

        if interface.role not in {
            "lan",
            "dmz",
            "sandbox",
        }:
            raise DhcpPreflightError(
                f"DHCP is not allowed on interface role "
                f"'{interface.role}'"
            )

        if interface.ipv4_method != "static":
            raise DhcpPreflightError(
                f"DHCP interface {dhcp.interface} must use static IPv4"
            )

        if interface.ipv4_address is None:
            raise DhcpPreflightError(
                f"DHCP interface {dhcp.interface} has no IPv4 address"
            )

        if interface.ipv4_address.network != dhcp.network:
            raise DhcpPreflightError(
                f"DHCP network {dhcp.network} does not match "
                f"interface network {interface.ipv4_address.network}"
            )

        if dhcp.gateway != interface.ipv4_address.ip:
            raise DhcpPreflightError(
                f"DHCP gateway {dhcp.gateway} does not match "
                f"interface address {interface.ipv4_address.ip}"
            )
