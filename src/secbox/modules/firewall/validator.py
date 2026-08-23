"""Firewall preflight validation."""

from secbox.modules.firewall.models import FirewallConfig
from secbox.modules.network.models import NetworkConfig


class FirewallPreflightError(Exception):
    """Raised when firewall configuration is inconsistent."""


def validate_firewall_preflight(
    firewall: FirewallConfig,
    network: NetworkConfig,
) -> None:
    """Validate firewall configuration against network roles."""

    interfaces = {
        interface.name: interface
        for interface in network.interfaces
    }

    wan = interfaces.get(firewall.wan_interface)
    lan = interfaces.get(firewall.lan_interface)
    management = interfaces.get(firewall.management_interface)

    if wan is None:
        raise FirewallPreflightError(
            f"WAN interface not found in network config: "
            f"{firewall.wan_interface}"
        )

    if lan is None:
        raise FirewallPreflightError(
            f"LAN interface not found in network config: "
            f"{firewall.lan_interface}"
        )

    if management is None:
        raise FirewallPreflightError(
            f"management interface not found in network config: "
            f"{firewall.management_interface}"
        )

    if wan.role != "wan":
        raise FirewallPreflightError(
            f"interface {wan.name} does not have WAN role"
        )

    if lan.role != "lan":
        raise FirewallPreflightError(
            f"interface {lan.name} does not have LAN role"
        )

    if management.role != "mgmt":
        raise FirewallPreflightError(
            f"interface {management.name} does not have MGMT role"
        )

    role_interfaces = {
        firewall.wan_interface,
        firewall.lan_interface,
        firewall.management_interface,
    }

    if len(role_interfaces) != 3:
        raise FirewallPreflightError(
            "WAN, LAN and management interfaces must be different"
        )
