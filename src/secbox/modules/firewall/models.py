"""Firewall configuration models."""

from pydantic import BaseModel, ConfigDict


class FirewallConfig(BaseModel):
    """Base SecBox firewall configuration."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True

    wan_interface: str
    lan_interface: str

    allow_lan_to_wan: bool = True
    allow_icmp_input: bool = True

    input_policy: str = "accept"
    forward_policy: str = "drop"
    output_policy: str = "accept"

    enable_ipv4_forwarding: bool = True
    enable_nat: bool = True
