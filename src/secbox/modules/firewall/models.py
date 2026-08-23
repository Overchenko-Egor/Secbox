"""Firewall configuration models."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


FirewallPolicy = Literal[
    "accept",
    "drop",
]


class FirewallConfig(BaseModel):
    """Base SecBox firewall configuration."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True

    wan_interface: str
    lan_interface: str
    management_interface: str

    management_tcp_ports: list[int] = Field(
        default_factory=lambda: [22]
    )

    allow_lan_to_wan: bool = True
    allow_icmp_input: bool = True
    allow_dhcp_server: bool = True

    enable_ipv4_forwarding: bool = True
    enable_nat: bool = True

    log_dropped_input: bool = True
    log_dropped_forward: bool = True
    log_rate: str = "10/second"
    log_burst: int = 20

    dynamic_blacklist_enabled: bool = True
    dynamic_blacklist_timeout: str = "1h"

    input_policy: FirewallPolicy = "drop"
    forward_policy: FirewallPolicy = "drop"
    output_policy: FirewallPolicy = "accept"

