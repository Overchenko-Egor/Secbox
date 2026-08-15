"""Network configuration models for SecBox."""

from ipaddress import IPv4Interface
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


InterfaceRole = Literal[
    "wan",
    "lan",
    "dmz",
    "mgmt",
    "sandbox",
    "unused",
]

IPv4Method = Literal[
    "dhcp",
    "static",
    "disabled",
]


class RoutingPolicyConfig(BaseModel):
    """Policy routing from an ingress interface to a routing table."""

    model_config = ConfigDict(extra="forbid")

    incoming_interface: str
    table: int = Field(ge=1, le=4294967295)
    priority: int = Field(ge=1, le=32765)


class NetworkInterfaceConfig(BaseModel):
    """Configuration of a single network interface."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        min_length=1,
        max_length=15,
        description="Linux network interface name",
    )

    role: InterfaceRole
    ipv4_method: IPv4Method = "disabled"
    ipv4_address: IPv4Interface | None = None

    routing_table: int | None = Field(
        default=None,
        ge=1,
        le=4294967295,
    )

    @field_validator("name")
    @classmethod
    def validate_interface_name(cls, value: str) -> str:
        if value == "lo":
            raise ValueError("loopback interface cannot be managed by SecBox")

        forbidden_characters = {"/", "\\", ":", " ", "\t", "\n"}

        if any(character in value for character in forbidden_characters):
            raise ValueError("invalid network interface name")

        return value

    @model_validator(mode="after")
    def validate_ipv4_configuration(self) -> "NetworkInterfaceConfig":
        if self.ipv4_method == "static" and self.ipv4_address is None:
            raise ValueError(
                "ipv4_address is required when ipv4_method is static"
            )

        if self.ipv4_method != "static" and self.ipv4_address is not None:
            raise ValueError(
                "ipv4_address may only be set when ipv4_method is static"
            )

        if self.routing_table is not None and self.role != "wan":
            raise ValueError(
                "routing_table may currently only be configured for WAN interfaces"
            )

        return self


class NetworkConfig(BaseModel):
    """Complete SecBox network configuration."""

    model_config = ConfigDict(extra="forbid")

    interfaces: list[NetworkInterfaceConfig] = Field(default_factory=list)

    routing_policy: list[RoutingPolicyConfig] = Field(
        default_factory=list
    )

    @model_validator(mode="after")
    def validate_interfaces(self) -> "NetworkConfig":
        names = [
            interface.name
            for interface in self.interfaces
        ]

        if len(names) != len(set(names)):
            raise ValueError(
                "network interface names must be unique"
            )

        tables = [
            interface.routing_table
            for interface in self.interfaces
            if interface.routing_table is not None
        ]

        if len(tables) != len(set(tables)):
            raise ValueError(
                "WAN routing table IDs must be unique"
            )

        return self
