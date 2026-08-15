"""DHCP configuration models."""

from ipaddress import IPv4Address, IPv4Network

from pydantic import BaseModel, ConfigDict, field_validator, model_validator


class DhcpServerConfig(BaseModel):
    """DHCP server configuration for one LAN segment."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    interface: str

    network: IPv4Network
    range_start: IPv4Address
    range_end: IPv4Address

    gateway: IPv4Address
    dns_servers: list[IPv4Address] = []

    lease_time: str = "12h"

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, value: str) -> str:
        if value == "lo":
            raise ValueError("DHCP cannot run on loopback")

        if not value:
            raise ValueError("interface cannot be empty")

        return value

    @model_validator(mode="after")
    def validate_addresses(self) -> "DhcpServerConfig":
        if self.range_start not in self.network:
            raise ValueError("range_start is outside DHCP network")

        if self.range_end not in self.network:
            raise ValueError("range_end is outside DHCP network")

        if self.gateway not in self.network:
            raise ValueError("gateway is outside DHCP network")

        if int(self.range_start) > int(self.range_end):
            raise ValueError("range_start must not be greater than range_end")

        if self.range_start in {
            self.network.network_address,
            self.network.broadcast_address,
        }:
            raise ValueError("range_start cannot be network or broadcast address")

        if self.range_end in {
            self.network.network_address,
            self.network.broadcast_address,
        }:
            raise ValueError("range_end cannot be network or broadcast address")

        return self
