"""Configuration models for SecBox VPN tunnels."""

from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class WireGuardPeerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    public_key: str = Field(min_length=1)
    preshared_key_file: Path | None = None
    endpoint: str = Field(min_length=1)
    allowed_ips: list[IPv4Network] = Field(default_factory=list)
    persistent_keepalive: int | None = Field(default=25, ge=0, le=65535)

    @field_validator("allowed_ips")
    @classmethod
    def validate_allowed_ips(
        cls,
        value: list[IPv4Network],
    ) -> list[IPv4Network]:
        if not value:
            raise ValueError("WireGuard peer must have at least one allowed IP network")

        if len(value) != len(set(value)):
            raise ValueError("WireGuard allowed IP networks must be unique")

        return value


class WireGuardTunnelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    enabled: bool = True

    interface: str = Field(min_length=1, max_length=15)
    address: IPv4Interface

    private_key_file: Path

    mtu: int | None = Field(default=1420, ge=576, le=9000)

    priority: int = Field(default=100, ge=1, le=65535)
    routing_table: int = Field(ge=1, le=4294967295)

    source_networks: list[IPv4Network] = Field(
        default_factory=list,
    )

    health_probe: IPv4Address | None = None

    peer: WireGuardPeerConfig

    @field_validator("source_networks")
    @classmethod
    def validate_source_networks(
        cls,
        value: list[IPv4Network],
    ) -> list[IPv4Network]:
        if len(value) != len(set(value)):
            raise ValueError(
                "VPN source networks must be unique"
            )

        return value

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, value: str) -> str:
        if value == "lo":
            raise ValueError("VPN interface must not be loopback")

        if any(character.isspace() for character in value):
            raise ValueError("VPN interface must not contain whitespace")

        return value


class VpnConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False

    tunnels: list[WireGuardTunnelConfig] = Field(
        default_factory=list,
    )

    @model_validator(mode="after")
    def validate_unique_tunnels(self):
        names = [tunnel.name for tunnel in self.tunnels]
        interfaces = [tunnel.interface for tunnel in self.tunnels]
        tables = [tunnel.routing_table for tunnel in self.tunnels]

        if len(names) != len(set(names)):
            raise ValueError("VPN tunnel names must be unique")

        if len(interfaces) != len(set(interfaces)):
            raise ValueError("VPN tunnel interfaces must be unique")

        if len(tables) != len(set(tables)):
            raise ValueError("VPN routing tables must be unique")

        if self.enabled and not self.tunnels:
            raise ValueError(
                "VPN must contain at least one tunnel when enabled"
            )

        return self
