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

    l2_tunnels: list["L2VpnTunnelConfig"] = Field(
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

        l2_names = [
            tunnel.name
            for tunnel in self.l2_tunnels
        ]

        l2_interfaces = [
            interface
            for tunnel in self.l2_tunnels
            for interface in (
                tunnel.transport.interface,
                tunnel.bridge.interface,
                tunnel.encapsulation.interface,
            )
        ]

        if len(l2_names) != len(set(l2_names)):
            raise ValueError("L2 VPN tunnel names must be unique")

        if len(l2_interfaces) != len(set(l2_interfaces)):
            raise ValueError(
                "L2 VPN interfaces must be unique"
            )

        all_interfaces = interfaces + l2_interfaces

        if len(all_interfaces) != len(set(all_interfaces)):
            raise ValueError(
                "L3 and L2 VPN interfaces must not conflict"
            )

        all_names = names + l2_names

        if len(all_names) != len(set(all_names)):
            raise ValueError(
                "L3 and L2 VPN tunnel names must not conflict"
            )

        if (
            self.enabled
            and not self.tunnels
            and not self.l2_tunnels
        ):
            raise ValueError(
                "VPN must contain at least one tunnel (L3 or L2) "
                "when enabled"
            )

        return self


class WireGuardL2TransportConfig(BaseModel):
    """WireGuard transport used only to carry an L2 overlay."""

    model_config = ConfigDict(extra="forbid")

    interface: str = Field(min_length=1, max_length=15)
    address: IPv4Interface
    private_key_file: Path
    mtu: int = Field(default=1420, ge=576, le=9000)
    listen_port: int | None = Field(default=None, ge=1, le=65535)
    peer: WireGuardPeerConfig

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, value: str) -> str:
        if value == "lo":
            raise ValueError("L2 transport interface must not be loopback")

        if any(character.isspace() for character in value):
            raise ValueError(
                "L2 transport interface must not contain whitespace"
            )

        return value


class GretapConfig(BaseModel):
    """GRETAP encapsulation carried by the WireGuard transport."""

    model_config = ConfigDict(extra="forbid")

    interface: str = Field(min_length=1, max_length=15)
    local: IPv4Address
    remote: IPv4Address
    mtu: int = Field(default=1376, ge=576, le=9000)
    ttl: int = Field(default=64, ge=1, le=255)

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, value: str) -> str:
        if value in {"lo", "gretap0"}:
            raise ValueError(
                "GRETAP interface uses a reserved system interface name"
            )

        if any(character.isspace() for character in value):
            raise ValueError(
                "GRETAP interface must not contain whitespace"
            )

        return value


class L2BridgeConfig(BaseModel):
    """Bridge used by an L2 VPN overlay."""

    model_config = ConfigDict(extra="forbid")

    interface: str = Field(min_length=1, max_length=15)
    address: IPv4Interface | None = None
    ports: list[str] = Field(default_factory=list)

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("L2 bridge ports must be unique")

        if any(
            not port or any(character.isspace() for character in port)
            for port in value
        ):
            raise ValueError("L2 bridge ports contain an invalid interface")

        return value


class L2VpnTunnelConfig(BaseModel):
    """One Ethernet-over-WireGuard VPN overlay."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    enabled: bool = True

    transport: WireGuardL2TransportConfig
    bridge: L2BridgeConfig
    encapsulation: GretapConfig

    @model_validator(mode="after")
    def validate_overlay(self):
        interfaces = [
            self.transport.interface,
            self.bridge.interface,
            self.encapsulation.interface,
        ]

        if len(interfaces) != len(set(interfaces)):
            raise ValueError(
                "L2 VPN transport, bridge and encapsulation "
                "interfaces must be different"
            )

        transport_network = self.transport.address.network

        if self.encapsulation.local not in transport_network:
            raise ValueError(
                "GRETAP local address must belong to "
                "the WireGuard transport network"
            )

        if self.encapsulation.remote not in transport_network:
            raise ValueError(
                "GRETAP remote address must belong to "
                "the WireGuard transport network"
            )

        if self.encapsulation.local != self.transport.address.ip:
            raise ValueError(
                "GRETAP local address must match "
                "the WireGuard transport address"
            )

        if self.encapsulation.local == self.encapsulation.remote:
            raise ValueError(
                "GRETAP local and remote addresses must be different"
            )

        if self.encapsulation.mtu >= self.transport.mtu:
            raise ValueError(
                "GRETAP MTU must be smaller than WireGuard transport MTU"
            )

        if self.encapsulation.interface in self.bridge.ports:
            raise ValueError(
                "GRETAP interface is attached automatically and "
                "must not be listed in bridge ports"
            )

        return self
