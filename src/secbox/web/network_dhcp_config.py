"""Web-facing Network and DHCP configuration models."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from secbox.modules.dhcp.models import DhcpServerConfig
from secbox.modules.network.models import NetworkConfig


class NetworkDhcpConfigPayload(BaseModel):
    """Complete editable Network + DHCP configuration."""

    model_config = ConfigDict(extra="forbid")

    network: NetworkConfig
    dhcp: list[DhcpServerConfig]


class NetworkDhcpConfigReadResponse(BaseModel):
    """Current Network + DHCP desired state."""

    model_config = ConfigDict(extra="forbid")

    network: NetworkConfig
    dhcp: list[DhcpServerConfig]


class NetworkDhcpValidationResponse(BaseModel):
    """Result of a non-applying validation."""

    model_config = ConfigDict(extra="forbid")

    valid: bool = True


class NetworkDhcpApplyResponse(BaseModel):
    """Result of privileged Network + DHCP apply."""

    model_config = ConfigDict(extra="forbid")

    ok: bool = True
    interfaces: int
    dhcp_scopes: int
    enabled_dhcp_scopes: int
