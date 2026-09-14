"""Safe Web API models and validation for VPN configuration."""

from collections.abc import Collection

from pydantic import BaseModel, ConfigDict

from secbox.modules.vpn.models import VpnConfig
from secbox.modules.vpn.validator import (
    VpnValidationError,
    validate_vpn_against_interfaces,
)


class VpnConfigPreviewRequest(BaseModel):
    """Candidate VPN configuration submitted by the Web UI."""

    model_config = ConfigDict(extra="forbid")

    vpn: VpnConfig


class VpnConfigPreviewResponse(BaseModel):
    """Result of validating a candidate VPN configuration."""

    model_config = ConfigDict(extra="forbid")

    valid: bool
    vpn: VpnConfig


def validate_vpn_candidate(
    candidate: VpnConfig,
    physical_interfaces: Collection[str],
) -> VpnConfigPreviewResponse:
    """Validate candidate VPN configuration without changing system state."""

    validate_vpn_against_interfaces(
        candidate,
        physical_interfaces,
    )

    return VpnConfigPreviewResponse(
        valid=True,
        vpn=candidate,
    )


__all__ = [
    "VpnConfigPreviewRequest",
    "VpnConfigPreviewResponse",
    "VpnValidationError",
    "validate_vpn_candidate",
]
