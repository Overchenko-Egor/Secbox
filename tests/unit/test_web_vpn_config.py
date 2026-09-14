from ipaddress import ip_address, ip_interface, ip_network
from pathlib import Path

import pytest

from secbox.modules.vpn.models import (
    VpnConfig,
    WireGuardPeerConfig,
    WireGuardTunnelConfig,
)
from secbox.modules.vpn.validator import VpnValidationError
from secbox.web.vpn_config import validate_vpn_candidate


def make_vpn(
    interface: str = "wg0",
    private_key_file: Path = Path("/etc/secbox/vpn/wg0.key"),
) -> VpnConfig:
    return VpnConfig(
        enabled=True,
        tunnels=[
            WireGuardTunnelConfig(
                name="primary",
                enabled=True,
                interface=interface,
                address=ip_interface("10.200.0.2/30"),
                private_key_file=private_key_file,
                mtu=1420,
                priority=100,
                routing_table=200,
                source_networks=[
                    ip_network("192.168.50.0/24"),
                ],
                health_probe=ip_address("10.200.0.1"),
                peer=WireGuardPeerConfig(
                    public_key="peer-public-key",
                    endpoint="192.168.1.108:51820",
                    allowed_ips=[
                        ip_network("0.0.0.0/0"),
                    ],
                    persistent_keepalive=25,
                ),
            ),
        ],
    )


def test_valid_vpn_candidate_is_accepted() -> None:
    result = validate_vpn_candidate(
        make_vpn(),
        {"ens33", "ens36", "ens38"},
    )

    assert result.valid is True
    assert result.vpn.enabled is True
    assert result.vpn.tunnels[0].interface == "wg0"


def test_physical_interface_conflict_is_rejected() -> None:
    with pytest.raises(
        VpnValidationError,
        match="conflicts with a configured physical interface",
    ):
        validate_vpn_candidate(
            make_vpn(interface="ens33"),
            {"ens33", "ens36", "ens38"},
        )


def test_relative_private_key_path_is_rejected() -> None:
    with pytest.raises(
        VpnValidationError,
        match="must be absolute",
    ):
        validate_vpn_candidate(
            make_vpn(
                private_key_file=Path("vpn/wg0.key"),
            ),
            {"ens33"},
        )


def test_disabled_vpn_is_accepted() -> None:
    result = validate_vpn_candidate(
        VpnConfig(
            enabled=False,
            tunnels=[],
        ),
        {"ens33"},
    )

    assert result.valid is True
    assert result.vpn.enabled is False
