from pathlib import Path

import pytest
from pydantic import ValidationError

from secbox.modules.dhcp.models import DhcpServerConfig
from secbox.modules.dhcp.renderer import render_dnsmasq_config
from secbox.modules.dhcp.validator import (
    DhcpPreflightError,
    validate_dhcp_preflight,
)
from secbox.modules.network.models import (
    NetworkConfig,
    NetworkInterfaceConfig,
)


def make_dhcp() -> DhcpServerConfig:
    return DhcpServerConfig(
        interface="ens36",
        network="192.168.50.0/24",
        range_start="192.168.50.100",
        range_end="192.168.50.200",
        gateway="192.168.50.1",
        dns_servers=["192.168.1.1"],
    )


def make_network() -> NetworkConfig:
    return NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens36",
                role="lan",
                ipv4_method="static",
                ipv4_address="192.168.50.1/24",
            )
        ]
    )


def test_valid_dhcp_config() -> None:
    config = make_dhcp()

    assert str(config.network) == "192.168.50.0/24"
    assert str(config.range_start) == "192.168.50.100"


def test_range_outside_network_is_rejected() -> None:
    with pytest.raises(ValidationError):
        DhcpServerConfig(
            interface="ens36",
            network="192.168.50.0/24",
            range_start="192.168.60.100",
            range_end="192.168.60.200",
            gateway="192.168.50.1",
        )


def test_dhcp_preflight_passes() -> None:
    validate_dhcp_preflight(
        [make_dhcp()],
        make_network(),
    )


def test_dhcp_on_wan_is_rejected() -> None:
    network = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens36",
                role="wan",
                ipv4_method="static",
                ipv4_address="192.168.50.1/24",
            )
        ]
    )

    with pytest.raises(
        DhcpPreflightError,
        match="not allowed",
    ):
        validate_dhcp_preflight(
            [make_dhcp()],
            network,
        )


def test_dhcp_network_must_match_interface() -> None:
    network = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens36",
                role="lan",
                ipv4_method="static",
                ipv4_address="192.168.60.1/24",
            )
        ]
    )

    with pytest.raises(
        DhcpPreflightError,
        match="does not match",
    ):
        validate_dhcp_preflight(
            [make_dhcp()],
            network,
        )


def test_render_dnsmasq(tmp_path: Path) -> None:
    output = tmp_path / "secbox-dhcp.conf"

    render_dnsmasq_config(
        [make_dhcp()],
        output,
    )

    content = output.read_text(
        encoding="utf-8",
    )

    assert "port=0" in content
    assert "bind-interfaces" in content
    assert "interface=ens36" in content
    assert (
        "dhcp-range=192.168.50.100,"
        "192.168.50.200,"
        "255.255.255.0,"
        "12h"
    ) in content
    assert (
        "dhcp-option=interface:ens36,3,192.168.50.1"
    ) in content
