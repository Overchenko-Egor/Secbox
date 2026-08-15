from pathlib import Path

import pytest

from secbox.modules.firewall.models import FirewallConfig
from secbox.modules.firewall.renderer import render_nftables_config
from secbox.modules.firewall.validator import (
    FirewallPreflightError,
    validate_firewall_preflight,
)
from secbox.modules.network.models import (
    NetworkConfig,
    NetworkInterfaceConfig,
)


def make_network() -> NetworkConfig:
    return NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens33",
                role="wan",
                ipv4_method="dhcp",
            ),
            NetworkInterfaceConfig(
                name="ens36",
                role="lan",
                ipv4_method="static",
                ipv4_address="192.168.50.1/24",
            ),
        ]
    )


def make_firewall() -> FirewallConfig:
    return FirewallConfig(
        wan_interface="ens33",
        lan_interface="ens36",
    )


def test_firewall_preflight_passes() -> None:
    validate_firewall_preflight(
        make_firewall(),
        make_network(),
    )


def test_wrong_wan_role_is_rejected() -> None:
    network = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens33",
                role="lan",
                ipv4_method="dhcp",
            ),
            NetworkInterfaceConfig(
                name="ens36",
                role="lan",
                ipv4_method="static",
                ipv4_address="192.168.50.1/24",
            ),
        ]
    )

    with pytest.raises(
        FirewallPreflightError,
        match="does not have WAN role",
    ):
        validate_firewall_preflight(
            make_firewall(),
            network,
        )


def test_render_firewall(tmp_path: Path) -> None:
    output = tmp_path / "secbox.nft"

    render_nftables_config(
        make_firewall(),
        output,
    )

    content = output.read_text(
        encoding="utf-8",
    )

    assert "table inet secbox_filter" in content
    assert "ct state established,related accept" in content
    assert 'iifname "ens36" oifname "ens33" accept' in content
    assert "policy drop;" in content


def test_render_nat(tmp_path: Path) -> None:
    output = tmp_path / "secbox.nft"

    config = make_firewall()

    render_nftables_config(
        config,
        output,
    )

    content = output.read_text(
        encoding="utf-8",
    )

    assert "table ip secbox_nat" in content
    assert 'oifname "ens33" iifname "ens36" masquerade' in content


def test_nat_can_be_disabled(tmp_path: Path) -> None:
    output = tmp_path / "secbox.nft"

    config = FirewallConfig(
        wan_interface="ens33",
        lan_interface="ens36",
        enable_nat=False,
    )

    render_nftables_config(
        config,
        output,
    )

    content = output.read_text(
        encoding="utf-8",
    )

    assert "table ip secbox_nat" not in content
