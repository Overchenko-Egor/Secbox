from pathlib import Path

import pytest
from pydantic import ValidationError

from secbox.core.models import SecBoxConfig
from secbox.modules.vpn.models import (
    VpnConfig,
    WireGuardPeerConfig,
    WireGuardTunnelConfig,
)
from secbox.modules.vpn.renderer import (
    render_wireguard_config,
)
from secbox.modules.vpn.validator import (
    VpnValidationError,
    validate_vpn_config,
)


def make_tunnel(**overrides):
    values = {
        "name": "primary",
        "enabled": True,
        "interface": "wg0",
        "address": "10.200.0.2/32",
        "private_key_file": "/etc/secbox/vpn/wg0.key",
        "mtu": 1420,
        "priority": 100,
        "routing_table": 200,
        "peer": {
            "public_key": "server-public-key",
            "endpoint": "198.51.100.10:51820",
            "allowed_ips": ["0.0.0.0/0"],
            "persistent_keepalive": 25,
        },
    }

    values.update(overrides)

    return WireGuardTunnelConfig(**values)


def test_vpn_requires_tunnel_when_enabled():
    with pytest.raises(
        ValidationError,
        match="at least one tunnel",
    ):
        VpnConfig(
            enabled=True,
            tunnels=[],
        )


def test_vpn_rejects_duplicate_interfaces():
    first = make_tunnel()

    second = make_tunnel(
        name="backup",
        routing_table=201,
    )

    with pytest.raises(
        ValidationError,
        match="interfaces must be unique",
    ):
        VpnConfig(
            enabled=True,
            tunnels=[first, second],
        )


def test_vpn_rejects_duplicate_routing_tables():
    first = make_tunnel()

    second = make_tunnel(
        name="backup",
        interface="wg1",
    )

    with pytest.raises(
        ValidationError,
        match="routing tables must be unique",
    ):
        VpnConfig(
            enabled=True,
            tunnels=[first, second],
        )


def test_vpn_interface_must_not_conflict_with_physical():
    config = SecBoxConfig.model_validate(
        {
            "network": {
                "interfaces": [
                    {
                        "name": "wg0",
                        "role": "wan",
                        "ipv4_method": "dhcp",
                    }
                ]
            },
            "vpn": {
                "enabled": True,
                "tunnels": [
                    make_tunnel().model_dump(
                        mode="json"
                    )
                ],
            },
        }
    )

    with pytest.raises(
        VpnValidationError,
        match="conflicts",
    ):
        validate_vpn_config(config)


def test_wireguard_renderer(tmp_path):
    output = tmp_path / "wg0.conf"

    render_wireguard_config(
        make_tunnel(),
        output,
    )

    rendered = output.read_text(
        encoding="utf-8",
    )

    assert "[Interface]" in rendered
    assert "Address = 10.200.0.2/32" in rendered
    assert "Table = off" in rendered
    assert "MTU = 1420" in rendered

    assert "[Peer]" in rendered
    assert "AllowedIPs = 0.0.0.0/0" in rendered
    assert "Endpoint = 198.51.100.10:51820" in rendered
    assert "PersistentKeepalive = 25" in rendered

    assert (
        "PrivateKey = "
        "<loaded-from:/etc/secbox/vpn/wg0.key>"
        in rendered
    )

    assert "server-public-key" in rendered


def test_wireguard_allowed_ips_cannot_be_empty():
    with pytest.raises(
        ValidationError,
        match="at least one allowed IP",
    ):
        WireGuardPeerConfig(
            public_key="server-key",
            endpoint="198.51.100.10:51820",
            allowed_ips=[],
        )


def test_private_key_path_must_be_absolute():
    config = SecBoxConfig(
        vpn=VpnConfig(
            enabled=True,
            tunnels=[
                make_tunnel(
                    private_key_file=Path(
                        "wg0.key"
                    )
                )
            ],
        )
    )

    with pytest.raises(
        VpnValidationError,
        match="must be absolute",
    ):
        validate_vpn_config(config)
