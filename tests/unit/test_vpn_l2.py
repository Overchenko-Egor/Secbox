from pathlib import Path

import pytest
from pydantic import ValidationError

from secbox.modules.vpn.models import (
    L2VpnTunnelConfig,
    VpnConfig,
)


def l2_tunnel(**overrides) -> L2VpnTunnelConfig:
    raw = {
        "name": "branch-l2",
        "enabled": True,
        "transport": {
            "interface": "wg2",
            "address": "10.202.0.2/30",
            "private_key_file": "/etc/secbox/vpn/wg2.key",
            "mtu": 1420,
            "peer": {
                "public_key": "peer-public-key",
                "endpoint": "192.168.1.108:51822",
                "allowed_ips": ["10.202.0.1/32"],
                "persistent_keepalive": 25,
            },
        },
        "bridge": {
            "interface": "br-l2vpn",
            "address": "172.30.0.2/24",
            "ports": [],
        },
        "encapsulation": {
            "interface": "gt-l2vpn",
            "local": "10.202.0.2",
            "remote": "10.202.0.1",
            "mtu": 1376,
            "ttl": 64,
        },
    }

    raw.update(overrides)

    return L2VpnTunnelConfig.model_validate(raw)


def test_l2_tunnel_model_accepts_lab_configuration():
    tunnel = l2_tunnel()

    assert tunnel.transport.interface == "wg2"
    assert tunnel.bridge.interface == "br-l2vpn"
    assert tunnel.encapsulation.interface == "gt-l2vpn"
    assert str(tunnel.encapsulation.remote) == "10.202.0.1"


def test_vpn_can_contain_only_l2_tunnel():
    vpn = VpnConfig(
        enabled=True,
        tunnels=[],
        l2_tunnels=[l2_tunnel()],
    )

    assert vpn.enabled is True
    assert vpn.tunnels == []
    assert len(vpn.l2_tunnels) == 1


def test_empty_enabled_vpn_is_still_rejected():
    with pytest.raises(ValidationError):
        VpnConfig(
            enabled=True,
            tunnels=[],
            l2_tunnels=[],
        )


def test_gretap0_is_reserved():
    raw = l2_tunnel().model_dump(mode="python")
    raw["encapsulation"]["interface"] = "gretap0"

    with pytest.raises(ValidationError):
        L2VpnTunnelConfig.model_validate(raw)


def test_gretap_local_must_match_transport():
    raw = l2_tunnel().model_dump(mode="python")
    raw["encapsulation"]["local"] = "10.202.0.1"
    raw["encapsulation"]["remote"] = "10.202.0.2"

    with pytest.raises(ValidationError):
        L2VpnTunnelConfig.model_validate(raw)


def test_gretap_mtu_must_be_lower_than_transport():
    raw = l2_tunnel().model_dump(mode="python")
    raw["encapsulation"]["mtu"] = 1420

    with pytest.raises(ValidationError):
        L2VpnTunnelConfig.model_validate(raw)


def test_l2_key_path_uses_secbox_key_directory():
    tunnel = l2_tunnel()

    assert tunnel.transport.private_key_file == Path(
        "/etc/secbox/vpn/wg2.key"
    )


def test_l3_and_l2_interfaces_cannot_collide():
    raw = {
        "enabled": True,
        "tunnels": [
            {
                "name": "primary",
                "interface": "wg0",
                "address": "10.200.0.2/30",
                "private_key_file": "/etc/secbox/vpn/wg0.key",
                "priority": 100,
                "routing_table": 200,
                "source_networks": ["192.168.50.0/24"],
                "peer": {
                    "public_key": "l3-peer",
                    "endpoint": "192.168.1.108:51820",
                    "allowed_ips": ["0.0.0.0/0"],
                },
            }
        ],
        "l2_tunnels": [
            l2_tunnel().model_dump(mode="python")
        ],
    }

    raw["l2_tunnels"][0]["transport"]["interface"] = "wg0"

    with pytest.raises(ValidationError):
        VpnConfig.model_validate(raw)
