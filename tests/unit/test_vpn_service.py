from pathlib import Path

import pytest

import secbox.modules.vpn.service as service
from secbox.core.models import SecBoxConfig
from secbox.modules.vpn.models import VpnConfig
from secbox.modules.vpn.service import (
    VpnServiceError,
    apply_vpn_config,
)


def vpn_config() -> SecBoxConfig:
    return SecBoxConfig.model_validate(
        {
            "vpn": {
                "enabled": True,
                "tunnels": [
                    {
                        "name": "primary",
                        "interface": "wg0",
                        "address": "10.200.0.2/30",
                        "private_key_file": "/key0",
                        "priority": 100,
                        "routing_table": 200,
                        "source_networks": [
                            "192.168.50.0/24"
                        ],
                        "peer": {
                            "public_key": "peer0",
                            "endpoint": "192.0.2.1:51820",
                            "allowed_ips": [
                                "0.0.0.0/0"
                            ],
                        },
                    },
                    {
                        "name": "backup",
                        "interface": "wg1",
                        "address": "10.201.0.2/30",
                        "private_key_file": "/key1",
                        "priority": 200,
                        "routing_table": 201,
                        "source_networks": [],
                        "peer": {
                            "public_key": "peer1",
                            "endpoint": "192.0.2.2:51821",
                            "allowed_ips": [
                                "0.0.0.0/0"
                            ],
                        },
                    },
                ],
            }
        }
    )


def test_apply_vpn_config_applies_pool(
    monkeypatch,
) -> None:
    config = vpn_config()
    calls: list[tuple[str, object]] = []

    monkeypatch.setattr(
        service,
        "validate_vpn_key_paths",
        lambda config: calls.append(("keys", config)),
    )

    monkeypatch.setattr(
        service,
        "apply_wireguard_tunnel",
        lambda tunnel: calls.append(
            ("tunnel", tunnel.interface)
        ),
    )

    monkeypatch.setattr(
        service,
        "configure_pool_policy",
        lambda tunnels: calls.append(
            (
                "policy",
                [tunnel.interface for tunnel in tunnels],
            )
        ),
    )

    monkeypatch.setattr(
        service,
        "activate_tunnel",
        lambda tunnel: calls.append(
            ("active", tunnel.interface)
        ),
    )

    result = apply_vpn_config(config)

    assert ("tunnel", "wg0") in calls
    assert ("tunnel", "wg1") in calls
    assert ("policy", ["wg0", "wg1"]) in calls
    assert ("active", "wg0") in calls

    assert result.applied_tunnels == 2
    assert result.active_name == "primary"
    assert result.active_interface == "wg0"


def test_apply_vpn_config_uses_priority(
    monkeypatch,
) -> None:
    config = vpn_config()

    primary = config.vpn.tunnels[0]
    backup = config.vpn.tunnels[1]

    primary.priority = 300
    backup.priority = 50

    activated: list[str] = []

    monkeypatch.setattr(
        service,
        "validate_vpn_key_paths",
        lambda config: None,
    )
    monkeypatch.setattr(
        service,
        "apply_wireguard_tunnel",
        lambda tunnel: None,
    )
    monkeypatch.setattr(
        service,
        "configure_pool_policy",
        lambda tunnels: None,
    )
    monkeypatch.setattr(
        service,
        "activate_tunnel",
        lambda tunnel: activated.append(
            tunnel.interface
        ),
    )

    result = apply_vpn_config(config)

    assert activated == ["wg1"]
    assert result.active_interface == "wg1"


def test_apply_vpn_config_rejects_disabled_vpn() -> None:
    config = SecBoxConfig(
        vpn=VpnConfig(
            enabled=False,
            tunnels=[],
        )
    )

    with pytest.raises(
        VpnServiceError,
        match="VPN is disabled",
    ):
        apply_vpn_config(
            config,
            validate_keys=False,
        )
