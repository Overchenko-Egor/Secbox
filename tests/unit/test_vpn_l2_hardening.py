"""Regression tests for L2 VPN access-port hardening."""

from unittest.mock import patch

import pytest

from secbox.core.models import SecBoxConfig
from secbox.modules.vpn.service import reconcile_vpn_config
from secbox.modules.vpn.validator import (
    VpnValidationError,
    validate_l2_access_ports,
)


def make_config(
    *,
    role: str = "l2",
    port: str = "ens37",
    duplicate: bool = False,
) -> SecBoxConfig:
    l2_tunnels = [
        {
            "name": "site-l2",
            "enabled": True,
            "transport": {
                "interface": "wg2",
                "address": "10.202.0.2/30",
                "private_key_file": "/etc/secbox/vpn/wg2.key",
                "mtu": 1420,
                "peer": {
                    "public_key": "A" * 43 + "=",
                    "endpoint": "192.168.1.108:51822",
                    "allowed_ips": ["10.202.0.1/32"],
                    "persistent_keepalive": 25,
                },
            },
            "bridge": {
                "interface": "br-l2vpn",
                "address": "172.30.0.2/24",
                "ports": [port],
            },
            "encapsulation": {
                "interface": "gt-l2vpn",
                "local": "10.202.0.2",
                "remote": "10.202.0.1",
                "mtu": 1376,
                "ttl": 64,
            },
        }
    ]

    if duplicate:
        second = {
            "name": "site-l2-backup",
            "enabled": True,
            "transport": {
                "interface": "wg3",
                "address": "10.203.0.2/30",
                "private_key_file": "/etc/secbox/vpn/wg3.key",
                "mtu": 1420,
                "peer": {
                    "public_key": "B" * 43 + "=",
                    "endpoint": "192.168.1.109:51823",
                    "allowed_ips": ["10.203.0.1/32"],
                    "persistent_keepalive": 25,
                },
            },
            "bridge": {
                "interface": "br-l2vpn2",
                "address": "172.30.1.2/24",
                "ports": [port],
            },
            "encapsulation": {
                "interface": "gt-l2vpn2",
                "local": "10.203.0.2",
                "remote": "10.203.0.1",
                "mtu": 1376,
                "ttl": 64,
            },
        }
        l2_tunnels.append(second)

    return SecBoxConfig.model_validate(
        {
            "network": {
                "interfaces": [
                    {
                        "name": port,
                        "role": role,
                        "ipv4_method": "disabled",
                    }
                ]
            },
            "vpn": {
                "enabled": True,
                "tunnels": [],
                "l2_tunnels": l2_tunnels,
            },
        }
    )


def test_l2_access_port_with_l2_role_is_accepted() -> None:
    validate_l2_access_ports(make_config())


def test_l2_access_port_requires_l2_role() -> None:
    config = make_config(role="lan")

    with pytest.raises(
        VpnValidationError,
        match="must have role 'l2'",
    ):
        validate_l2_access_ports(config)


def test_l2_access_port_cannot_be_shared() -> None:
    config = make_config(duplicate=True)

    with pytest.raises(
        VpnValidationError,
        match="multiple tunnels",
    ):
        validate_l2_access_ports(config)


def test_l2_access_port_must_exist_in_network_config() -> None:
    config = make_config()

    config.network.interfaces = []

    with pytest.raises(
        VpnValidationError,
        match="not present in network configuration",
    ):
        validate_l2_access_ports(config)


def test_reconcile_detaches_stale_l2_port() -> None:
    previous = make_config(port="ens37")
    desired = make_config(port="ens39")

    # desired already contains ens39 as a configured L2 physical port.
    with (
        patch(
            "secbox.modules.vpn.service.apply_l2_vpn_tunnel"
        ),
        patch(
            "secbox.modules.vpn.service.subprocess.run"
        ) as run,
    ):
        reconcile_vpn_config(
            previous,
            desired,
            validate_keys=False,
        )

    assert any(
        call.args[0]
        == [
            "/usr/sbin/ip",
            "link",
            "set",
            "dev",
            "ens37",
            "nomaster",
        ]
        for call in run.call_args_list
    )
