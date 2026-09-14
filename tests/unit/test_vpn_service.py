import pytest

import secbox.modules.vpn.service as service
from secbox.core.models import SecBoxConfig
from secbox.modules.vpn.models import VpnConfig
from secbox.modules.vpn.service import (
    VpnServiceError,
    apply_vpn_config,
    reconcile_vpn_config,
)


def config_with_tunnels(
    tunnels,
    *,
    enabled=True,
):
    return SecBoxConfig.model_validate(
        {
            "vpn": {
                "enabled": enabled,
                "tunnels": tunnels,
            }
        }
    )


def tunnel(
    name,
    interface,
    table,
    priority,
    source="192.168.50.0/24",
):
    return {
        "name": name,
        "interface": interface,
        "address": (
            "10.200.0.2/30"
            if interface == "wg0"
            else "10.201.0.2/30"
        ),
        "private_key_file": f"/key-{interface}",
        "priority": priority,
        "routing_table": table,
        "source_networks": (
            [source]
            if source is not None
            else []
        ),
        "peer": {
            "public_key": f"peer-{interface}",
            "endpoint": "192.0.2.1:51820",
            "allowed_ips": [
                "0.0.0.0/0",
            ],
        },
    }


def standard_config():
    return config_with_tunnels(
        [
            tunnel(
                "primary",
                "wg0",
                200,
                100,
            ),
            tunnel(
                "backup",
                "wg1",
                201,
                200,
                source=None,
            ),
        ]
    )


def patch_runtime(
    monkeypatch,
):
    calls = []

    monkeypatch.setattr(
        service,
        "validate_vpn_key_paths",
        lambda config: calls.append(
            ("keys", None)
        ),
    )

    monkeypatch.setattr(
        service,
        "apply_wireguard_tunnel",
        lambda tunnel: calls.append(
            ("apply", tunnel.interface)
        ),
    )

    monkeypatch.setattr(
        service,
        "remove_wireguard_tunnel",
        lambda tunnel, **kwargs: calls.append(
            (
                "remove",
                tunnel.interface,
                kwargs.get(
                    "remove_route",
                    True,
                ),
            )
        ),
    )

    monkeypatch.setattr(
        service,
        "configure_pool_policy",
        lambda tunnels: calls.append(
            (
                "configure_policy",
                [
                    t.interface
                    for t in tunnels
                ],
            )
        ),
    )

    monkeypatch.setattr(
        service,
        "reconcile_pool_policy",
        lambda old, new: calls.append(
            (
                "reconcile_policy",
                [t.interface for t in old],
                [t.interface for t in new],
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

    monkeypatch.setattr(
        service,
        "remove_tunnel_route",
        lambda tunnel: calls.append(
            ("flush_table", tunnel.routing_table)
        ),
    )

    monkeypatch.setattr(
        service,
        "flush_active_table",
        lambda: calls.append(
            ("flush_active", None)
        ),
    )

    return calls


def test_apply_vpn_config_applies_pool(
    monkeypatch,
):
    config = standard_config()
    calls = patch_runtime(
        monkeypatch
    )

    result = apply_vpn_config(
        config
    )

    assert (
        "apply",
        "wg0",
    ) in calls

    assert (
        "apply",
        "wg1",
    ) in calls

    assert (
        "active",
        "wg0",
    ) in calls

    assert result.applied_tunnels == 2
    assert result.active_interface == "wg0"


def test_apply_vpn_config_rejects_disabled_vpn():
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


def test_reconcile_removes_old_tunnel(
    monkeypatch,
):
    previous = standard_config()

    desired = config_with_tunnels(
        [
            tunnel(
                "primary",
                "wg0",
                200,
                100,
            )
        ]
    )

    calls = patch_runtime(
        monkeypatch
    )

    result = reconcile_vpn_config(
        previous,
        desired,
    )

    assert (
        "apply",
        "wg0",
    ) in calls

    assert (
        "active",
        "wg0",
    ) in calls

    assert (
        "remove",
        "wg1",
        True,
    ) in calls

    assert result.removed_tunnels == 1
    assert result.active_interface == "wg0"


def test_reconcile_replaces_backup_interface(
    monkeypatch,
):
    previous = standard_config()

    desired = config_with_tunnels(
        [
            tunnel(
                "primary",
                "wg0",
                200,
                100,
            ),
            tunnel(
                "new-backup",
                "wg2",
                202,
                200,
                source=None,
            ),
        ]
    )

    calls = patch_runtime(
        monkeypatch
    )

    result = reconcile_vpn_config(
        previous,
        desired,
    )

    assert (
        "apply",
        "wg2",
    ) in calls

    assert (
        "remove",
        "wg1",
        True,
    ) in calls

    assert result.applied_tunnels == 2
    assert result.removed_tunnels == 1


def test_reconcile_preserves_reused_routing_table(
    monkeypatch,
):
    previous = config_with_tunnels(
        [
            tunnel(
                "old",
                "wg1",
                201,
                100,
            )
        ]
    )

    desired = config_with_tunnels(
        [
            tunnel(
                "new",
                "wg2",
                201,
                100,
            )
        ]
    )

    calls = patch_runtime(
        monkeypatch
    )

    reconcile_vpn_config(
        previous,
        desired,
    )

    assert (
        "remove",
        "wg1",
        False,
    ) in calls


def test_reconcile_cleans_old_table_when_interface_kept(
    monkeypatch,
):
    previous = config_with_tunnels(
        [
            tunnel(
                "primary",
                "wg0",
                200,
                100,
            )
        ]
    )

    desired = config_with_tunnels(
        [
            tunnel(
                "primary",
                "wg0",
                205,
                100,
            )
        ]
    )

    calls = patch_runtime(
        monkeypatch
    )

    reconcile_vpn_config(
        previous,
        desired,
    )

    assert (
        "flush_table",
        200,
    ) in calls


def test_reconcile_can_disable_vpn(
    monkeypatch,
):
    previous = standard_config()

    desired = SecBoxConfig(
        vpn=VpnConfig(
            enabled=False,
            tunnels=[],
        )
    )

    calls = patch_runtime(
        monkeypatch
    )

    result = reconcile_vpn_config(
        previous,
        desired,
    )

    assert (
        "remove",
        "wg0",
        True,
    ) in calls

    assert (
        "remove",
        "wg1",
        True,
    ) in calls

    assert (
        "flush_active",
        None,
    ) in calls

    assert result.active_interface is None
    assert result.applied_tunnels == 0
    assert result.removed_tunnels == 2
