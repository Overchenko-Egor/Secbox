import pytest

import secbox.web.actions as actions
from secbox.modules.vpn.models import VpnConfig


def vpn() -> VpnConfig:
    return VpnConfig.model_validate(
        {
            "enabled": True,
            "tunnels": [
                {
                    "name": "primary",
                    "interface": "wg0",
                    "address": "10.200.0.2/30",
                    "private_key_file": "/etc/secbox/vpn/wg0.key",
                    "priority": 100,
                    "routing_table": 200,
                    "peer": {
                        "public_key": "peer",
                        "endpoint": "192.0.2.1:51820",
                        "allowed_ips": [
                            "0.0.0.0/0"
                        ],
                    },
                }
            ],
        }
    )


def test_apply_vpn_via_helper_success(
    monkeypatch,
):
    monkeypatch.setattr(
        actions,
        "_exchange",
        lambda request: {
            "ok": True,
            "result": {
                "applied_tunnels": 1,
                "removed_tunnels": 0,
                "active_name": "primary",
                "active_interface": "wg0",
            },
        },
    )

    result = actions.apply_vpn_via_helper(
        vpn()
    )

    assert result.applied_tunnels == 1
    assert result.removed_tunnels == 0
    assert result.active_name == "primary"
    assert result.active_interface == "wg0"


def test_apply_vpn_via_helper_busy(
    monkeypatch,
):
    monkeypatch.setattr(
        actions,
        "_exchange",
        lambda request: {
            "ok": False,
            "error": "busy",
        },
    )

    with pytest.raises(
        actions.WebActionBusyError
    ):
        actions.apply_vpn_via_helper(
            vpn()
        )


def test_apply_vpn_via_helper_failure(
    monkeypatch,
):
    monkeypatch.setattr(
        actions,
        "_exchange",
        lambda request: {
            "ok": False,
            "error": "transaction_failed",
        },
    )

    with pytest.raises(
        actions.WebActionError
    ):
        actions.apply_vpn_via_helper(
            vpn()
        )


def test_apply_vpn_via_helper_timeout(
    monkeypatch,
):
    def timeout(request):
        raise actions.WebActionTimeoutError(
            "timeout"
        )

    monkeypatch.setattr(
        actions,
        "_exchange",
        timeout,
    )

    with pytest.raises(
        actions.WebActionTimeoutError
    ):
        actions.apply_vpn_via_helper(
            vpn()
        )
