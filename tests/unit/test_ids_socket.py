import pytest

from secbox.actions import ids_socket


def test_rejects_generic_action():
    with pytest.raises(
        ValueError,
        match="unsupported IDS action",
    ):
        ids_socket.handle(
            {
                "action":
                    "get-system-runtime",
            }
        )


def test_runtime_config_action(
    monkeypatch,
):
    monkeypatch.setattr(
        ids_socket,
        "get_ids_runtime_config_action",
        lambda: {
            "ids": {
                "enabled": True,
            }
        },
    )

    result = ids_socket.handle(
        {
            "action":
                "get-ids-runtime-config",
        }
    )

    assert result == {
        "ok": True,
        "result": {
            "config": {
                "ids": {
                    "enabled": True,
                }
            }
        },
    }


def test_blackhole_action(
    monkeypatch,
):
    observed = {}

    def fake_action(
        *,
        address,
        signature_id,
        severity,
        count,
    ):
        observed.update(
            {
                "address":
                    address,
                "signature_id":
                    signature_id,
                "severity":
                    severity,
                "count":
                    count,
            }
        )

        return {
            "address":
                address,
        }

    monkeypatch.setattr(
        ids_socket,
        "add_ids_blackhole_action",
        fake_action,
    )

    result = ids_socket.handle(
        {
            "action":
                "ids-blackhole-add",
            "address":
                "203.0.113.50",
            "signature_id":
                100001,
            "severity":
                1,
            "count":
                5,
        }
    )

    assert result["ok"] is True

    assert observed == {
        "address":
            "203.0.113.50",
        "signature_id":
            100001,
        "severity":
            1,
        "count":
            5,
    }
