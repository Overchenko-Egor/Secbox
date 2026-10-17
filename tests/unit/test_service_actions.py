import subprocess

import pytest

from secbox.actions import services


def _result(
    stdout: str = "",
    returncode: int = 0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=[],
        returncode=returncode,
        stdout=stdout,
        stderr="",
    )


def test_unknown_service_is_rejected():
    with pytest.raises(
        services.ServiceActionError
    ):
        services.service_action(
            "sshd.service",
            "restart",
        )


def test_web_service_cannot_be_restarted():
    with pytest.raises(
        services.ServiceActionError
    ):
        services.service_action(
            "secbox-web.service",
            "restart",
        )


def test_firewall_cannot_be_stopped():
    with pytest.raises(
        services.ServiceActionError
    ):
        services.service_action(
            "secbox-firewall.service",
            "stop",
        )


def test_doh_inactive_dead_is_idle(monkeypatch):
    def fake_systemctl(
        arguments,
        *,
        timeout=30.0,
    ):
        return _result(
            stdout=(
                "Description=SecBox Managed DoH Feed Update\n"
                "LoadState=loaded\n"
                "ActiveState=inactive\n"
                "SubState=dead\n"
                "UnitFileState=static\n"
            )
        )

    monkeypatch.setattr(
        services,
        "_systemctl",
        fake_systemctl,
    )

    state = services.get_service_status(
        "secbox-doh-feed.service"
    )

    assert state["health"] == "idle"


def test_restart_allowed_service(monkeypatch):
    calls = []

    def fake_systemctl(
        arguments,
        *,
        timeout=30.0,
    ):
        calls.append(arguments)

        if arguments[0] == "restart":
            return _result()

        return _result(
            stdout=(
                "Description=Suricata\n"
                "LoadState=loaded\n"
                "ActiveState=active\n"
                "SubState=running\n"
                "UnitFileState=enabled\n"
            )
        )

    monkeypatch.setattr(
        services,
        "_systemctl",
        fake_systemctl,
    )

    state = services.service_action(
        "suricata.service",
        "restart",
    )

    assert calls[0] == [
        "restart",
        "suricata.service",
    ]

    assert state["active_state"] == "active"
