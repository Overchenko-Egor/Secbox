from types import SimpleNamespace

import ipaddress

import pytest

from secbox.actions import deception


def test_reason_rejects_control_chars():
    with pytest.raises(
        deception.DeceptionActionError
    ):
        deception._sanitize_reason(
            "bad\nreason"
        )


def test_protected_source_rejected(
    monkeypatch,
):
    config = SimpleNamespace()

    monkeypatch.setattr(
        deception,
        "discover_interfaces",
        lambda: [],
    )

    monkeypatch.setattr(
        deception,
        "build_protected_networks",
        lambda config, interfaces: (
            ipaddress.ip_network(
                "192.168.100.0/24"
            ),
        ),
    )

    with pytest.raises(
        deception.DeceptionActionError,
        match="protected",
    ):
        deception._validate_source(
            source_ip="192.168.100.2",
            config=config,
        )


def test_external_source_allowed(
    monkeypatch,
):
    config = SimpleNamespace()

    monkeypatch.setattr(
        deception,
        "discover_interfaces",
        lambda: [],
    )

    monkeypatch.setattr(
        deception,
        "build_protected_networks",
        lambda config, interfaces: (
            ipaddress.ip_network(
                "192.168.100.0/24"
            ),
        ),
    )

    result = (
        deception._validate_source(
            source_ip="203.0.113.10",
            config=config,
        )
    )

    assert result == (
        "203.0.113.10"
    )
