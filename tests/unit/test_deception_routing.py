import pytest

from secbox.modules.deception import routing


def test_policy_rule_uses_dedicated_table():
    command = (
        routing.policy_rule_add_command()
    )

    assert "260" in command
    assert "0x400/0x400" in command
    assert "80" in command


def test_default_route_goes_to_namespace():
    command = (
        routing.quarantine_default_route_command()
    )

    assert "10.250.0.2" in command
    assert "veth-dec-host" in command
    assert "260" in command


def test_fail_closed_route_exists():
    command = (
        routing.fail_closed_route_command()
    )

    assert "blackhole" in command
    assert "260" in command
    assert "default" in command


def test_namespace_source_route():
    command = (
        routing.namespace_source_route_add_command(
            "203.0.113.7"
        )
    )

    assert "203.0.113.7/32" in command
    assert "10.250.0.1" in command
    assert "secbox-deception" in command


def test_management_interface_rejected():
    with pytest.raises(
        routing.DeceptionRoutingError,
        match="management",
    ):
        routing.validate_ingress_interfaces(
            [
                "ens33",
                "ens38",
            ]
        )


def test_supported_interfaces_are_preserved():
    result = (
        routing.validate_ingress_interfaces(
            [
                "ens33",
                "ens36",
                "wg0",
                "wg1",
                "wg2",
            ]
        )
    )

    assert result == [
        "ens33",
        "ens36",
        "wg0",
        "wg1",
        "wg2",
    ]


def test_duplicates_removed():
    result = (
        routing.validate_ingress_interfaces(
            [
                "ens33",
                "ens33",
                "wg0",
            ]
        )
    )

    assert result == [
        "ens33",
        "wg0",
    ]


def test_ipv6_source_rejected():
    with pytest.raises(
        routing.DeceptionRoutingError,
        match="only IPv4",
    ):
        routing.namespace_source_route_add_command(
            "2001:db8::10"
        )
