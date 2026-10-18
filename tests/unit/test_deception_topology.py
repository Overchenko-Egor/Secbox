import pytest

from secbox.modules.deception import topology


def test_enterprise_inventory_valid():
    topology.validate_inventory()

    assert len(
        topology.ENTERPRISE_HOSTS
    ) == 9


def test_shadow_ranges_only():
    for address in topology.addresses():
        assert address.startswith(
            (
                "10.61.",
                "10.62.",
                "10.63.",
            )
        )


def test_inventory_addresses_unique():
    values = topology.addresses()

    assert len(values) == len(
        set(values)
    )


def test_host_lookup():
    host = topology.get_host(
        "10.61.21.34"
    )

    assert host is not None
    assert (
        host.hostname
        == "gitlab.corp.local"
    )
    assert 22 in host.services
    assert 443 in host.services


def test_unknown_host_returns_none():
    assert topology.get_host(
        "10.61.99.99"
    ) is None


def test_reject_host_outside_shadow_ranges():
    invalid = (
        topology.FakeHost(
            address="192.168.50.20",
            hostname="real.corp.local",
            role="bad",
            os_family="linux",
            services=(22,),
        ),
    )

    with pytest.raises(
        topology.DeceptionTopologyError,
        match="outside shadow ranges",
    ):
        topology.validate_inventory(
            invalid
        )


def test_no_real_secbox_ranges_present():
    forbidden_prefixes = (
        "192.168.1.",
        "192.168.50.",
        "192.168.100.",
        "10.200.",
        "10.201.",
        "10.202.",
        "10.250.",
        "172.30.",
    )

    for address in topology.addresses():
        assert not address.startswith(
            forbidden_prefixes
        )
