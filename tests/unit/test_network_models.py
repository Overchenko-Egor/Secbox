from ipaddress import IPv4Interface

import pytest
from pydantic import ValidationError

from secbox.modules.network.models import (
    NetworkConfig,
    NetworkInterfaceConfig,
)


def test_dhcp_interface_is_valid() -> None:
    interface = NetworkInterfaceConfig(
        name="ens33",
        role="wan",
        ipv4_method="dhcp",
    )

    assert interface.name == "ens33"
    assert interface.role == "wan"
    assert interface.ipv4_address is None


def test_static_interface_is_valid() -> None:
    interface = NetworkInterfaceConfig(
        name="ens36",
        role="lan",
        ipv4_method="static",
        ipv4_address="192.168.50.1/24",
    )

    assert interface.ipv4_address == IPv4Interface("192.168.50.1/24")


def test_static_interface_requires_address() -> None:
    with pytest.raises(ValidationError):
        NetworkInterfaceConfig(
            name="ens36",
            role="lan",
            ipv4_method="static",
        )


def test_dhcp_interface_rejects_static_address() -> None:
    with pytest.raises(ValidationError):
        NetworkInterfaceConfig(
            name="ens33",
            role="wan",
            ipv4_method="dhcp",
            ipv4_address="192.168.1.10/24",
        )


def test_loopback_interface_is_rejected() -> None:
    with pytest.raises(ValidationError):
        NetworkInterfaceConfig(
            name="lo",
            role="mgmt",
            ipv4_method="dhcp",
        )


def test_duplicate_interface_names_are_rejected() -> None:
    with pytest.raises(ValidationError):
        NetworkConfig(
            interfaces=[
                NetworkInterfaceConfig(
                    name="ens33",
                    role="wan",
                    ipv4_method="dhcp",
                ),
                NetworkInterfaceConfig(
                    name="ens33",
                    role="lan",
                    ipv4_method="static",
                    ipv4_address="192.168.50.1/24",
                ),
            ]
        )


def test_empty_network_config_is_valid() -> None:
    config = NetworkConfig()

    assert config.interfaces == []
