from unittest.mock import Mock

from fastapi.testclient import TestClient

from secbox.modules.network.models import (
    NetworkConfig,
    NetworkInterfaceConfig,
)
from secbox.web.actions import WebNetworkDhcpApplyResult


def sample_network():
    return NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens38",
                role="mgmt",
                ipv4_method="static",
                ipv4_address="192.168.100.2/24",
            ),
        ]
    )


def test_network_config_model_import():
    from secbox.web.network_dhcp_config import (
        NetworkDhcpConfigPayload,
    )

    payload = NetworkDhcpConfigPayload(
        network=sample_network(),
        dhcp=[],
    )

    assert payload.network.interfaces[0].name == "ens38"
    assert payload.dhcp == []


def test_network_dhcp_result_model():
    result = WebNetworkDhcpApplyResult(
        interfaces=4,
        dhcp_scopes=2,
        enabled_dhcp_scopes=2,
    )

    assert result.interfaces == 4
    assert result.dhcp_scopes == 2
    assert result.enabled_dhcp_scopes == 2
