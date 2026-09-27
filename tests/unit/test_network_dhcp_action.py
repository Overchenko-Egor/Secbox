from pathlib import Path

import pytest

from secbox.actions import network_dhcp as action
from secbox.core.config_store import ConfigStore
from secbox.core.models import SecBoxConfig
from secbox.modules.dhcp.models import DhcpServerConfig
from secbox.modules.network.models import (
    NetworkConfig,
    NetworkInterfaceConfig,
)


def make_network(address: str) -> NetworkConfig:
    return NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens38",
                role="mgmt",
                ipv4_method="static",
                ipv4_address=address,
            ),
        ]
    )


def make_dhcp() -> list[DhcpServerConfig]:
    return []


def make_store(tmp_path: Path) -> ConfigStore:
    store = ConfigStore(
        tmp_path / "config.yml"
    )

    store.save(
        SecBoxConfig(
            network=make_network(
                "192.168.100.2/24"
            ),
            dhcp=[],
        )
    )

    return store


def test_get_network_dhcp(
    tmp_path: Path,
):
    store = make_store(tmp_path)

    network, dhcp = (
        action.get_network_dhcp_action(
            store=store
        )
    )

    assert network.interfaces[0].name == "ens38"
    assert dhcp == []


def test_successful_transaction(
    tmp_path: Path,
    monkeypatch,
):
    store = make_store(tmp_path)

    new_network = make_network(
        "192.168.100.3/24"
    )

    monkeypatch.setattr(
        action,
        "_validate_candidate",
        lambda candidate: None,
    )

    calls = []

    monkeypatch.setattr(
        action,
        "_apply_network",
        lambda network: calls.append(
            ("network", str(
                network.interfaces[0].ipv4_address
            ))
        ),
    )

    monkeypatch.setattr(
        action,
        "_apply_dhcp",
        lambda candidate: calls.append(
            ("dhcp", len(candidate.dhcp))
        ),
    )

    class FakeRuntimeStore:
        def save(self, metadata):
            calls.append(
                ("metadata", True)
            )

    monkeypatch.setattr(
        action,
        "NetworkRuntimeStore",
        FakeRuntimeStore,
    )

    result = action.apply_network_dhcp_action(
        new_network,
        make_dhcp(),
        store=store,
    )

    assert (
        str(
            store.load()
            .network
            .interfaces[0]
            .ipv4_address
        )
        == "192.168.100.3/24"
    )

    assert result.interfaces == 1
    assert result.dhcp_scopes == 0

    assert calls[0][0] == "network"
    assert calls[1][0] == "dhcp"


def test_dhcp_failure_restores_previous_config_and_runtime(
    tmp_path: Path,
    monkeypatch,
):
    store = make_store(tmp_path)

    new_network = make_network(
        "192.168.100.3/24"
    )

    monkeypatch.setattr(
        action,
        "_validate_candidate",
        lambda candidate: None,
    )

    applied_networks = []

    def fake_network(network):
        applied_networks.append(
            str(
                network.interfaces[0]
                .ipv4_address
            )
        )

    monkeypatch.setattr(
        action,
        "_apply_network",
        fake_network,
    )

    state = {
        "dhcp_calls": 0,
    }

    def fake_dhcp(candidate):
        state["dhcp_calls"] += 1

        if state["dhcp_calls"] == 1:
            raise RuntimeError(
                "simulated DHCP failure"
            )

    monkeypatch.setattr(
        action,
        "_apply_dhcp",
        fake_dhcp,
    )

    class FakeRuntimeStore:
        def save(self, metadata):
            pass

    monkeypatch.setattr(
        action,
        "NetworkRuntimeStore",
        FakeRuntimeStore,
    )

    with pytest.raises(
        action.NetworkDhcpActionError,
        match="simulated DHCP failure",
    ):
        action.apply_network_dhcp_action(
            new_network,
            [],
            store=store,
        )

    restored = store.load()

    assert (
        str(
            restored.network
            .interfaces[0]
            .ipv4_address
        )
        == "192.168.100.2/24"
    )

    assert applied_networks == [
        "192.168.100.3/24",
        "192.168.100.2/24",
    ]


def test_validation_failure_does_not_change_config(
    tmp_path: Path,
    monkeypatch,
):
    store = make_store(tmp_path)

    before = store.config_path.read_bytes()

    def fail(candidate):
        raise RuntimeError(
            "bad candidate"
        )

    monkeypatch.setattr(
        action,
        "_validate_candidate",
        fail,
    )

    with pytest.raises(
        action.NetworkDhcpActionError,
        match="bad candidate",
    ):
        action.apply_network_dhcp_action(
            make_network(
                "192.168.100.3/24"
            ),
            [],
            store=store,
        )

    assert store.config_path.read_bytes() == before


def test_network_dhcp_handler_returns_transaction_detail(
    monkeypatch,
):
    from secbox.actions import cli
    from secbox.actions.network_dhcp import (
        NetworkDhcpActionError,
    )

    def fail(*args, **kwargs):
        raise NetworkDhcpActionError(
            "Network/DHCP apply failed: TEST_FAILURE; "
            "previous configuration restored"
        )

    monkeypatch.setattr(
        cli,
        "_execute_network_dhcp",
        fail,
    )

    response, code = cli._handle_network_dhcp(
        {},
        [],
    )

    assert code != 0
    assert response["ok"] is False
    assert response["error"] == "transaction_failed"
    assert "TEST_FAILURE" in response["detail"]
