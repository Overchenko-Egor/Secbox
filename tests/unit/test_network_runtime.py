from pathlib import Path

import pytest

from secbox.modules.network.models import (
    NetworkConfig,
    NetworkInterfaceConfig,
)
from secbox.modules.network.runtime import (
    NetworkRuntimeError,
    NetworkRuntimeStore,
    build_network_status,
    metadata_from_config,
)
from secbox.modules.network.state import (
    NetworkAddress,
    NetworkInterfaceState,
)


def runtime_interface(
    name: str,
    operstate: str,
    ipv4: str | None = None,
) -> NetworkInterfaceState:
    addresses: list[NetworkAddress] = []

    if ipv4 is not None:
        addresses.append(
            NetworkAddress(
                family="inet",
                address=ipv4,
                prefixlen=24,
                scope="global",
            )
        )

    return NetworkInterfaceState(
        name=name,
        mac="00:11:22:33:44:55",
        mtu=1500,
        operstate=operstate,
        flags=[],
        addresses=addresses,
        is_loopback=False,
    )


def network_config() -> NetworkConfig:
    return NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens33",
                role="wan",
                ipv4_method="dhcp",
            ),
            NetworkInterfaceConfig(
                name="ens36",
                role="lan",
                ipv4_method="static",
                ipv4_address="192.168.50.1/24",
            ),
            NetworkInterfaceConfig(
                name="ens37",
                role="unused",
                ipv4_method="disabled",
            ),
        ]
    )


def test_metadata_contains_only_safe_fields() -> None:
    metadata = metadata_from_config(network_config())

    assert metadata.model_dump() == {
        "interfaces": [
            {
                "name": "ens33",
                "role": "wan",
                "ipv4_method": "dhcp",
            },
            {
                "name": "ens36",
                "role": "lan",
                "ipv4_method": "static",
            },
            {
                "name": "ens37",
                "role": "unused",
                "ipv4_method": "disabled",
            },
        ]
    }


def test_runtime_store_round_trip(
    tmp_path: Path,
) -> None:
    store = NetworkRuntimeStore(
        tmp_path / "network-runtime.json"
    )

    expected = metadata_from_config(network_config())

    store.save(expected)

    assert store.load() == expected


def test_missing_runtime_returns_none(
    tmp_path: Path,
) -> None:
    store = NetworkRuntimeStore(
        tmp_path / "missing.json"
    )

    assert store.load() is None


def test_corrupt_runtime_is_rejected(
    tmp_path: Path,
) -> None:
    path = tmp_path / "network-runtime.json"
    path.write_text("{broken", encoding="utf-8")

    store = NetworkRuntimeStore(path)

    with pytest.raises(NetworkRuntimeError):
        store.load()


def test_status_merges_roles_with_live_state() -> None:
    metadata = metadata_from_config(network_config())

    status = build_network_status(
        metadata,
        [
            runtime_interface(
                "ens33",
                "UP",
                "192.168.1.63",
            ),
            runtime_interface(
                "ens36",
                "UP",
                "192.168.50.1",
            ),
            runtime_interface(
                "ens37",
                "DOWN",
            ),
            runtime_interface(
                "wg0",
                "UNKNOWN",
                "10.200.0.2",
            ),
        ],
    )

    assert len(status.interfaces) == 3

    assert status.interfaces[0].role == "wan"
    assert status.interfaces[0].operstate == "UP"
    assert status.interfaces[0].addresses == [
        "192.168.1.63/24"
    ]

    assert status.interfaces[1].role == "lan"
    assert status.interfaces[1].configured is True

    assert status.interfaces[2].role == "unused"
    assert status.interfaces[2].configured is False
    assert status.interfaces[2].operstate == "DOWN"


def test_missing_managed_interface_is_reported() -> None:
    metadata = metadata_from_config(network_config())

    status = build_network_status(
        metadata,
        [],
    )

    assert status.interfaces[0].operstate == "MISSING"
    assert status.interfaces[0].addresses == []
