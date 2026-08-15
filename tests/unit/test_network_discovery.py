import json
import subprocess

from pytest import MonkeyPatch

from secbox.modules.network.discovery import (
    discover_interfaces,
    discover_manageable_interfaces,
)


def fake_ip_output() -> str:
    return json.dumps(
        [
            {
                "ifindex": 1,
                "ifname": "lo",
                "flags": [
                    "LOOPBACK",
                    "UP",
                    "LOWER_UP",
                ],
                "mtu": 65536,
                "operstate": "UNKNOWN",
                "address": "00:00:00:00:00:00",
                "addr_info": [
                    {
                        "family": "inet",
                        "local": "127.0.0.1",
                        "prefixlen": 8,
                        "scope": "host",
                    }
                ],
            },
            {
                "ifindex": 2,
                "ifname": "ens33",
                "flags": [
                    "BROADCAST",
                    "MULTICAST",
                    "UP",
                    "LOWER_UP",
                ],
                "mtu": 1500,
                "operstate": "UP",
                "address": "00:0c:29:aa:8c:0d",
                "addr_info": [],
            },
            {
                "ifindex": 3,
                "ifname": "ens38",
                "flags": [
                    "BROADCAST",
                    "MULTICAST",
                    "UP",
                    "LOWER_UP",
                ],
                "mtu": 1500,
                "operstate": "UP",
                "address": "00:0c:29:aa:8c:2b",
                "addr_info": [
                    {
                        "family": "inet",
                        "local": "192.168.1.92",
                        "prefixlen": 24,
                        "scope": "global",
                    }
                ],
            },
        ]
    )


def fake_run(
    *args: object,
    **kwargs: object,
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["ip"],
        returncode=0,
        stdout=fake_ip_output(),
        stderr="",
    )


def test_discover_interfaces(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    interfaces = discover_interfaces()

    assert len(interfaces) == 3
    assert interfaces[0].name == "lo"
    assert interfaces[1].name == "ens33"
    assert interfaces[2].name == "ens38"


def test_discover_manageable_interfaces(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    interfaces = discover_manageable_interfaces()

    assert len(interfaces) == 2
    assert [interface.name for interface in interfaces] == [
        "ens33",
        "ens38",
    ]


def test_interface_ipv4_address(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    interfaces = discover_manageable_interfaces()

    ens38 = next(
        interface
        for interface in interfaces
        if interface.name == "ens38"
    )

    assert len(ens38.addresses) == 1
    assert ens38.addresses[0].address == "192.168.1.92"
    assert ens38.addresses[0].prefixlen == 24
