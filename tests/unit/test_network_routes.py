import json
import subprocess

from pytest import MonkeyPatch

from secbox.modules.network.routes import discover_ipv4_routes


def fake_route_output() -> str:
    return json.dumps(
        [
            {
                "dst": "default",
                "gateway": "192.168.1.1",
                "dev": "ens33",
                "protocol": "dhcp",
                "prefsrc": "192.168.1.63",
                "metric": 1024,
            },
            {
                "dst": "192.168.50.0/24",
                "dev": "ens36",
                "protocol": "kernel",
                "prefsrc": "192.168.50.1",
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
        stdout=fake_route_output(),
        stderr="",
    )


def test_discover_ipv4_routes(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    routes = discover_ipv4_routes()

    assert len(routes) == 2

    default_route = routes[0]

    assert default_route.destination == "default"
    assert default_route.gateway == "192.168.1.1"
    assert default_route.interface == "ens33"
    assert default_route.metric == 1024


def test_connected_route_is_discovered(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    routes = discover_ipv4_routes()

    lan_route = routes[1]

    assert lan_route.destination == "192.168.50.0/24"
    assert lan_route.interface == "ens36"
