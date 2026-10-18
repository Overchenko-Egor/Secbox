from secbox.modules.deception import (
    network,
)


def test_constants():
    assert (
        network.NAMESPACE
        == "secbox-deception"
    )

    assert (
        network.HOST_INTERFACE
        == "veth-dec-host"
    )

    assert (
        network.NAMESPACE_ADDRESS
        == "10.250.0.2/24"
    )


def test_link_exists_uses_fixed_ip(
    monkeypatch,
):
    observed = []

    class Result:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(
        argv,
        **kwargs,
    ):
        observed.append(
            argv
        )

        return Result()

    monkeypatch.setattr(
        network.subprocess,
        "run",
        fake_run,
    )

    assert (
        network.link_exists(
            "veth-dec-host"
        )
        is True
    )

    assert observed == [
        [
            "/usr/bin/ip",
            "link",
            "show",
            "dev",
            "veth-dec-host",
        ]
    ]


def test_verify_rejects_default_route(
    monkeypatch,
):
    monkeypatch.setattr(
        network,
        "namespace_exists",
        lambda: True,
    )

    monkeypatch.setattr(
        network,
        "link_exists",
        lambda name: True,
    )

    monkeypatch.setattr(
        network,
        "routes",
        lambda: [
            {
                "dst":
                    "10.250.0.0/24",
            },
            {
                "dst":
                    "default",
            },
        ],
    )

    try:
        network.verify()

    except network.DeceptionNetworkError as error:
        assert (
            "default route"
            in str(error)
        )

    else:
        raise AssertionError(
            "default route was accepted"
        )


def test_verify_accepts_connected_route_only(
    monkeypatch,
):
    monkeypatch.setattr(
        network,
        "namespace_exists",
        lambda: True,
    )

    monkeypatch.setattr(
        network,
        "link_exists",
        lambda name: True,
    )

    monkeypatch.setattr(
        network,
        "routes",
        lambda: [
            {
                "dst":
                    "10.250.0.0/24",
            }
        ],
    )

    network.verify()
