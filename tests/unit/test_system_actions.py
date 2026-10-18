import subprocess

import pytest

from secbox.actions import system


def test_power_rejects_wrong_confirmation(
    monkeypatch,
) -> None:
    called = False

    def fake_popen(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError(
            "Popen must not be called"
        )

    monkeypatch.setattr(
        system.subprocess,
        "Popen",
        fake_popen,
    )

    with pytest.raises(
        system.SystemActionError,
        match="confirmation",
    ):
        system.system_power_action(
            operation="reboot",
            confirmation="wrong",
        )

    assert called is False


def test_power_rejects_unknown_operation(
) -> None:
    with pytest.raises(
        system.SystemActionError,
        match="unsupported",
    ):
        system.system_power_action(
            operation="shell",
            confirmation="SHELL",
        )


def test_power_uses_fixed_systemctl_argv(
    monkeypatch,
) -> None:
    observed = {}

    class Process:
        pid = 1234

    def fake_popen(
        argv,
        **kwargs,
    ):
        observed["argv"] = argv
        observed["kwargs"] = kwargs

        return Process()

    monkeypatch.setattr(
        system.subprocess,
        "Popen",
        fake_popen,
    )

    result = (
        system
        .system_power_action(
            operation="reboot",
            confirmation="REBOOT",
        )
    )

    assert observed[
        "argv"
    ] == [
        "/usr/bin/systemctl",
        "--no-block",
        "reboot",
    ]

    assert result == {
        "accepted":
            True,
        "operation":
            "reboot",
        "pid":
            1234,
    }


def test_system_runtime_shape(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        system,
        "_cpu_percent",
        lambda: 12.5,
    )

    monkeypatch.setattr(
        system,
        "_load_average",
        lambda: [
            0.1,
            0.2,
            0.3,
        ],
    )

    monkeypatch.setattr(
        system,
        "_failed_units",
        lambda: [],
    )

    monkeypatch.setattr(
        system,
        "_temperatures",
        lambda: [],
    )

    monkeypatch.setattr(
        system,
        "_journal_usage_bytes",
        lambda: 1024,
    )

    result = (
        system
        .get_system_runtime_action()
    )

    assert (
        result["secbox_version"]
    )

    assert (
        result["cpu"]
        ["used_percent"]
        == 12.5
    )

    assert (
        result[
            "failed_unit_count"
        ]
        == 0
    )

    assert (
        "total_bytes"
        in result[
            "root_filesystem"
        ]
    )
