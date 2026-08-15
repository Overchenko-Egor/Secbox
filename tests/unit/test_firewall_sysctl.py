import subprocess

from pytest import MonkeyPatch

from secbox.modules.firewall.sysctl import set_ipv4_forwarding


def test_enable_ipv4_forwarding(
    monkeypatch: MonkeyPatch,
) -> None:
    commands: list[list[str]] = []

    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        commands.append(command)

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    set_ipv4_forwarding(True)

    assert [
        "/usr/sbin/sysctl",
        "-w",
        "net.ipv4.ip_forward=1",
    ] in commands
