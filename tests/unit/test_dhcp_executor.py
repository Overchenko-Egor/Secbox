from pathlib import Path

from pytest import MonkeyPatch

from secbox.modules.dhcp.executor import apply_dnsmasq_config


def test_apply_dnsmasq_config(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    rendered = tmp_path / "rendered.conf"
    target = tmp_path / "target.conf"
    backup = tmp_path / "backup.conf"

    rendered.write_text(
        "port=0\n",
        encoding="utf-8",
    )

    commands: list[list[str]] = []

    class Result:
        stdout = "active\n"

    def fake_run_command(
        command: list[str],
    ) -> Result:
        commands.append(command)
        return Result()

    monkeypatch.setattr(
        "secbox.modules.dhcp.executor.run_command",
        fake_run_command,
    )

    apply_dnsmasq_config(
        rendered_file=rendered,
        target_file=target,
        backup_file=backup,
    )

    assert [
        "systemctl",
        "restart",
        "dnsmasq",
    ] in commands

    assert [
        "systemctl",
        "is-active",
        "dnsmasq",
    ] in commands
