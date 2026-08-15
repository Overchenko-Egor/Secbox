from pathlib import Path

from pytest import MonkeyPatch

from secbox.modules.firewall.executor import apply_firewall_config


def test_apply_firewall_config(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    rendered = tmp_path / "rendered.nft"
    target = tmp_path / "target.nft"
    backup = tmp_path / "backup.nft"

    rendered.write_text("flush ruleset\n", encoding="utf-8")

    commands: list[list[str]] = []

    class Result:
        stdout = ""

    def fake_run_command(command: list[str]) -> Result:
        commands.append(command)
        return Result()

    monkeypatch.setattr(
        "secbox.modules.firewall.executor.run_command",
        fake_run_command,
    )

    apply_firewall_config(
        rendered_file=rendered,
        target_file=target,
        backup_file=backup,
    )

    assert any("--check" in command for command in commands)
    assert any(
        "--file" in command and "--check" not in command
        for command in commands
    )
