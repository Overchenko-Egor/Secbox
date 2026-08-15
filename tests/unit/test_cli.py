from pathlib import Path

from pytest import MonkeyPatch
from typer.testing import CliRunner

from secbox.cli import app

runner = CliRunner()


def set_test_config_path(
    monkeypatch: MonkeyPatch,
    path: Path,
) -> None:
    monkeypatch.setenv("SECBOX_CONFIG_PATH", str(path))


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "0.1.0" in result.stdout


def test_config_init_and_show(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "secbox.yml"
    set_test_config_path(monkeypatch, config_path)

    init_result = runner.invoke(app, ["config", "init"])
    show_result = runner.invoke(app, ["config", "show"])

    assert init_result.exit_code == 0
    assert config_path.exists()
    assert show_result.exit_code == 0
    assert "hostname: secbox" in show_result.stdout


def test_config_init_refuses_existing_file(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "secbox.yml"
    set_test_config_path(monkeypatch, config_path)

    runner.invoke(app, ["config", "init"])
    second_result = runner.invoke(app, ["config", "init"])

    assert second_result.exit_code == 1
    assert "configuration already exists" in second_result.stderr


def test_set_hostname_and_rollback(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "secbox.yml"
    set_test_config_path(monkeypatch, config_path)

    runner.invoke(app, ["config", "init"])
    update_result = runner.invoke(
        app,
        ["config", "set-hostname", "Gateway-01"],
    )
    rollback_result = runner.invoke(app, ["config", "rollback"])
    show_result = runner.invoke(app, ["config", "show"])

    assert update_result.exit_code == 0
    assert "gateway-01" in update_result.stdout
    assert rollback_result.exit_code == 0
    assert "hostname: secbox" in show_result.stdout


def test_validate_invalid_config(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "invalid.yml"
    config_path.write_text(
        "schema_version: 1\nunknown_field: true\n",
        encoding="utf-8",
    )
    set_test_config_path(monkeypatch, tmp_path / "active.yml")

    result = runner.invoke(
        app,
        ["config", "validate", str(config_path)],
    )

    assert result.exit_code == 1
    assert "configuration validation failed" in result.stderr






def test_network_load_and_show(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "secbox.yml"
    network_path = tmp_path / "network.yml"

    set_test_config_path(monkeypatch, config_path)

    network_path.write_text(
        """
interfaces:
  - name: ens33
    role: wan
    ipv4_method: dhcp

  - name: ens34
    role: lan
    ipv4_method: static
    ipv4_address: 192.168.50.1/24
""".strip(),
        encoding="utf-8",
    )

    runner.invoke(app, ["config", "init"])
    load_result = runner.invoke(
        app,
        ["network", "load", str(network_path)],
    )
    show_result = runner.invoke(app, ["network", "show"])

    assert load_result.exit_code == 0
    assert show_result.exit_code == 0
    assert "name: ens33" in show_result.stdout
    assert "role: wan" in show_result.stdout
    assert "address: 192.168.50.1/24" in show_result.stdout
