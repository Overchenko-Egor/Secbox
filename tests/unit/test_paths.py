from pathlib import Path

from pytest import MonkeyPatch

from secbox.core.paths import get_config_path


def test_default_config_path(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.delenv("SECBOX_CONFIG_PATH", raising=False)
    monkeypatch.setenv("HOME", "/home/tester")

    assert get_config_path() == Path("/home/tester/.config/secbox/secbox.yml")


def test_config_path_can_be_overridden(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    custom_path = tmp_path / "custom.yml"
    monkeypatch.setenv("SECBOX_CONFIG_PATH", str(custom_path))

    assert get_config_path() == custom_path
