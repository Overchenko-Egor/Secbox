from pathlib import Path

import pytest

from secbox.core.config_store import (
    ConfigBackupNotFoundError,
    ConfigNotFoundError,
    ConfigStore,
    ConfigValidationError,
)
from secbox.core.models import SecBoxConfig, SystemConfig


def test_create_default_config(tmp_path: Path) -> None:
    config_path = tmp_path / "secbox.yml"
    store = ConfigStore(config_path)

    created = store.create_default()
    loaded = store.load()

    assert created == loaded
    assert loaded.system.hostname == "secbox"
    assert config_path.stat().st_mode & 0o777 == 0o600


def test_load_missing_config_raises_error(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path / "missing.yml")

    with pytest.raises(ConfigNotFoundError):
        store.load()


def test_unknown_fields_are_rejected(tmp_path: Path) -> None:
    config_path = tmp_path / "secbox.yml"
    config_path.write_text(
        "schema_version: 1\nunknown_option: true\n",
        encoding="utf-8",
    )

    store = ConfigStore(config_path)

    with pytest.raises(ConfigValidationError):
        store.load()


def test_save_creates_backup(tmp_path: Path) -> None:
    config_path = tmp_path / "secbox.yml"
    store = ConfigStore(config_path)

    store.save(SecBoxConfig(system=SystemConfig(hostname="first")))
    store.save(SecBoxConfig(system=SystemConfig(hostname="second")))

    assert store.load().system.hostname == "second"
    assert store.backup_path.exists()


def test_rollback_restores_previous_config(tmp_path: Path) -> None:
    config_path = tmp_path / "secbox.yml"
    store = ConfigStore(config_path)

    store.save(SecBoxConfig(system=SystemConfig(hostname="first")))
    store.save(SecBoxConfig(system=SystemConfig(hostname="second")))

    restored = store.rollback()

    assert restored.system.hostname == "first"
    assert store.load().system.hostname == "first"


def test_rollback_without_backup_raises_error(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path / "secbox.yml")
    store.create_default()

    with pytest.raises(ConfigBackupNotFoundError):
        store.rollback()
