"""Safe loading and saving of the SecBox configuration."""

import os
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from secbox.core.models import SecBoxConfig


class ConfigStoreError(Exception):
    """Base error raised by the configuration store."""


class ConfigNotFoundError(ConfigStoreError):
    """Raised when the configuration file does not exist."""


class ConfigValidationError(ConfigStoreError):
    """Raised when configuration data fails validation."""


class ConfigBackupNotFoundError(ConfigStoreError):
    """Raised when rollback is requested but no backup exists."""


class ConfigStore:
    """Read and atomically update the SecBox YAML configuration."""

    def __init__(self, config_path: Path) -> None:
        self.config_path = config_path
        self.backup_path = config_path.with_suffix(config_path.suffix + ".bak")

    def load(self) -> SecBoxConfig:
        """Load and validate the current configuration."""
        if not self.config_path.exists():
            raise ConfigNotFoundError(
                f"configuration file does not exist: {self.config_path}"
            )

        try:
            raw_data = yaml.safe_load(
                self.config_path.read_text(encoding="utf-8")
            )
        except (OSError, yaml.YAMLError) as error:
            raise ConfigStoreError(
                f"failed to read configuration: {error}"
            ) from error

        if raw_data is None:
            raw_data = {}

        if not isinstance(raw_data, dict):
            raise ConfigValidationError(
                "configuration root must be a YAML mapping"
            )

        return self._validate(raw_data)

    def save(self, config: SecBoxConfig) -> None:
        """Atomically save a validated configuration.

        If a current configuration exists, it is copied to the backup path
        before the new file replaces it.
        """
        self.config_path.parent.mkdir(parents=True, exist_ok=True)

        serialized = yaml.safe_dump(
            config.model_dump(mode="json"),
            sort_keys=False,
            allow_unicode=True,
        )

        temporary_path: Path | None = None

        try:
            file_descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{self.config_path.name}.",
                suffix=".tmp",
                dir=self.config_path.parent,
                text=True,
            )
            temporary_path = Path(temporary_name)

            with os.fdopen(file_descriptor, "w", encoding="utf-8") as file:
                file.write(serialized)
                file.flush()
                os.fsync(file.fileno())

            self._apply_target_metadata(temporary_path)

            if self.config_path.exists():
                shutil.copy2(self.config_path, self.backup_path)
                self.backup_path.chmod(0o600)

            os.replace(temporary_path, self.config_path)
            temporary_path = None

        except OSError as error:
            raise ConfigStoreError(
                f"failed to save configuration: {error}"
            ) from error

        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    def create_default(self) -> SecBoxConfig:
        """Create and save the default SecBox configuration."""
        config = SecBoxConfig()
        self.save(config)
        return config

    def rollback(self) -> SecBoxConfig:
        """Restore the most recent configuration backup."""
        if not self.backup_path.exists():
            raise ConfigBackupNotFoundError(
                f"backup file does not exist: {self.backup_path}"
            )

        try:
            backup_data = yaml.safe_load(
                self.backup_path.read_text(encoding="utf-8")
            )
        except (OSError, yaml.YAMLError) as error:
            raise ConfigStoreError(
                f"failed to read backup configuration: {error}"
            ) from error

        if not isinstance(backup_data, dict):
            raise ConfigValidationError(
                "backup configuration root must be a YAML mapping"
            )

        restored_config = self._validate(backup_data)
        self._replace_without_backup(restored_config)

        return restored_config

    def _replace_without_backup(self, config: SecBoxConfig) -> None:
        """Atomically replace the current file without overwriting its backup."""
        serialized = yaml.safe_dump(
            config.model_dump(mode="json"),
            sort_keys=False,
            allow_unicode=True,
        )

        temporary_path: Path | None = None

        try:
            file_descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{self.config_path.name}.",
                suffix=".tmp",
                dir=self.config_path.parent,
                text=True,
            )
            temporary_path = Path(temporary_name)

            with os.fdopen(file_descriptor, "w", encoding="utf-8") as file:
                file.write(serialized)
                file.flush()
                os.fsync(file.fileno())

            self._apply_target_metadata(temporary_path)
            os.replace(temporary_path, self.config_path)
            temporary_path = None

        except OSError as error:
            raise ConfigStoreError(
                f"failed to restore configuration: {error}"
            ) from error

        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    def _apply_target_metadata(self, path: Path) -> None:
        """Apply secure metadata to an atomic replacement file.

        A new configuration defaults to owner-only access.  When replacing
        an existing file, preserve its mode and, when running as root, its
        owner/group.  This keeps the production root:secbox-web 0640 policy
        intact across atomic saves and rollbacks.
        """
        if not self.config_path.exists():
            path.chmod(0o600)
            return

        target_stat = self.config_path.stat()
        path.chmod(stat.S_IMODE(target_stat.st_mode))

        if os.geteuid() == 0:
            os.chown(
                path,
                target_stat.st_uid,
                target_stat.st_gid,
            )

    def _apply_target_metadata(self, path: Path) -> None:
        if not self.config_path.exists():
            path.chmod(0o600)
            return

        target_stat = self.config_path.stat()
        path.chmod(stat.S_IMODE(target_stat.st_mode))

        if os.geteuid() == 0:
            os.chown(
                path,
                target_stat.st_uid,
                target_stat.st_gid,
            )

    @staticmethod
    def _validate(raw_data: dict[str, Any]) -> SecBoxConfig:
        try:
            return SecBoxConfig.model_validate(raw_data)
        except ValidationError as error:
            raise ConfigValidationError(
                f"configuration validation failed: {error}"
            ) from error
