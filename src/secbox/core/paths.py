"""Filesystem paths used by SecBox."""

import os
from pathlib import Path


def get_config_path() -> Path:
    """Return the active SecBox configuration path.

    SECBOX_CONFIG_PATH can override the default path. This is useful for
    development, tests and recovery operations.
    """
    configured_path = os.environ.get("SECBOX_CONFIG_PATH")

    if configured_path:
        return Path(configured_path).expanduser()

    return Path.home() / ".config" / "secbox" / "secbox.yml"
