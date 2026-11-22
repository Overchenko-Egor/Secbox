"""Explicit credentials and configuration path for the web process."""

import os
from dataclasses import dataclass, field
from pathlib import Path

from secbox.core.paths import get_config_path


@dataclass(frozen=True)
class WebSettings:
    config_path: Path
    password: str = field(repr=False)
    username: str = "admin"
    users_path: Path = Path(
        "/var/lib/secbox/web/users.json"
    )
    session_key_path: Path = Path(
        "/var/lib/secbox/web/session.key"
    )

    def __post_init__(self) -> None:
        if len(self.password) < 16 or not self.password.isascii() or not self.password.isprintable():
            raise ValueError("web password must contain at least 16 printable ASCII characters")
        if not self.username or not self.username.isascii() or ":" in self.username:
            raise ValueError("web username must be non-empty ASCII without a colon")

    @classmethod
    def from_environment(cls) -> "WebSettings":
        password = os.environ.get("SECBOX_WEB_PASSWORD", "")
        password_file = os.environ.get("SECBOX_WEB_PASSWORD_FILE")
        if password_file:
            if password:
                raise ValueError("set only one of SECBOX_WEB_PASSWORD and SECBOX_WEB_PASSWORD_FILE")
            password = Path(password_file).expanduser().read_text(encoding="utf-8").rstrip("\r\n")
        if not password:
            raise ValueError("set SECBOX_WEB_PASSWORD_FILE or SECBOX_WEB_PASSWORD before starting the web server")
        return cls(
            config_path=get_config_path(),
            password=password,
            username=os.environ.get("SECBOX_WEB_USER", "admin"),
            users_path=Path(
                os.environ.get(
                    "SECBOX_WEB_USERS_FILE",
                    "/var/lib/secbox/web/users.json",
                )
            ),
            session_key_path=Path(
                os.environ.get(
                    "SECBOX_WEB_SESSION_KEY_FILE",
                    "/var/lib/secbox/web/session.key",
                )
            ),
        )
