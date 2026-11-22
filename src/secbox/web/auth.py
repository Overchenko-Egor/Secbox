"""Local SecBox Web users and signed sessions."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import time

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


USERNAME_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{2,31}$"
)

PASSWORD_MIN_LENGTH = 12

SESSION_COOKIE = "secbox_session"
SESSION_TTL_SECONDS = 8 * 60 * 60

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1


class AuthError(RuntimeError):
    """Base Web authentication error."""


class UserValidationError(AuthError):
    """Invalid user input."""


class UserConflictError(AuthError):
    """Requested user already exists."""


class UserNotFoundError(AuthError):
    """Requested user does not exist."""


class UserDeleteError(AuthError):
    """User cannot be deleted."""


@dataclass(frozen=True)
class AuthUser:
    username: str
    role: str = "admin"
    enabled: bool = True


def validate_username(username: str) -> str:
    value = username.strip()

    if not USERNAME_RE.fullmatch(value):
        raise UserValidationError(
            "Имя пользователя: 3–32 символа; "
            "допустимы латинские буквы, цифры, '.', '_' и '-'."
        )

    return value


def validate_password(password: str) -> None:
    if len(password) < PASSWORD_MIN_LENGTH:
        raise UserValidationError(
            f"Пароль должен содержать минимум "
            f"{PASSWORD_MIN_LENGTH} символов."
        )

    if len(password) > 256:
        raise UserValidationError(
            "Пароль слишком длинный."
        )

    if not password.isprintable():
        raise UserValidationError(
            "Пароль содержит недопустимые управляющие символы."
        )


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(
        value
    ).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)

    return base64.urlsafe_b64decode(
        value + padding
    )


def hash_password(password: str) -> str:
    validate_password(password)

    salt = secrets.token_bytes(16)

    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=32,
        maxmem=64 * 1024 * 1024,
    )

    return (
        f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}"
        f"${_b64encode(salt)}"
        f"${_b64encode(digest)}"
    )


def verify_password(
    password: str,
    encoded: str,
) -> bool:
    try:
        algorithm, n, r, p, salt, expected = (
            encoded.split("$", 5)
        )

        if algorithm != "scrypt":
            return False

        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=_b64decode(salt),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=32,
            maxmem=64 * 1024 * 1024,
        )

        return hmac.compare_digest(
            digest,
            _b64decode(expected),
        )

    except (
        ValueError,
        TypeError,
        OSError,
    ):
        return False


@contextmanager
def _lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(
            handle.fileno(),
            fcntl.LOCK_EX,
        )

        try:
            yield

        finally:
            fcntl.flock(
                handle.fileno(),
                fcntl.LOCK_UN,
            )


class UserStore:
    """Atomic local Web user database."""

    def __init__(
        self,
        path: Path,
    ) -> None:
        self.path = path
        self.lock_path = path.with_suffix(
            path.suffix + ".lock"
        )

    def _read_unlocked(self) -> dict:
        if not self.path.exists():
            return {
                "version": 1,
                "users": [],
            }

        try:
            payload = json.loads(
                self.path.read_text(
                    encoding="utf-8"
                )
            )
        except (
            OSError,
            json.JSONDecodeError,
        ) as error:
            raise AuthError(
                f"Не удалось прочитать базу пользователей: "
                f"{error}"
            ) from error

        if (
            not isinstance(payload, dict)
            or payload.get("version") != 1
            or not isinstance(
                payload.get("users"),
                list,
            )
        ):
            raise AuthError(
                "Некорректный формат базы пользователей."
            )

        return payload

    def _write_unlocked(
        self,
        payload: dict,
    ) -> None:
        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        temporary_path: Path | None = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=".users.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary_path = Path(
                    temporary.name
                )

                json.dump(
                    payload,
                    temporary,
                    indent=2,
                    ensure_ascii=False,
                )

                temporary.write("\n")
                temporary.flush()
                os.fsync(
                    temporary.fileno()
                )

            temporary_path.chmod(0o600)

            os.replace(
                temporary_path,
                self.path,
            )

            self.path.chmod(0o600)

        finally:
            if (
                temporary_path is not None
                and temporary_path.exists()
            ):
                try:
                    temporary_path.unlink()
                except OSError:
                    pass

    @staticmethod
    def _public(
        record: dict,
    ) -> dict[str, object]:
        return {
            "username": record["username"],
            "role": record.get(
                "role",
                "admin",
            ),
            "enabled": bool(
                record.get(
                    "enabled",
                    True,
                )
            ),
        }

    def ensure_bootstrap(
        self,
        *,
        username: str,
        password: str,
    ) -> None:
        """Create initial admin only when DB is absent/empty."""

        username = validate_username(
            username
        )

        with _lock(self.lock_path):
            payload = self._read_unlocked()

            if payload["users"]:
                return

            payload["users"].append(
                {
                    "username": username,
                    "password_hash":
                        hash_password(password),
                    "role": "admin",
                    "enabled": True,
                    "session_version": 1,
                }
            )

            self._write_unlocked(
                payload
            )

    def authenticate(
        self,
        username: str,
        password: str,
    ) -> tuple[AuthUser, int] | None:
        with _lock(self.lock_path):
            payload = self._read_unlocked()

            for record in payload["users"]:
                if (
                    record.get("username")
                    != username
                ):
                    continue

                if not record.get(
                    "enabled",
                    True,
                ):
                    return None

                if not verify_password(
                    password,
                    str(
                        record.get(
                            "password_hash",
                            "",
                        )
                    ),
                ):
                    return None

                return (
                    AuthUser(
                        username=record[
                            "username"
                        ],
                        role=record.get(
                            "role",
                            "admin",
                        ),
                        enabled=True,
                    ),
                    int(
                        record.get(
                            "session_version",
                            1,
                        )
                    ),
                )

        return None

    def get_session_user(
        self,
        username: str,
        session_version: int,
    ) -> AuthUser | None:
        with _lock(self.lock_path):
            payload = self._read_unlocked()

            for record in payload["users"]:
                if (
                    record.get("username")
                    != username
                ):
                    continue

                if not record.get(
                    "enabled",
                    True,
                ):
                    return None

                if int(
                    record.get(
                        "session_version",
                        1,
                    )
                ) != session_version:
                    return None

                return AuthUser(
                    username=username,
                    role=record.get(
                        "role",
                        "admin",
                    ),
                    enabled=True,
                )

        return None

    def list_users(
        self,
    ) -> list[dict[str, object]]:
        with _lock(self.lock_path):
            payload = self._read_unlocked()

            users = [
                self._public(record)
                for record in payload["users"]
            ]

        users.sort(
            key=lambda item: str(
                item["username"]
            ).lower()
        )

        return users

    def create_user(
        self,
        *,
        username: str,
        password: str,
    ) -> dict[str, object]:
        username = validate_username(
            username
        )
        validate_password(password)

        with _lock(self.lock_path):
            payload = self._read_unlocked()

            if any(
                item.get("username")
                == username
                for item in payload["users"]
            ):
                raise UserConflictError(
                    "Пользователь уже существует."
                )

            record = {
                "username": username,
                "password_hash":
                    hash_password(password),
                "role": "admin",
                "enabled": True,
                "session_version": 1,
            }

            payload["users"].append(record)

            self._write_unlocked(
                payload
            )

            return self._public(record)

    def change_password(
        self,
        *,
        username: str,
        password: str,
    ) -> None:
        validate_password(password)

        with _lock(self.lock_path):
            payload = self._read_unlocked()

            for record in payload["users"]:
                if (
                    record.get("username")
                    != username
                ):
                    continue

                record["password_hash"] = (
                    hash_password(password)
                )

                record["session_version"] = (
                    int(
                        record.get(
                            "session_version",
                            1,
                        )
                    )
                    + 1
                )

                self._write_unlocked(
                    payload
                )

                return

            raise UserNotFoundError(
                "Пользователь не найден."
            )

    def delete_user(
        self,
        *,
        username: str,
        current_username: str,
    ) -> None:
        with _lock(self.lock_path):
            payload = self._read_unlocked()

            if username == current_username:
                raise UserDeleteError(
                    "Нельзя удалить текущего пользователя."
                )

            target = None

            for record in payload["users"]:
                if (
                    record.get("username")
                    == username
                ):
                    target = record
                    break

            if target is None:
                raise UserNotFoundError(
                    "Пользователь не найден."
                )

            admins = [
                record
                for record in payload["users"]
                if (
                    record.get(
                        "role",
                        "admin",
                    )
                    == "admin"
                    and record.get(
                        "enabled",
                        True,
                    )
                )
            ]

            if (
                target.get(
                    "role",
                    "admin",
                )
                == "admin"
                and len(admins) <= 1
            ):
                raise UserDeleteError(
                    "Нельзя удалить последнего администратора."
                )

            payload["users"] = [
                record
                for record in payload["users"]
                if (
                    record.get("username")
                    != username
                )
            ]

            self._write_unlocked(
                payload
            )


class SessionSigner:
    """HMAC-signed stateless session cookies."""

    def __init__(
        self,
        key_path: Path,
    ) -> None:
        self.key_path = key_path
        self._key = self._load_or_create()

    def _load_or_create(self) -> bytes:
        self.key_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        if self.key_path.exists():
            value = self.key_path.read_bytes()

            if len(value) < 32:
                raise AuthError(
                    "Некорректный ключ Web-сессий."
                )

            return value

        value = secrets.token_bytes(32)

        fd = os.open(
            self.key_path,
            os.O_CREAT
            | os.O_EXCL
            | os.O_WRONLY,
            0o600,
        )

        try:
            os.write(fd, value)
            os.fsync(fd)

        finally:
            os.close(fd)

        return value

    def create(
        self,
        *,
        username: str,
        session_version: int,
    ) -> str:
        now = int(time.time())

        payload = {
            "u": username,
            "v": session_version,
            "iat": now,
            "exp":
                now + SESSION_TTL_SECONDS,
            "n":
                secrets.token_urlsafe(8),
        }

        encoded = _b64encode(
            json.dumps(
                payload,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        )

        signature = _b64encode(
            hmac.new(
                self._key,
                encoded.encode("ascii"),
                hashlib.sha256,
            ).digest()
        )

        return (
            f"{encoded}.{signature}"
        )

    def parse(
        self,
        token: str,
    ) -> tuple[str, int] | None:
        try:
            encoded, signature = (
                token.split(".", 1)
            )

            expected = _b64encode(
                hmac.new(
                    self._key,
                    encoded.encode("ascii"),
                    hashlib.sha256,
                ).digest()
            )

            if not hmac.compare_digest(
                signature,
                expected,
            ):
                return None

            payload = json.loads(
                _b64decode(
                    encoded
                ).decode("utf-8")
            )

            if int(
                payload["exp"]
            ) < int(time.time()):
                return None

            username = validate_username(
                str(payload["u"])
            )

            version = int(
                payload["v"]
            )

            return (
                username,
                version,
            )

        except (
            ValueError,
            KeyError,
            TypeError,
            json.JSONDecodeError,
            UserValidationError,
        ):
            return None
