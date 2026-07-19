"""Pydantic models for the SecBox configuration."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SystemConfig(BaseModel):
    """General SecBox system settings."""

    model_config = ConfigDict(extra="forbid")

    hostname: str = Field(
        default="secbox",
        min_length=1,
        max_length=63,
        description="System hostname",
    )

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, value: str) -> str:
        """Validate hostname using a conservative DNS-compatible format."""
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")

        if any(character not in allowed for character in value):
            raise ValueError("hostname may contain only letters, digits and hyphens")

        if value.startswith("-") or value.endswith("-"):
            raise ValueError("hostname must not start or end with a hyphen")

        return value.lower()


class SecBoxConfig(BaseModel):
    """Root SecBox configuration model."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    system: SystemConfig = Field(default_factory=SystemConfig)
