"""Models for managed DoH resolver state."""

from datetime import datetime
from ipaddress import IPv4Address

from pydantic import BaseModel, ConfigDict, Field, field_validator


class DohFeedState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    addresses: list[IPv4Address] = Field(default_factory=list)
    updated_at: datetime | None = None

    @field_validator("addresses")
    @classmethod
    def validate_addresses(
        cls,
        value: list[IPv4Address],
    ) -> list[IPv4Address]:
        if len(value) != len(set(value)):
            raise ValueError(
                "managed DoH resolver addresses must be unique"
            )

        return value

    @field_validator("updated_at")
    @classmethod
    def validate_updated_at(
        cls,
        value: datetime | None,
    ) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError(
                "managed DoH state timestamp must be timezone-aware"
            )

        return value
