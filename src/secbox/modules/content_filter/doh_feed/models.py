"""Models for managed DoH resolver state."""

from datetime import datetime
from ipaddress import IPv4Address

from pydantic import BaseModel, ConfigDict, Field


class DohFeedState(BaseModel):
    """Persisted state of the managed DoH resolver feed."""

    model_config = ConfigDict(extra="forbid")

    addresses: list[IPv4Address] = Field(
        default_factory=list
    )

    updated_at: datetime | None = None
