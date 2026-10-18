"""Models for SecBox deception cases."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
)


CaseStatus = Literal[
    "observing",
    "stopped",
    "error",
]


class DeceptionTrigger(BaseModel):
    """Reason why an observation case was created."""

    model_config = ConfigDict(
        extra="forbid",
    )

    source: str = Field(
        min_length=1,
        max_length=32,
    )

    reason: str = Field(
        min_length=1,
        max_length=256,
    )

    signature_id: int | None = Field(
        default=None,
        ge=1,
    )

    severity: int | None = Field(
        default=None,
        ge=1,
        le=3,
    )

    count: int | None = Field(
        default=None,
        ge=1,
    )


class DeceptionCase(BaseModel):
    """Persistent metadata for one Deception investigation."""

    model_config = ConfigDict(
        extra="forbid",
    )

    case_id: str
    source_ip: str

    status: CaseStatus

    created_at: datetime
    updated_at: datetime
    stopped_at: datetime | None = None

    trigger: DeceptionTrigger

    capture_unit: str

    eve_event_count: int = 0

    error: str | None = None
