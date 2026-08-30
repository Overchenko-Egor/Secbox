"""Models for dynamic blacklist state."""

from datetime import datetime

from pydantic import BaseModel


class BlacklistEntry(BaseModel):
    """Stored metadata for a blacklist entry."""

    address: str
    reason: str
    source: str
    created_at: datetime
    expires_at: datetime
