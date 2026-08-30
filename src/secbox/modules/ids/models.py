"""Models for Suricata IDS events."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict


class SuricataAlert(BaseModel):
    """Suricata alert information from an EVE event."""

    model_config = ConfigDict(
        extra="ignore",
    )

    action: str
    gid: int
    signature_id: int
    rev: int
    signature: str
    category: str
    severity: int
    metadata: dict[str, Any] | None = None


class SuricataFlow(BaseModel):
    """Optional flow information embedded in an alert."""

    model_config = ConfigDict(
        extra="ignore",
    )

    pkts_toserver: int | None = None
    pkts_toclient: int | None = None
    bytes_toserver: int | None = None
    bytes_toclient: int | None = None
    start: datetime | None = None
    src_ip: str | None = None
    dest_ip: str | None = None


class SuricataAlertEvent(BaseModel):
    """Normalized Suricata EVE alert event."""

    model_config = ConfigDict(
        extra="ignore",
    )

    timestamp: datetime
    event_type: Literal["alert"]

    flow_id: int | None = None
    in_iface: str | None = None

    src_ip: str
    src_port: int | None = None

    dest_ip: str
    dest_port: int | None = None

    proto: str
    app_proto: str | None = None

    direction: str | None = None
    pkt_src: str | None = None

    icmp_type: int | None = None
    icmp_code: int | None = None

    alert: SuricataAlert
    flow: SuricataFlow | None = None
