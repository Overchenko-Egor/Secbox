"""Aggregation of repeated correlated IDS alerts."""

from dataclasses import dataclass
from datetime import datetime, timedelta

from secbox.modules.ids.correlation import (
    CorrelatedAlert,
)


DEFAULT_AGGREGATION_WINDOW = timedelta(
    seconds=30
)


@dataclass(frozen=True)
class DetectionKey:
    """Fields identifying one repeated IDS detection."""

    gid: int
    signature_id: int
    rev: int

    source_ip: str
    destination_ip: str

    proto: str

    destination_port: int | None

    icmp_type: int | None
    icmp_code: int | None


@dataclass(frozen=True)
class Detection:
    """Aggregated IDS detection."""

    key: DetectionKey

    alerts: tuple[CorrelatedAlert, ...]

    first_seen: datetime
    last_seen: datetime

    @property
    def count(self) -> int:
        """Return number of logical alerts."""

        return len(self.alerts)

    @property
    def duration(self) -> timedelta:
        """Return time between first and last alert."""

        return (
            self.last_seen
            - self.first_seen
        )

    @property
    def source_ip(self) -> str:
        """Return source address."""

        return self.key.source_ip

    @property
    def destination_ip(self) -> str:
        """Return destination address."""

        return self.key.destination_ip

    @property
    def signature_id(self) -> int:
        """Return Suricata signature ID."""

        return self.key.signature_id

    @property
    def signature(self) -> str:
        """Return signature text."""

        return (
            self.alerts[0]
            .canonical
            .event
            .alert
            .signature
        )

    @property
    def severity(self) -> int:
        """Return Suricata severity."""

        return (
            self.alerts[0]
            .canonical
            .event
            .alert
            .severity
        )

    @property
    def category(self) -> str:
        """Return Suricata alert category."""

        return (
            self.alerts[0]
            .canonical
            .event
            .alert
            .category
        )

    @property
    def nat_correlated_count(self) -> int:
        """Return number of alerts correlated across NAT."""

        return sum(
            1
            for alert in self.alerts
            if alert.nat_correlated
        )


def build_detection_key(
    alert: CorrelatedAlert,
) -> DetectionKey:
    """Build aggregation key from a logical IDS alert."""

    event = alert.canonical.event

    return DetectionKey(
        gid=event.alert.gid,
        signature_id=event.alert.signature_id,
        rev=event.alert.rev,
        source_ip=alert.source_ip,
        destination_ip=alert.destination_ip,
        proto=event.proto,
        destination_port=event.dest_port,
        icmp_type=event.icmp_type,
        icmp_code=event.icmp_code,
    )


def aggregate_alerts(
    alerts: list[CorrelatedAlert],
    window: timedelta = DEFAULT_AGGREGATION_WINDOW,
) -> list[Detection]:
    """Aggregate repeated logical alerts within a time window."""

    if window <= timedelta():
        raise ValueError(
            "aggregation window must be positive"
        )

    sorted_alerts = sorted(
        alerts,
        key=lambda alert: (
            alert.canonical.event.timestamp
        ),
    )

    active: dict[
        DetectionKey,
        list[CorrelatedAlert],
    ] = {}

    detections: list[Detection] = []

    for alert in sorted_alerts:
        key = build_detection_key(
            alert
        )

        existing = active.get(key)

        if not existing:
            active[key] = [alert]
            continue

        first_timestamp = (
            existing[0]
            .canonical
            .event
            .timestamp
        )

        current_timestamp = (
            alert
            .canonical
            .event
            .timestamp
        )

        if (
            current_timestamp
            - first_timestamp
            <= window
        ):
            existing.append(alert)
            continue

        detections.append(
            _build_detection(
                key,
                existing,
            )
        )

        active[key] = [alert]

    for key, grouped_alerts in active.items():
        detections.append(
            _build_detection(
                key,
                grouped_alerts,
            )
        )

    detections.sort(
        key=lambda detection: (
            detection.first_seen
        )
    )

    return detections


def _build_detection(
    key: DetectionKey,
    alerts: list[CorrelatedAlert],
) -> Detection:
    """Create a Detection from grouped logical alerts."""

    if not alerts:
        raise ValueError(
            "cannot build detection without alerts"
        )

    timestamps = [
        alert.canonical.event.timestamp
        for alert in alerts
    ]

    return Detection(
        key=key,
        alerts=tuple(alerts),
        first_seen=min(timestamps),
        last_seen=max(timestamps),
    )
