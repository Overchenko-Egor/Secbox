"""Tests for IDS alert aggregation."""

import ipaddress

from datetime import timedelta

from secbox.modules.ids.aggregation import (
    aggregate_alerts,
)
from secbox.modules.ids.classification import (
    IdsNetworkContext,
    classify_alert,
)
from secbox.modules.ids.correlation import (
    correlate_nat_observations,
)
from secbox.modules.ids.parser import (
    parse_eve_line,
)


def make_context() -> IdsNetworkContext:
    """Create test IDS network context."""

    return IdsNetworkContext(
        wan_interface="ens33",
        lan_interface="ens36",
        wan_ipv4_addresses=(
            ipaddress.IPv4Address(
                "192.168.1.63"
            ),
        ),
        lan_ipv4_networks=(
            ipaddress.IPv4Network(
                "192.168.50.0/24"
            ),
        ),
    )


def make_icmp_observation(
    timestamp: str,
    interface: str,
    source_ip: str,
    destination_ip: str = "8.8.8.8",
    signature_id: int = 9900001,
):
    """Create one classified ICMP observation."""

    event = parse_eve_line(
        f"""
        {{
          "timestamp": "{timestamp}",
          "in_iface": "{interface}",
          "event_type": "alert",
          "src_ip": "{source_ip}",
          "dest_ip": "{destination_ip}",
          "proto": "ICMP",
          "icmp_type": 8,
          "icmp_code": 0,
          "alert": {{
            "action": "allowed",
            "gid": 1,
            "signature_id": {signature_id},
            "rev": 1,
            "signature": "SECBOX TEST ICMP ALERT",
            "category": "Test",
            "severity": 3
          }}
        }}
        """
    )

    assert event is not None

    return classify_alert(
        event,
        make_context(),
    )


def make_four_ping_alerts():
    """Create four real-style NAT correlated ping alerts."""

    observations = []

    timestamps = [
        (
            "2026-08-30T07:18:08.645338-0400",
            "2026-08-30T07:18:08.645380-0400",
        ),
        (
            "2026-08-30T07:18:09.645338-0400",
            "2026-08-30T07:18:09.645380-0400",
        ),
        (
            "2026-08-30T07:18:10.645338-0400",
            "2026-08-30T07:18:10.645380-0400",
        ),
        (
            "2026-08-30T07:18:11.645338-0400",
            "2026-08-30T07:18:11.645380-0400",
        ),
    ]

    for lan_timestamp, wan_timestamp in timestamps:
        observations.append(
            make_icmp_observation(
                lan_timestamp,
                "ens36",
                "192.168.50.134",
            )
        )

        observations.append(
            make_icmp_observation(
                wan_timestamp,
                "ens33",
                "192.168.1.63",
            )
        )

    return correlate_nat_observations(
        observations
    )


def test_aggregate_four_repeated_alerts() -> None:
    """Aggregate four repeated ping alerts."""

    alerts = make_four_ping_alerts()

    assert len(alerts) == 4

    detections = aggregate_alerts(
        alerts
    )

    assert len(detections) == 1

    detection = detections[0]

    assert detection.count == 4

    assert detection.source_ip == (
        "192.168.50.134"
    )

    assert detection.destination_ip == (
        "8.8.8.8"
    )

    assert detection.signature_id == 9900001

    assert detection.signature == (
        "SECBOX TEST ICMP ALERT"
    )

    assert detection.severity == 3
    assert detection.category == "Test"

    assert (
        detection.nat_correlated_count
        == 4
    )

    assert detection.duration < timedelta(
        seconds=4
    )


def test_different_destination_is_separate() -> None:
    """Do not aggregate different destinations."""

    first = make_icmp_observation(
        "2026-08-30T07:18:08-0400",
        "ens36",
        "192.168.50.134",
        "8.8.8.8",
    )

    second = make_icmp_observation(
        "2026-08-30T07:18:09-0400",
        "ens36",
        "192.168.50.134",
        "1.1.1.1",
    )

    alerts = correlate_nat_observations(
        [
            first,
            second,
        ]
    )

    detections = aggregate_alerts(
        alerts
    )

    assert len(detections) == 2


def test_different_signature_is_separate() -> None:
    """Do not aggregate different signatures."""

    first = make_icmp_observation(
        "2026-08-30T07:18:08-0400",
        "ens36",
        "192.168.50.134",
        signature_id=9900001,
    )

    second = make_icmp_observation(
        "2026-08-30T07:18:09-0400",
        "ens36",
        "192.168.50.134",
        signature_id=9900002,
    )

    alerts = correlate_nat_observations(
        [
            first,
            second,
        ]
    )

    detections = aggregate_alerts(
        alerts
    )

    assert len(detections) == 2


def test_alert_outside_window_starts_new_detection() -> None:
    """Start a new detection after aggregation window."""

    first = make_icmp_observation(
        "2026-08-30T07:18:00-0400",
        "ens36",
        "192.168.50.134",
    )

    second = make_icmp_observation(
        "2026-08-30T07:18:31-0400",
        "ens36",
        "192.168.50.134",
    )

    alerts = correlate_nat_observations(
        [
            first,
            second,
        ]
    )

    detections = aggregate_alerts(
        alerts,
        window=timedelta(
            seconds=30
        ),
    )

    assert len(detections) == 2

    assert all(
        detection.count == 1
        for detection in detections
    )


def test_alert_inside_window_is_aggregated() -> None:
    """Aggregate alert exactly at the window boundary."""

    first = make_icmp_observation(
        "2026-08-30T07:18:00-0400",
        "ens36",
        "192.168.50.134",
    )

    second = make_icmp_observation(
        "2026-08-30T07:18:30-0400",
        "ens36",
        "192.168.50.134",
    )

    alerts = correlate_nat_observations(
        [
            first,
            second,
        ]
    )

    detections = aggregate_alerts(
        alerts,
        window=timedelta(
            seconds=30
        ),
    )

    assert len(detections) == 1
    assert detections[0].count == 2


def test_invalid_aggregation_window() -> None:
    """Reject non-positive aggregation window."""

    try:
        aggregate_alerts(
            [],
            window=timedelta(),
        )
    except ValueError as error:
        assert (
            "aggregation window must be positive"
            in str(error)
        )
    else:
        raise AssertionError(
            "ValueError was not raised"
        )
