"""Tests for IDS policy engine."""

import ipaddress
import pytest

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
from secbox.modules.ids.policy import (
    IdsPolicyConfig,
    PolicyAction,
    evaluate_detection,
)


def make_context() -> IdsNetworkContext:
    """Create IDS network context."""

    return IdsNetworkContext(
        wan_interface="wan0",
        lan_interface="lan0",
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


def make_detection(
    *,
    source_ip: str,
    destination_ip: str,
    interface: str,
    severity: int,
    count: int,
    signature_id: int = 9000001,
):
    """Create one aggregated detection."""

    observations = []

    for index in range(count):
        timestamp = (
            "2026-08-30T07:18:"
            f"{index:02d}-0400"
        )

        event = parse_eve_line(
            f"""
            {{
              "timestamp": "{timestamp}",
              "in_iface": "{interface}",
              "event_type": "alert",
              "src_ip": "{source_ip}",
              "dest_ip": "{destination_ip}",
              "proto": "TCP",
              "src_port": 40000,
              "dest_port": 22,
              "alert": {{
                "action": "allowed",
                "gid": 1,
                "signature_id": {signature_id},
                "rev": 1,
                "signature": "TEST POLICY ALERT",
                "category": "Attempted Admin",
                "severity": {severity}
              }}
            }}
            """
        )

        assert event is not None

        observations.append(
            classify_alert(
                event,
                make_context(),
            )
        )

    alerts = correlate_nat_observations(
        observations
    )

    detections = aggregate_alerts(
        alerts
    )

    assert len(detections) == 1

    return detections[0]


def test_repeated_high_severity_wan_inbound_is_block_candidate() -> None:
    """Repeated high-severity WAN inbound traffic may be blocked."""

    detection = make_detection(
        source_ip="203.0.113.50",
        destination_ip="192.168.1.63",
        interface="wan0",
        severity=1,
        count=5,
    )

    decision = evaluate_detection(
        detection,
        IdsPolicyConfig(),
    )

    assert decision.action == (
        PolicyAction.BLOCK_CANDIDATE
    )

    assert "high-severity" in (
        decision.reason
    )


def test_single_high_severity_alert_is_only_logged() -> None:
    """A single severe alert must not trigger blocking."""

    detection = make_detection(
        source_ip="203.0.113.50",
        destination_ip="192.168.1.63",
        interface="wan0",
        severity=1,
        count=1,
    )

    decision = evaluate_detection(
        detection,
        IdsPolicyConfig(),
    )

    assert decision.action == (
        PolicyAction.LOG
    )


def test_repeated_medium_severity_wan_inbound_is_alert() -> None:
    """Repeated severity-2 WAN traffic generates an alert."""

    detection = make_detection(
        source_ip="203.0.113.50",
        destination_ip="192.168.1.63",
        interface="wan0",
        severity=2,
        count=3,
    )

    decision = evaluate_detection(
        detection,
        IdsPolicyConfig(),
    )

    assert decision.action == (
        PolicyAction.ALERT
    )


def test_low_severity_wan_inbound_is_logged() -> None:
    """Severity-3 traffic does not trigger automatic response."""

    detection = make_detection(
        source_ip="203.0.113.50",
        destination_ip="192.168.1.63",
        interface="wan0",
        severity=3,
        count=10,
    )

    decision = evaluate_detection(
        detection,
        IdsPolicyConfig(),
    )

    assert decision.action == (
        PolicyAction.LOG
    )


def test_lan_outbound_never_auto_blocks() -> None:
    """Do not automatically block LAN clients yet."""

    detection = make_detection(
        source_ip="192.168.50.134",
        destination_ip="8.8.8.8",
        interface="lan0",
        severity=1,
        count=20,
    )

    decision = evaluate_detection(
        detection,
        IdsPolicyConfig(),
    )

    assert decision.action == (
        PolicyAction.LOG
    )

    assert "disabled" in decision.reason


def test_protected_source_is_never_block_candidate() -> None:
    """Protected networks override automatic response."""

    detection = make_detection(
        source_ip="192.168.100.10",
        destination_ip="192.168.1.63",
        interface="wan0",
        severity=1,
        count=20,
    )

    decision = evaluate_detection(
        detection,
        IdsPolicyConfig(
            protected_networks=(
                ipaddress.IPv4Network(
                    "192.168.100.0/24"
                ),
            ),
        ),
    )

    assert decision.action == (
        PolicyAction.LOG
    )

    assert "protected network" in (
        decision.reason
    )


@pytest.mark.parametrize(
    "source_ip",
    [
        "192.168.1.63",
        "192.168.50.1",
        "192.168.100.2",
    ],
)
def test_local_secbox_address_is_never_block_candidate(
    source_ip: str,
) -> None:
    """A local SecBox address must never become a block candidate."""

    detection = make_detection(
        source_ip=source_ip,
        destination_ip="192.168.1.63",
        interface="wan0",
        severity=1,
        count=20,
    )

    protected_networks = tuple(
        ipaddress.IPv4Network(
            f"{address}/32"
        )
        for address in (
            "192.168.1.63",
            "192.168.50.1",
            "192.168.100.2",
        )
    )

    decision = evaluate_detection(
        detection,
        IdsPolicyConfig(
            protected_networks=(
                protected_networks
            ),
        ),
    )

    assert decision.action == (
        PolicyAction.LOG
    )

    assert "protected network" in (
        decision.reason
    )


def test_custom_block_threshold_is_respected() -> None:
    """Use configurable repetition thresholds."""

    detection = make_detection(
        source_ip="203.0.113.50",
        destination_ip="192.168.1.63",
        interface="wan0",
        severity=1,
        count=7,
    )

    decision = evaluate_detection(
        detection,
        IdsPolicyConfig(
            minimum_block_count=10,
        ),
    )

    assert decision.action == (
        PolicyAction.ALERT
    )


def test_invalid_policy_thresholds_fail() -> None:
    """Reject block threshold lower than alert threshold."""

    with pytest.raises(
        ValueError,
        match="minimum_block_count",
    ):
        IdsPolicyConfig(
            minimum_alert_count=5,
            minimum_block_count=2,
        )


def test_zero_alert_count_threshold_fails() -> None:
    """Reject zero minimum alert count."""

    with pytest.raises(
        ValueError,
        match="minimum_alert_count",
    ):
        IdsPolicyConfig(
            minimum_alert_count=0,
        )


def test_zero_block_count_threshold_fails() -> None:
    """Reject zero minimum block count."""

    with pytest.raises(
        ValueError,
        match="minimum_block_count",
    ):
        IdsPolicyConfig(
            minimum_block_count=0,
        )


def test_invalid_alert_severity_fails() -> None:
    """Reject Suricata severity outside supported range."""

    with pytest.raises(
        ValueError,
        match="maximum_alert_severity",
    ):
        IdsPolicyConfig(
            maximum_alert_severity=4,
        )


def test_invalid_block_severity_fails() -> None:
    """Reject block severity outside supported range."""

    with pytest.raises(
        ValueError,
        match="maximum_block_severity",
    ):
        IdsPolicyConfig(
            maximum_block_severity=0,
        )


def test_block_severity_cannot_be_less_restrictive() -> None:
    """Reject block threshold weaker than alert threshold."""

    with pytest.raises(
        ValueError,
        match="block severity threshold",
    ):
        IdsPolicyConfig(
            maximum_alert_severity=2,
            maximum_block_severity=3,
        )


