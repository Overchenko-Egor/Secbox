"""Tests for IDS traffic classification."""

import ipaddress
import pytest

from secbox.modules.ids.classification import (
    IdsNetworkContext,
    TrafficClass,
    classify_alert,
    TrafficClassificationError,
)
from secbox.modules.ids.parser import (
    parse_eve_line,
)


def make_context() -> IdsNetworkContext:
    """Create test SecBox network context."""

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


def test_classify_lan_outbound_pre_nat() -> None:
    """Classify LAN traffic before NAT."""

    event = parse_eve_line(
        """
        {
          "timestamp": "2026-08-30T07:18:08.645338-0400",
          "flow_id": 238434534371613,
          "in_iface": "lan0",
          "event_type": "alert",
          "src_ip": "192.168.50.134",
          "dest_ip": "8.8.8.8",
          "proto": "ICMP",
          "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 9900001,
            "rev": 1,
            "signature": "SECBOX TEST ICMP ALERT",
            "category": "",
            "severity": 3
          }
        }
        """
    )

    assert event is not None

    observation = classify_alert(
        event,
        make_context(),
    )

    assert observation.traffic_class == (
        TrafficClass.LAN_OUTBOUND_PRE_NAT
    )

    assert observation.source_ip == (
        "192.168.50.134"
    )


def test_classify_wan_outbound_post_nat() -> None:
    """Classify outbound traffic after NAT."""

    event = parse_eve_line(
        """
        {
          "timestamp": "2026-08-30T07:18:08.645380-0400",
          "flow_id": 238614233346066,
          "in_iface": "wan0",
          "event_type": "alert",
          "src_ip": "192.168.1.63",
          "dest_ip": "8.8.8.8",
          "proto": "ICMP",
          "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 9900001,
            "rev": 1,
            "signature": "SECBOX TEST ICMP ALERT",
            "category": "",
            "severity": 3
          }
        }
        """
    )

    assert event is not None

    observation = classify_alert(
        event,
        make_context(),
    )

    assert observation.traffic_class == (
        TrafficClass.WAN_OUTBOUND_POST_NAT
    )


def test_classify_wan_inbound() -> None:
    """Classify traffic arriving from WAN."""

    event = parse_eve_line(
        """
        {
          "timestamp": "2026-08-30T07:20:00-0400",
          "in_iface": "wan0",
          "event_type": "alert",
          "src_ip": "203.0.113.50",
          "dest_ip": "192.168.1.63",
          "proto": "TCP",
          "src_port": 45678,
          "dest_port": 22,
          "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 9000001,
            "rev": 1,
            "signature": "TEST WAN INBOUND",
            "category": "Test",
            "severity": 1
          }
        }
        """
    )

    assert event is not None

    observation = classify_alert(
        event,
        make_context(),
    )

    assert observation.traffic_class == (
        TrafficClass.WAN_INBOUND
    )

    assert observation.source_ip == (
        "203.0.113.50"
    )


def test_classify_lan_inbound() -> None:
    """Classify traffic delivered toward the LAN."""

    event = parse_eve_line(
        """
        {
          "timestamp": "2026-08-30T07:20:00-0400",
          "in_iface": "lan0",
          "event_type": "alert",
          "src_ip": "8.8.8.8",
          "dest_ip": "192.168.50.134",
          "proto": "TCP",
          "src_port": 443,
          "dest_port": 55000,
          "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 9000002,
            "rev": 1,
            "signature": "TEST LAN INBOUND",
            "category": "Test",
            "severity": 1
          }
        }
        """
    )

    assert event is not None

    observation = classify_alert(
        event,
        make_context(),
    )

    assert observation.traffic_class == (
        TrafficClass.LAN_INBOUND
    )


def test_unknown_interface_is_not_classified() -> None:
    """Do not classify events observed on other interfaces."""

    event = parse_eve_line(
        """
        {
          "timestamp": "2026-08-30T07:20:00-0400",
          "in_iface": "mgmt0",
          "event_type": "alert",
          "src_ip": "192.168.100.10",
          "dest_ip": "192.168.100.2",
          "proto": "TCP",
          "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 9000003,
            "rev": 1,
            "signature": "TEST MGMT",
            "category": "Test",
            "severity": 1
          }
        }
        """
    )

    assert event is not None

    observation = classify_alert(
        event,
        make_context(),
    )

    assert observation.traffic_class == (
        TrafficClass.UNKNOWN
    )


def test_lan_to_lan_is_unknown() -> None:
    """Do not treat local LAN communication as Internet traffic."""

    event = parse_eve_line(
        """
        {
          "timestamp": "2026-08-30T07:20:00-0400",
          "in_iface": "lan0",
          "event_type": "alert",
          "src_ip": "192.168.50.100",
          "dest_ip": "192.168.50.200",
          "proto": "TCP",
          "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 9000004,
            "rev": 1,
            "signature": "TEST LAN LOCAL",
            "category": "Test",
            "severity": 1
          }
        }
        """
    )

    assert event is not None

    observation = classify_alert(
        event,
        make_context(),
    )

    assert observation.traffic_class == (
        TrafficClass.UNKNOWN
    )


def test_ipv6_alert_is_unknown() -> None:
    """Ignore IPv6 until IPv6 IDS policy is implemented."""

    event = parse_eve_line(
        """
        {
          "timestamp": "2026-08-30T07:20:00-0400",
          "in_iface": "wan0",
          "event_type": "alert",
          "src_ip": "2001:db8::10",
          "dest_ip": "2001:db8::20",
          "proto": "TCP",
          "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 9000005,
            "rev": 1,
            "signature": "TEST IPV6",
            "category": "Test",
            "severity": 1
          }
        }
        """
    )

    assert event is not None

    observation = classify_alert(
        event,
        make_context(),
    )

    assert observation.traffic_class == (
        TrafficClass.UNKNOWN
    )


def test_invalid_ip_fails() -> None:
    """Reject malformed IP addresses."""

    event = parse_eve_line(
        """
        {
          "timestamp": "2026-08-30T07:20:00-0400",
          "in_iface": "wan0",
          "event_type": "alert",
          "src_ip": "not-an-ip",
          "dest_ip": "192.168.1.63",
          "proto": "TCP",
          "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 9000006,
            "rev": 1,
            "signature": "TEST INVALID IP",
            "category": "Test",
            "severity": 1
          }
        }
        """
    )

    assert event is not None

    with pytest.raises(
        TrafficClassificationError,
        match="invalid IP address",
    ):
        classify_alert(
            event,
            make_context(),
        )
