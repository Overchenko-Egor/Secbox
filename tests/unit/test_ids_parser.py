"""Tests for Suricata EVE parser."""

import pytest

from secbox.modules.ids.parser import (
    SuricataEveParseError,
    parse_eve_line,
)


def test_parse_suricata_icmp_alert() -> None:
    """Parse the controlled SecBox ICMP test alert."""

    line = """
    {
      "timestamp": "2026-08-30T07:18:08.645338-0400",
      "flow_id": 238434534371613,
      "in_iface": "ens36",
      "event_type": "alert",
      "src_ip": "192.168.50.134",
      "dest_ip": "8.8.8.8",
      "proto": "ICMP",
      "icmp_type": 8,
      "icmp_code": 0,
      "pkt_src": "wire/pcap",
      "alert": {
        "action": "allowed",
        "gid": 1,
        "signature_id": 9900001,
        "rev": 1,
        "signature": "SECBOX TEST ICMP ALERT",
        "category": "",
        "severity": 3
      },
      "direction": "to_server",
      "flow": {
        "pkts_toserver": 1,
        "pkts_toclient": 0,
        "bytes_toserver": 98,
        "bytes_toclient": 0,
        "start": "2026-08-30T07:18:08.645338-0400",
        "src_ip": "192.168.50.134",
        "dest_ip": "8.8.8.8"
      }
    }
    """

    event = parse_eve_line(line)

    assert event is not None
    assert event.event_type == "alert"
    assert event.in_iface == "ens36"
    assert event.src_ip == "192.168.50.134"
    assert event.dest_ip == "8.8.8.8"
    assert event.proto == "ICMP"
    assert event.icmp_type == 8

    assert event.alert.signature_id == 9900001
    assert event.alert.signature == (
        "SECBOX TEST ICMP ALERT"
    )
    assert event.alert.severity == 3

    assert event.flow is not None
    assert event.flow.pkts_toserver == 1


def test_parse_suricata_et_alert() -> None:
    """Parse a real Emerging Threats alert."""

    line = """
    {
      "timestamp": "2026-08-30T07:07:29.224735-0400",
      "in_iface": "ens36",
      "event_type": "alert",
      "src_ip": "192.168.50.134",
      "src_port": 57336,
      "dest_ip": "201.51.8.95",
      "dest_port": 80,
      "proto": "TCP",
      "app_proto": "http",
      "flow_id": 494627000191626,
      "alert": {
        "action": "allowed",
        "gid": 1,
        "signature_id": 2034567,
        "rev": 1,
        "signature": "ET HUNTING curl User-Agent to Dotted Quad",
        "category": "Potentially Bad Traffic",
        "severity": 2,
        "metadata": {
          "attack_target": [
            "Client_Endpoint"
          ],
          "confidence": [
            "Medium"
          ]
        }
      }
    }
    """

    event = parse_eve_line(line)

    assert event is not None
    assert event.in_iface == "ens36"
    assert event.src_port == 57336
    assert event.dest_port == 80
    assert event.app_proto == "http"

    assert event.alert.signature_id == 2034567
    assert event.alert.severity == 2

    assert event.alert.metadata is not None
    assert event.alert.metadata["confidence"] == [
        "Medium"
    ]


def test_ignore_non_alert_event() -> None:
    """Ignore valid EVE events that are not alerts."""

    line = """
    {
      "timestamp": "2026-08-30T07:08:22.551656-0400",
      "event_type": "stats",
      "stats": {
        "uptime": 222
      }
    }
    """

    assert parse_eve_line(line) is None


def test_reject_invalid_json() -> None:
    """Reject malformed JSON."""

    with pytest.raises(
        SuricataEveParseError,
        match="invalid EVE JSON",
    ):
        parse_eve_line(
            "{invalid-json"
        )


def test_reject_incomplete_alert() -> None:
    """Reject alert events missing required fields."""

    line = """
    {
      "timestamp": "2026-08-30T07:18:08-0400",
      "event_type": "alert",
      "src_ip": "192.168.50.134"
    }
    """

    with pytest.raises(
        SuricataEveParseError,
        match="invalid Suricata alert event",
    ):
        parse_eve_line(line)
