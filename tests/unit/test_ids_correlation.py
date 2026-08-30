"""Tests for IDS NAT correlation."""

from datetime import timedelta

from secbox.modules.ids.classification import (
    IdsNetworkContext,
    TrafficClass,
    classify_alert,
)
from secbox.modules.ids.correlation import (
    correlate_nat_observations,
)
from secbox.modules.ids.parser import (
    parse_eve_line,
)

import ipaddress


def make_context() -> IdsNetworkContext:
    """Create network context used by correlation tests."""

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


def parse_observation(
    line: str,
):
    """Parse and classify a Suricata alert."""

    event = parse_eve_line(line)

    assert event is not None

    return classify_alert(
        event,
        make_context(),
    )


def test_correlate_real_icmp_nat_pair() -> None:
    """Combine real LAN/WAN observations of one ping."""

    lan = parse_observation(
        """
        {
          "timestamp":
            "2026-08-30T07:18:08.645338-0400",
          "flow_id": 238434534371613,
          "in_iface": "ens36",
          "event_type": "alert",
          "src_ip": "192.168.50.134",
          "dest_ip": "8.8.8.8",
          "proto": "ICMP",
          "icmp_type": 8,
          "icmp_code": 0,
          "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 9900001,
            "rev": 1,
            "signature":
              "SECBOX TEST ICMP ALERT",
            "category": "",
            "severity": 3
          }
        }
        """
    )

    wan = parse_observation(
        """
        {
          "timestamp":
            "2026-08-30T07:18:08.645380-0400",
          "flow_id": 238614233346066,
          "in_iface": "ens33",
          "event_type": "alert",
          "src_ip": "192.168.1.63",
          "dest_ip": "8.8.8.8",
          "proto": "ICMP",
          "icmp_type": 8,
          "icmp_code": 0,
          "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 9900001,
            "rev": 1,
            "signature":
              "SECBOX TEST ICMP ALERT",
            "category": "",
            "severity": 3
          }
        }
        """
    )

    result = correlate_nat_observations(
        [
            wan,
            lan,
        ]
    )

    assert len(result) == 1

    alert = result[0]

    assert alert.nat_correlated is True

    assert alert.canonical.traffic_class == (
        TrafficClass.LAN_OUTBOUND_PRE_NAT
    )

    assert alert.source_ip == (
        "192.168.50.134"
    )

    assert alert.destination_ip == "8.8.8.8"
    assert alert.signature_id == 9900001

    assert set(alert.interfaces) == {
        "ens33",
        "ens36",
    }

    assert alert.correlation_delta_ms is not None

    assert alert.correlation_delta_ms < 1


def test_repeated_pings_become_separate_alerts() -> None:
    """Deduplicate interfaces without collapsing repeated packets."""

    observations = []

    for second in (
        "08.645338",
        "09.646488",
    ):
        observations.append(
            parse_observation(
                f"""
                {{
                  "timestamp":
                    "2026-08-30T07:18:{second}-0400",
                  "in_iface": "ens36",
                  "event_type": "alert",
                  "src_ip": "192.168.50.134",
                  "dest_ip": "8.8.8.8",
                  "proto": "ICMP",
                  "icmp_type": 8,
                  "icmp_code": 0,
                  "alert": {{
                    "action": "allowed",
                    "gid": 1,
                    "signature_id": 9900001,
                    "rev": 1,
                    "signature":
                      "SECBOX TEST ICMP ALERT",
                    "category": "",
                    "severity": 3
                  }}
                }}
                """
            )
        )

    for second in (
        "08.645380",
        "09.646519",
    ):
        observations.append(
            parse_observation(
                f"""
                {{
                  "timestamp":
                    "2026-08-30T07:18:{second}-0400",
                  "in_iface": "ens33",
                  "event_type": "alert",
                  "src_ip": "192.168.1.63",
                  "dest_ip": "8.8.8.8",
                  "proto": "ICMP",
                  "icmp_type": 8,
                  "icmp_code": 0,
                  "alert": {{
                    "action": "allowed",
                    "gid": 1,
                    "signature_id": 9900001,
                    "rev": 1,
                    "signature":
                      "SECBOX TEST ICMP ALERT",
                    "category": "",
                    "severity": 3
                  }}
                }}
                """
            )
        )

    result = correlate_nat_observations(
        observations
    )

    assert len(result) == 2

    assert all(
        alert.nat_correlated
        for alert in result
    )

    assert all(
        alert.source_ip
        == "192.168.50.134"
        for alert in result
    )


def test_do_not_correlate_different_signatures() -> None:
    """Do not merge different Suricata signatures."""

    lan = parse_observation(
        """
        {
          "timestamp":
            "2026-08-30T07:18:08.645338-0400",
          "in_iface": "ens36",
          "event_type": "alert",
          "src_ip": "192.168.50.134",
          "dest_ip": "8.8.8.8",
          "proto": "ICMP",
          "icmp_type": 8,
          "icmp_code": 0,
          "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 9900001,
            "rev": 1,
            "signature": "TEST ONE",
            "category": "",
            "severity": 3
          }
        }
        """
    )

    wan = parse_observation(
        """
        {
          "timestamp":
            "2026-08-30T07:18:08.645380-0400",
          "in_iface": "ens33",
          "event_type": "alert",
          "src_ip": "192.168.1.63",
          "dest_ip": "8.8.8.8",
          "proto": "ICMP",
          "icmp_type": 8,
          "icmp_code": 0,
          "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 9900002,
            "rev": 1,
            "signature": "TEST TWO",
            "category": "",
            "severity": 3
          }
        }
        """
    )

    result = correlate_nat_observations(
        [
            lan,
            wan,
        ]
    )

    assert len(result) == 2

    assert all(
        not alert.nat_correlated
        for alert in result
    )


def test_do_not_correlate_outside_window() -> None:
    """Do not merge observations that are too far apart."""

    lan = parse_observation(
        """
        {
          "timestamp":
            "2026-08-30T07:18:08.000000-0400",
          "in_iface": "ens36",
          "event_type": "alert",
          "src_ip": "192.168.50.134",
          "dest_ip": "8.8.8.8",
          "proto": "ICMP",
          "icmp_type": 8,
          "icmp_code": 0,
          "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 9900001,
            "rev": 1,
            "signature": "TEST",
            "category": "",
            "severity": 3
          }
        }
        """
    )

    wan = parse_observation(
        """
        {
          "timestamp":
            "2026-08-30T07:18:08.100000-0400",
          "in_iface": "ens33",
          "event_type": "alert",
          "src_ip": "192.168.1.63",
          "dest_ip": "8.8.8.8",
          "proto": "ICMP",
          "icmp_type": 8,
          "icmp_code": 0,
          "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 9900001,
            "rev": 1,
            "signature": "TEST",
            "category": "",
            "severity": 3
          }
        }
        """
    )

    result = correlate_nat_observations(
        [
            lan,
            wan,
        ],
        window=timedelta(
            milliseconds=10
        ),
    )

    assert len(result) == 2
    assert result[0].nat_correlated is False
    assert result[1].nat_correlated is False


def test_do_not_correlate_different_destination() -> None:
    """Do not merge traffic to different destinations."""

    lan = parse_observation(
        """
        {
          "timestamp":
            "2026-08-30T07:18:08.645338-0400",
          "in_iface": "ens36",
          "event_type": "alert",
          "src_ip": "192.168.50.134",
          "dest_ip": "8.8.8.8",
          "proto": "ICMP",
          "icmp_type": 8,
          "icmp_code": 0,
          "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 9900001,
            "rev": 1,
            "signature": "TEST",
            "category": "",
            "severity": 3
          }
        }
        """
    )

    wan = parse_observation(
        """
        {
          "timestamp":
            "2026-08-30T07:18:08.645380-0400",
          "in_iface": "ens33",
          "event_type": "alert",
          "src_ip": "192.168.1.63",
          "dest_ip": "1.1.1.1",
          "proto": "ICMP",
          "icmp_type": 8,
          "icmp_code": 0,
          "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 9900001,
            "rev": 1,
            "signature": "TEST",
            "category": "",
            "severity": 3
          }
        }
        """
    )

    result = correlate_nat_observations(
        [
            lan,
            wan,
        ]
    )

    assert len(result) == 2
