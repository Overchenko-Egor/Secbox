"""Tests for the high-level IDS processing pipeline."""

from secbox.core.models import SecBoxConfig
from secbox.modules.ids.policy import (
    PolicyAction,
)
from secbox.modules.ids.processor import (
    process_eve_lines,
)
from secbox.modules.network.state import (
    NetworkAddress,
    NetworkInterfaceState,
)


def make_config() -> SecBoxConfig:
    """Create SecBox configuration for IDS tests."""

    return SecBoxConfig.model_validate(
        {
            "schema_version": 1,
            "system": {
                "hostname": "secbox",
            },
            "network": {
                "interfaces": [
                    {
                        "name": "ens33",
                        "role": "wan",
                        "ipv4_method": "dhcp",
                    },
                    {
                        "name": "ens36",
                        "role": "lan",
                        "ipv4_method": "static",
                        "ipv4_address": (
                            "192.168.50.1/24"
                        ),
                    },
                    {
                        "name": "ens38",
                        "role": "mgmt",
                        "ipv4_method": "static",
                        "ipv4_address": (
                            "192.168.100.2/24"
                        ),
                    },
                ],
            },
            "dhcp": [],
            "ids": {
                "enabled": True,
                "nat_correlation_window_ms": 10,
                "aggregation_window_seconds": 30,
                "policy": {
                    "minimum_alert_count": 2,
                    "minimum_block_count": 5,
                    "maximum_alert_severity": 2,
                    "maximum_block_severity": 1,
                },
                "automatic_blackhole": {
                    "enabled": False,
                    "timeout": "15m",
                },
            },
        }
    )


def make_runtime_interfaces() -> list[
    NetworkInterfaceState
]:
    """Create runtime interface state for IDS tests."""

    return [
        NetworkInterfaceState(
            name="ens33",
            mac="00:00:00:00:00:01",
            mtu=1500,
            operstate="UP",
            flags=[
                "BROADCAST",
                "MULTICAST",
                "UP",
            ],
            addresses=[
                NetworkAddress(
                    family="inet",
                    address="192.168.1.63",
                    prefixlen=24,
                    scope="global",
                ),
            ],
            is_loopback=False,
        ),
        NetworkInterfaceState(
            name="ens36",
            mac="00:00:00:00:00:02",
            mtu=1500,
            operstate="UP",
            flags=[
                "BROADCAST",
                "MULTICAST",
                "UP",
            ],
            addresses=[
                NetworkAddress(
                    family="inet",
                    address="192.168.50.1",
                    prefixlen=24,
                    scope="global",
                ),
            ],
            is_loopback=False,
        ),
        NetworkInterfaceState(
            name="ens38",
            mac="00:00:00:00:00:03",
            mtu=1500,
            operstate="UP",
            flags=[
                "BROADCAST",
                "MULTICAST",
                "UP",
            ],
            addresses=[
                NetworkAddress(
                    family="inet",
                    address="192.168.100.2",
                    prefixlen=24,
                    scope="global",
                ),
            ],
            is_loopback=False,
        ),
    ]


def make_icmp_alert(
    *,
    timestamp: str,
    interface: str,
    source_ip: str,
) -> str:
    """Create one controlled Suricata ICMP alert."""

    return (
        "{"
        f'"timestamp":"{timestamp}",'
        f'"in_iface":"{interface}",'
        '"event_type":"alert",'
        f'"src_ip":"{source_ip}",'
        '"dest_ip":"8.8.8.8",'
        '"proto":"ICMP",'
        '"icmp_type":8,'
        '"icmp_code":0,'
        '"alert":{'
        '"action":"allowed",'
        '"gid":1,'
        '"signature_id":9900001,'
        '"rev":1,'
        '"signature":"SECBOX TEST ICMP ALERT",'
        '"category":"Test",'
        '"severity":3'
        "}"
        "}"
    )


def test_complete_nat_processing_pipeline() -> None:
    """Process four ping packets observed before and after NAT."""

    lines: list[str] = []

    for second in range(4):
        lines.append(
            make_icmp_alert(
                timestamp=(
                    "2026-08-30T07:18:"
                    f"0{second}.100000-0400"
                ),
                interface="ens36",
                source_ip="192.168.50.134",
            )
        )

        lines.append(
            make_icmp_alert(
                timestamp=(
                    "2026-08-30T07:18:"
                    f"0{second}.100040-0400"
                ),
                interface="ens33",
                source_ip="192.168.1.63",
            )
        )

    result = process_eve_lines(
        lines,
        make_config(),
        make_runtime_interfaces(),
    )

    assert result.observation_count == 8

    assert (
        result.logical_alert_count
        == 4
    )

    assert result.detection_count == 1
    assert result.decision_count == 1

    detection = result.detections[0]

    assert detection.count == 4

    assert detection.source_ip == (
        "192.168.50.134"
    )

    assert detection.destination_ip == (
        "8.8.8.8"
    )

    decision = result.decisions[0]

    assert decision.action == (
        PolicyAction.LOG
    )

    assert result.parse_error_count == 0

    assert (
        result.classification_error_count
        == 0
    )


def test_non_alert_event_is_ignored() -> None:
    """Ignore Suricata EVE events that are not alerts."""

    lines = [
        (
            '{"timestamp":'
            '"2026-08-30T07:18:00-0400",'
            '"event_type":"stats"}'
        ),
    ]

    result = process_eve_lines(
        lines,
        make_config(),
        make_runtime_interfaces(),
    )

    assert result.observation_count == 0
    assert result.logical_alert_count == 0
    assert result.detection_count == 0
    assert result.decision_count == 0


def test_malformed_json_does_not_stop_pipeline() -> None:
    """Skip malformed EVE lines and count parser errors."""

    valid_line = make_icmp_alert(
        timestamp=(
            "2026-08-30T07:18:00-0400"
        ),
        interface="ens36",
        source_ip="192.168.50.134",
    )

    lines = [
        valid_line,
        "{this is invalid json",
        valid_line,
    ]

    result = process_eve_lines(
        lines,
        make_config(),
        make_runtime_interfaces(),
    )

    assert result.observation_count == 2
    assert result.parse_error_count == 1


def test_disabled_ids_returns_empty_result() -> None:
    """Do not process events when IDS is disabled."""

    config = make_config()

    config.ids.enabled = False

    result = process_eve_lines(
        [
            "{completely invalid json",
        ],
        config,
        make_runtime_interfaces(),
    )

    assert result.observation_count == 0
    assert result.logical_alert_count == 0
    assert result.detection_count == 0
    assert result.decision_count == 0

    assert result.parse_error_count == 0
