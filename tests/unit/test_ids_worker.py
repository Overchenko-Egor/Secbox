"""Tests for the stateful streaming IDS worker."""

from secbox.core.models import SecBoxConfig
from secbox.modules.ids.policy import (
    PolicyAction,
)
from secbox.modules.ids.worker import (
    StreamingIdsWorker,
)
from secbox.modules.network.state import (
    NetworkAddress,
    NetworkInterfaceState,
)


def make_config(
    *,
    aggregation_window_seconds: int = 30,
) -> SecBoxConfig:
    """Create SecBox configuration for worker tests."""

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
                "aggregation_window_seconds": (
                    aggregation_window_seconds
                ),
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
    """Create runtime network state."""

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


def make_alert(
    *,
    timestamp: str,
    interface: str,
    source_ip: str,
    destination_ip: str,
    severity: int,
    signature_id: int = 9900001,
) -> str:
    """Create one Suricata alert line."""

    return (
        "{"
        f'"timestamp":"{timestamp}",'
        f'"in_iface":"{interface}",'
        '"event_type":"alert",'
        f'"src_ip":"{source_ip}",'
        f'"dest_ip":"{destination_ip}",'
        '"proto":"TCP",'
        '"src_port":40000,'
        '"dest_port":22,'
        '"alert":{'
        '"action":"allowed",'
        '"gid":1,'
        f'"signature_id":{signature_id},'
        '"rev":1,'
        '"signature":"SECBOX WORKER TEST",'
        '"category":"Attempted Admin",'
        f'"severity":{severity}'
        "}"
        "}"
    )


def test_nat_pair_is_correlated_before_aggregation() -> None:
    """Combine LAN and WAN observations into one logical alert."""

    worker = StreamingIdsWorker(
        make_config(),
        make_runtime_interfaces(),
    )

    lan_line = make_alert(
        timestamp=(
            "2026-09-05T10:00:00.100000+00:00"
        ),
        interface="ens36",
        source_ip="192.168.50.134",
        destination_ip="8.8.8.8",
        severity=3,
    )

    wan_line = make_alert(
        timestamp=(
            "2026-09-05T10:00:00.100040+00:00"
        ),
        interface="ens33",
        source_ip="192.168.1.63",
        destination_ip="8.8.8.8",
        severity=3,
    )

    assert worker.ingest_line(
        lan_line,
        now=100.000,
    ) == []

    assert worker.stats().pending_observations == 1

    assert worker.ingest_line(
        wan_line,
        now=100.001,
    ) == []

    stats = worker.stats()

    assert stats.pending_observations == 0
    assert stats.logical_alerts == 1
    assert stats.active_detections == 1

    decisions = worker.close()

    assert len(decisions) == 1

    detection = (
        decisions[0].detection
    )

    assert detection.count == 1

    assert detection.source_ip == (
        "192.168.50.134"
    )

    assert (
        detection.alerts[0]
        .nat_correlated
        is True
    )


def test_unpaired_observation_waits_for_correlation_window() -> None:
    """Do not finalize an unmatched alert immediately."""

    worker = StreamingIdsWorker(
        make_config(),
        make_runtime_interfaces(),
    )

    line = make_alert(
        timestamp=(
            "2026-09-05T10:00:00+00:00"
        ),
        interface="ens33",
        source_ip="203.0.113.50",
        destination_ip="192.168.1.63",
        severity=1,
    )

    assert worker.ingest_line(
        line,
        now=100.000,
    ) == []

    assert worker.stats().pending_observations == 1

    assert worker.flush(
        now=100.005,
    ) == []

    assert worker.stats().pending_observations == 1

    assert worker.flush(
        now=100.011,
    ) == []

    stats = worker.stats()

    assert stats.pending_observations == 0
    assert stats.logical_alerts == 1
    assert stats.active_detections == 1


def test_five_inbound_alerts_become_block_candidate() -> None:
    """Aggregate repeated severe WAN alerts before policy evaluation."""

    worker = StreamingIdsWorker(
        make_config(),
        make_runtime_interfaces(),
    )

    for index in range(5):
        line = make_alert(
            timestamp=(
                "2026-09-05T10:00:"
                f"0{index}+00:00"
            ),
            interface="ens33",
            source_ip="203.0.113.50",
            destination_ip="192.168.1.63",
            severity=1,
            signature_id=9000001,
        )

        decisions = worker.ingest_line(
            line,
            now=float(index),
        )

        assert decisions == []

    decisions = worker.flush(
        now=31.0,
    )

    assert len(decisions) == 1

    decision = decisions[0]

    assert decision.action == (
        PolicyAction.BLOCK_CANDIDATE
    )

    assert (
        decision.detection.count
        == 5
    )

    assert (
        decision.detection.source_ip
        == "203.0.113.50"
    )


def test_four_nat_pairs_count_as_four_not_eight() -> None:
    """Count logical packets after NAT deduplication."""

    worker = StreamingIdsWorker(
        make_config(),
        make_runtime_interfaces(),
    )

    for index in range(4):
        base = float(index)

        lan_line = make_alert(
            timestamp=(
                "2026-09-05T10:00:"
                f"0{index}.100000+00:00"
            ),
            interface="ens36",
            source_ip="192.168.50.134",
            destination_ip="8.8.8.8",
            severity=3,
        )

        wan_line = make_alert(
            timestamp=(
                "2026-09-05T10:00:"
                f"0{index}.100040+00:00"
            ),
            interface="ens33",
            source_ip="192.168.1.63",
            destination_ip="8.8.8.8",
            severity=3,
        )

        worker.ingest_line(
            lan_line,
            now=base,
        )

        worker.ingest_line(
            wan_line,
            now=base + 0.001,
        )

    decisions = worker.close()

    assert len(decisions) == 1

    detection = (
        decisions[0].detection
    )

    assert detection.count == 4

    assert len(
        detection.alerts
    ) == 4

    assert all(
        alert.nat_correlated
        for alert in detection.alerts
    )


def test_malformed_json_does_not_stop_worker() -> None:
    """Count malformed lines without terminating worker."""

    worker = StreamingIdsWorker(
        make_config(),
        make_runtime_interfaces(),
    )

    decisions = worker.ingest_line(
        "{invalid json",
        now=1.0,
    )

    assert decisions == []

    stats = worker.stats()

    assert stats.received_lines == 1
    assert stats.parse_errors == 1


def test_non_alert_event_is_ignored() -> None:
    """Ignore non-alert EVE events."""

    worker = StreamingIdsWorker(
        make_config(),
        make_runtime_interfaces(),
    )

    line = (
        "{"
        '"timestamp":'
        '"2026-09-05T10:00:00+00:00",'
        '"event_type":"stats"'
        "}"
    )

    assert worker.ingest_line(
        line,
        now=1.0,
    ) == []

    stats = worker.stats()

    assert stats.received_lines == 1
    assert stats.ignored_events == 1
    assert stats.parsed_alerts == 0


def test_force_close_finalizes_pending_state() -> None:
    """Finalize both correlation and aggregation buffers on shutdown."""

    worker = StreamingIdsWorker(
        make_config(),
        make_runtime_interfaces(),
    )

    line = make_alert(
        timestamp=(
            "2026-09-05T10:00:00+00:00"
        ),
        interface="ens33",
        source_ip="203.0.113.50",
        destination_ip="192.168.1.63",
        severity=1,
    )

    worker.ingest_line(
        line,
        now=100.0,
    )

    assert (
        worker.stats()
        .pending_observations
        == 1
    )

    decisions = worker.close()

    assert len(decisions) == 1

    stats = worker.stats()

    assert stats.pending_observations == 0
    assert stats.active_detections == 0
    assert stats.detections == 1
    assert stats.decisions == 1
