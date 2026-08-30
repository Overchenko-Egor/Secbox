"""Policy evaluation for aggregated IDS detections."""

import ipaddress
from dataclasses import dataclass
from enum import StrEnum

from secbox.modules.ids.aggregation import Detection
from secbox.modules.ids.classification import (
    TrafficClass,
)


class PolicyAction(StrEnum):
    """Possible IDS policy decisions."""

    IGNORE = "ignore"
    LOG = "log"
    ALERT = "alert"
    BLOCK_CANDIDATE = "block_candidate"


@dataclass(frozen=True)
class IdsPolicyConfig:
    """IDS policy thresholds and protection rules."""

    minimum_alert_count: int = 2
    minimum_block_count: int = 5

    maximum_alert_severity: int = 2
    maximum_block_severity: int = 1

    protected_networks: tuple[
        ipaddress.IPv4Network,
        ...,
    ] = ()

    def __post_init__(self) -> None:
        """Validate policy thresholds."""

        if self.minimum_alert_count < 1:
            raise ValueError(
                "minimum_alert_count must be at least 1"
            )

        if self.minimum_block_count < 1:
            raise ValueError(
                "minimum_block_count must be at least 1"
            )

        if self.minimum_block_count < (
            self.minimum_alert_count
        ):
            raise ValueError(
                "minimum_block_count must be greater "
                "than or equal to minimum_alert_count"
            )

        if not 1 <= self.maximum_alert_severity <= 3:
            raise ValueError(
                "maximum_alert_severity must be between 1 and 3"
            )

        if not 1 <= self.maximum_block_severity <= 3:
            raise ValueError(
                "maximum_block_severity must be between 1 and 3"
            )

        if (
            self.maximum_block_severity
            > self.maximum_alert_severity
        ):
            raise ValueError(
                "block severity threshold cannot be "
                "less restrictive than alert threshold"
            )

@dataclass(frozen=True)
class PolicyDecision:
    """Result of evaluating one detection."""

    action: PolicyAction
    detection: Detection
    reason: str

    @property
    def source_ip(self) -> str:
        """Return detection source IP."""

        return self.detection.source_ip

    @property
    def signature_id(self) -> int:
        """Return Suricata signature ID."""

        return self.detection.signature_id


def _source_is_protected(
    source_ip: str,
    protected_networks: tuple[
        ipaddress.IPv4Network,
        ...,
    ],
) -> bool:
    """Check whether source belongs to a protected network."""

    try:
        address = ipaddress.ip_address(
            source_ip
        )
    except ValueError:
        return False

    if not isinstance(
        address,
        ipaddress.IPv4Address,
    ):
        return False

    return any(
        address in network
        for network in protected_networks
    )


def _get_traffic_class(
    detection: Detection,
) -> TrafficClass:
    """Return traffic class of the canonical alert."""

    return (
        detection.alerts[0]
        .canonical
        .traffic_class
    )


def evaluate_detection(
    detection: Detection,
    config: IdsPolicyConfig,
) -> PolicyDecision:
    """Evaluate one aggregated IDS detection."""

    if detection.count <= 0:
        return PolicyDecision(
            action=PolicyAction.IGNORE,
            detection=detection,
            reason="detection contains no alerts",
        )

    if _source_is_protected(
        detection.source_ip,
        config.protected_networks,
    ):
        return PolicyDecision(
            action=PolicyAction.LOG,
            detection=detection,
            reason="source belongs to protected network",
        )

    traffic_class = _get_traffic_class(
        detection
    )

    if traffic_class == TrafficClass.UNKNOWN:
        return PolicyDecision(
            action=PolicyAction.LOG,
            detection=detection,
            reason="traffic direction is unknown",
        )

    if traffic_class in {
        TrafficClass.LAN_OUTBOUND_PRE_NAT,
        TrafficClass.WAN_OUTBOUND_POST_NAT,
        TrafficClass.LAN_INBOUND,
    }:
        return PolicyDecision(
            action=PolicyAction.LOG,
            detection=detection,
            reason=(
                "automatic blocking is disabled "
                "for this traffic class"
            ),
        )

    if traffic_class != TrafficClass.WAN_INBOUND:
        return PolicyDecision(
            action=PolicyAction.LOG,
            detection=detection,
            reason="unsupported traffic class",
        )

    if (
        detection.severity
        <= config.maximum_block_severity
        and detection.count
        >= config.minimum_block_count
    ):
        return PolicyDecision(
            action=PolicyAction.BLOCK_CANDIDATE,
            detection=detection,
            reason=(
                "repeated high-severity inbound "
                "WAN detection"
            ),
        )

    if (
        detection.severity
        <= config.maximum_alert_severity
        and detection.count
        >= config.minimum_alert_count
    ):
        return PolicyDecision(
            action=PolicyAction.ALERT,
            detection=detection,
            reason=(
                "repeated inbound WAN detection "
                "meets alert threshold"
            ),
        )

    return PolicyDecision(
        action=PolicyAction.LOG,
        detection=detection,
        reason=(
            "detection does not meet automatic "
            "response thresholds"
        ),
    )
