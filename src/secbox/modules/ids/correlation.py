"""Correlation and deduplication of IDS observations."""

from dataclasses import dataclass
from datetime import timedelta

from secbox.modules.ids.classification import (
    TrafficClass,
    TrafficObservation,
)


DEFAULT_NAT_CORRELATION_WINDOW = timedelta(
    milliseconds=10
)


@dataclass(frozen=True)
class CorrelatedAlert:
    """One logical IDS alert built from one or more observations."""

    canonical: TrafficObservation
    observations: tuple[TrafficObservation, ...]
    nat_correlated: bool
    correlation_delta_ms: float | None = None

    @property
    def source_ip(self) -> str:
        """Return the canonical source address."""

        return self.canonical.source_ip

    @property
    def destination_ip(self) -> str:
        """Return the canonical destination address."""

        return self.canonical.destination_ip

    @property
    def signature_id(self) -> int:
        """Return Suricata signature ID."""

        return (
            self.canonical.event.alert.signature_id
        )

    @property
    def interfaces(self) -> tuple[str, ...]:
        """Return interfaces where the alert was observed."""

        return tuple(
            observation.interface
            for observation in self.observations
            if observation.interface is not None
        )


def _same_optional_value(
    first: object | None,
    second: object | None,
) -> bool:
    """Compare optional values without rejecting missing metadata."""

    if first is None or second is None:
        return True

    return first == second


def _is_nat_pair_candidate(
    lan_observation: TrafficObservation,
    wan_observation: TrafficObservation,
) -> bool:
    """Check whether two observations can represent one NATed packet."""

    if (
        lan_observation.traffic_class
        != TrafficClass.LAN_OUTBOUND_PRE_NAT
    ):
        return False

    if (
        wan_observation.traffic_class
        != TrafficClass.WAN_OUTBOUND_POST_NAT
    ):
        return False

    lan_event = lan_observation.event
    wan_event = wan_observation.event

    if (
        lan_event.alert.gid
        != wan_event.alert.gid
    ):
        return False

    if (
        lan_event.alert.signature_id
        != wan_event.alert.signature_id
    ):
        return False

    if (
        lan_event.alert.rev
        != wan_event.alert.rev
    ):
        return False

    if lan_event.proto != wan_event.proto:
        return False

    if (
        lan_event.dest_ip
        != wan_event.dest_ip
    ):
        return False

    if not _same_optional_value(
        lan_event.dest_port,
        wan_event.dest_port,
    ):
        return False

    if not _same_optional_value(
        lan_event.app_proto,
        wan_event.app_proto,
    ):
        return False

    if not _same_optional_value(
        lan_event.icmp_type,
        wan_event.icmp_type,
    ):
        return False

    if not _same_optional_value(
        lan_event.icmp_code,
        wan_event.icmp_code,
    ):
        return False

    return True


def _time_delta(
    first: TrafficObservation,
    second: TrafficObservation,
) -> timedelta:
    """Return absolute timestamp difference."""

    delta = (
        first.event.timestamp
        - second.event.timestamp
    )

    if delta < timedelta():
        return -delta

    return delta


def _milliseconds(
    value: timedelta,
) -> float:
    """Convert timedelta to milliseconds."""

    return value.total_seconds() * 1000


def correlate_nat_observations(
    observations: list[TrafficObservation],
    window: timedelta = DEFAULT_NAT_CORRELATION_WINDOW,
) -> list[CorrelatedAlert]:
    """Correlate outbound LAN/WAN observations across NAT.

    The LAN pre-NAT observation becomes canonical because it
    preserves the original client source address.
    """

    if window <= timedelta():
        raise ValueError(
            "correlation window must be positive"
        )

    lan_indices = [
        index
        for index, observation in enumerate(
            observations
        )
        if observation.traffic_class
        == TrafficClass.LAN_OUTBOUND_PRE_NAT
    ]

    wan_indices = {
        index
        for index, observation in enumerate(
            observations
        )
        if observation.traffic_class
        == TrafficClass.WAN_OUTBOUND_POST_NAT
    }

    paired_indices: set[int] = set()
    correlated: list[CorrelatedAlert] = []

    for lan_index in lan_indices:
        lan_observation = observations[
            lan_index
        ]

        candidates: list[
            tuple[timedelta, int]
        ] = []

        for wan_index in wan_indices:
            if wan_index in paired_indices:
                continue

            wan_observation = observations[
                wan_index
            ]

            if not _is_nat_pair_candidate(
                lan_observation,
                wan_observation,
            ):
                continue

            delta = _time_delta(
                lan_observation,
                wan_observation,
            )

            if delta > window:
                continue

            candidates.append(
                (
                    delta,
                    wan_index,
                )
            )

        if not candidates:
            continue

        delta, wan_index = min(
            candidates,
            key=lambda item: item[0],
        )

        wan_observation = observations[
            wan_index
        ]

        paired_indices.add(
            lan_index
        )
        paired_indices.add(
            wan_index
        )

        correlated.append(
            CorrelatedAlert(
                canonical=lan_observation,
                observations=(
                    lan_observation,
                    wan_observation,
                ),
                nat_correlated=True,
                correlation_delta_ms=(
                    _milliseconds(delta)
                ),
            )
        )

    for index, observation in enumerate(
        observations
    ):
        if index in paired_indices:
            continue

        correlated.append(
            CorrelatedAlert(
                canonical=observation,
                observations=(
                    observation,
                ),
                nat_correlated=False,
            )
        )

    correlated.sort(
        key=lambda item: (
            item.canonical.event.timestamp
        )
    )

    return correlated
