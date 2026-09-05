"""Stateful streaming worker for Suricata IDS events."""

import time
from dataclasses import dataclass
from datetime import datetime

from secbox.core.models import SecBoxConfig
from secbox.modules.ids.aggregation import (
    Detection,
    DetectionKey,
    build_detection_key,
)
from secbox.modules.ids.classification import (
    TrafficClassificationError,
    TrafficObservation,
    classify_alert,
)
from secbox.modules.ids.context import (
    IdsContextError,
    build_ids_network_context,
)
from secbox.modules.ids.correlation import (
    CorrelatedAlert,
    correlate_nat_observations,
)
from secbox.modules.ids.parser import (
    SuricataEveParseError,
    parse_eve_line,
)
from secbox.modules.ids.policy import (
    IdsPolicyConfig,
    PolicyDecision,
    evaluate_detection,
)
from secbox.modules.ids.runtime import (
    IdsRuntimeConfigError,
    build_ids_policy_config,
    get_aggregation_window,
    get_nat_correlation_window,
)
from secbox.modules.network.state import (
    NetworkInterfaceState,
)


class IdsWorkerError(Exception):
    """Raised when the streaming IDS worker cannot operate."""


@dataclass(frozen=True)
class PendingObservation:
    """Observation waiting for NAT correlation."""

    observation: TrafficObservation
    received_at: float


@dataclass
class ActiveDetection:
    """Repeated logical alerts waiting for aggregation."""

    key: DetectionKey
    alerts: list[CorrelatedAlert]

    first_received_at: float
    last_received_at: float


@dataclass(frozen=True)
class IdsWorkerStats:
    """Current streaming IDS worker counters."""

    received_lines: int
    parsed_alerts: int
    ignored_events: int

    parse_errors: int
    classification_errors: int

    logical_alerts: int
    detections: int
    decisions: int

    pending_observations: int
    active_detections: int


class StreamingIdsWorker:
    """Stateful Suricata IDS processing worker."""

    def __init__(
        self,
        config: SecBoxConfig,
        runtime_interfaces: list[
            NetworkInterfaceState
        ],
    ) -> None:
        self.config = config

        try:
            self.network_context = (
                build_ids_network_context(
                    config,
                    runtime_interfaces,
                )
            )

            self.policy_config: IdsPolicyConfig = (
                build_ids_policy_config(
                    config
                )
            )

            self.nat_correlation_window = (
                get_nat_correlation_window(
                    config.ids
                )
            )

            self.aggregation_window = (
                get_aggregation_window(
                    config.ids
                )
            )

        except (
            IdsContextError,
            IdsRuntimeConfigError,
        ) as error:
            raise IdsWorkerError(
                "failed to initialize IDS worker: "
                f"{error}"
            ) from error

        self._pending_observations: list[
            PendingObservation
        ] = []

        self._active_detections: dict[
            DetectionKey,
            ActiveDetection,
        ] = {}

        self._received_lines = 0
        self._parsed_alerts = 0
        self._ignored_events = 0

        self._parse_errors = 0
        self._classification_errors = 0

        self._logical_alerts = 0
        self._detections = 0
        self._decisions = 0

    def ingest_line(
        self,
        line: str,
        *,
        now: float | None = None,
    ) -> list[PolicyDecision]:
        """Process one newly received Suricata EVE line."""

        if now is None:
            now = time.monotonic()

        self._received_lines += 1

        if not self.config.ids.enabled:
            self._ignored_events += 1
            return []

        try:
            event = parse_eve_line(
                line
            )

        except SuricataEveParseError:
            self._parse_errors += 1

            return self.flush(
                now=now
            )

        if event is None:
            self._ignored_events += 1

            return self.flush(
                now=now
            )

        self._parsed_alerts += 1

        try:
            observation = classify_alert(
                event,
                self.network_context,
            )

        except TrafficClassificationError:
            self._classification_errors += 1

            return self.flush(
                now=now
            )

        self._pending_observations.append(
            PendingObservation(
                observation=observation,
                received_at=now,
            )
        )

        return self.flush(
            now=now
        )

    def flush(
        self,
        *,
        now: float | None = None,
        force: bool = False,
    ) -> list[PolicyDecision]:
        """Flush ready correlation and aggregation state."""

        if now is None:
            now = time.monotonic()

        ready_alerts = (
            self._flush_correlations(
                now=now,
                force=force,
            )
        )

        decisions: list[
            PolicyDecision
        ] = []

        for (
            alert,
            received_at,
        ) in ready_alerts:
            decisions.extend(
                self._add_logical_alert(
                    alert,
                    received_at=received_at,
                )
            )

        decisions.extend(
            self._flush_detections(
                now=now,
                force=force,
            )
        )

        return decisions

    def close(
        self,
    ) -> list[PolicyDecision]:
        """Force all buffered IDS state to be finalized."""

        return self.flush(
            force=True
        )

    def stats(
        self,
    ) -> IdsWorkerStats:
        """Return current worker counters."""

        return IdsWorkerStats(
            received_lines=(
                self._received_lines
            ),
            parsed_alerts=(
                self._parsed_alerts
            ),
            ignored_events=(
                self._ignored_events
            ),
            parse_errors=(
                self._parse_errors
            ),
            classification_errors=(
                self._classification_errors
            ),
            logical_alerts=(
                self._logical_alerts
            ),
            detections=(
                self._detections
            ),
            decisions=(
                self._decisions
            ),
            pending_observations=len(
                self._pending_observations
            ),
            active_detections=len(
                self._active_detections
            ),
        )

    def _flush_correlations(
        self,
        *,
        now: float,
        force: bool,
    ) -> list[
        tuple[
            CorrelatedAlert,
            float,
        ]
    ]:
        """Finalize NAT correlations that are ready."""

        if not self._pending_observations:
            return []

        observations = [
            pending.observation
            for pending
            in self._pending_observations
        ]

        received_at_by_id = {
            id(pending.observation): (
                pending.received_at
            )
            for pending
            in self._pending_observations
        }

        correlated = (
            correlate_nat_observations(
                observations,
                window=(
                    self.nat_correlation_window
                ),
            )
        )

        correlation_seconds = (
            self.nat_correlation_window
            .total_seconds()
        )

        finalized: list[
            tuple[
                CorrelatedAlert,
                float,
            ]
        ] = []

        consumed_ids: set[int] = set()

        for alert in correlated:
            observation_times = [
                received_at_by_id[
                    id(observation)
                ]
                for observation
                in alert.observations
            ]

            first_received_at = min(
                observation_times
            )

            last_received_at = max(
                observation_times
            )

            if force:
                ready = True

            elif alert.nat_correlated:
                ready = True

            else:
                ready = (
                    now
                    - first_received_at
                    >= correlation_seconds
                )

            if not ready:
                continue

            finalized.append(
                (
                    alert,
                    last_received_at,
                )
            )

            for observation in (
                alert.observations
            ):
                consumed_ids.add(
                    id(observation)
                )

        if consumed_ids:
            self._pending_observations = [
                pending
                for pending
                in self._pending_observations
                if id(pending.observation)
                not in consumed_ids
            ]

        self._logical_alerts += len(
            finalized
        )

        return finalized

    def _add_logical_alert(
        self,
        alert: CorrelatedAlert,
        *,
        received_at: float,
    ) -> list[PolicyDecision]:
        """Add one logical alert to its active detection."""

        key = build_detection_key(
            alert
        )

        active = (
            self._active_detections.get(
                key
            )
        )

        if active is None:
            self._active_detections[
                key
            ] = ActiveDetection(
                key=key,
                alerts=[alert],
                first_received_at=(
                    received_at
                ),
                last_received_at=(
                    received_at
                ),
            )

            return []

        aggregation_seconds = (
            self.aggregation_window
            .total_seconds()
        )

        if (
            received_at
            - active.first_received_at
            <= aggregation_seconds
        ):
            active.alerts.append(
                alert
            )

            active.last_received_at = (
                received_at
            )

            return []

        decision = (
            self._finalize_detection(
                active
            )
        )

        self._active_detections[
            key
        ] = ActiveDetection(
            key=key,
            alerts=[alert],
            first_received_at=(
                received_at
            ),
            last_received_at=(
                received_at
            ),
        )

        return [decision]

    def _flush_detections(
        self,
        *,
        now: float,
        force: bool,
    ) -> list[PolicyDecision]:
        """Finalize expired aggregation windows."""

        aggregation_seconds = (
            self.aggregation_window
            .total_seconds()
        )

        ready_keys: list[
            DetectionKey
        ] = []

        for (
            key,
            active,
        ) in self._active_detections.items():
            if force:
                ready_keys.append(
                    key
                )

                continue

            if (
                now
                - active.first_received_at
                > aggregation_seconds
            ):
                ready_keys.append(
                    key
                )

        decisions: list[
            PolicyDecision
        ] = []

        for key in ready_keys:
            active = (
                self._active_detections.pop(
                    key
                )
            )

            decisions.append(
                self._finalize_detection(
                    active
                )
            )

        return decisions

    def _finalize_detection(
        self,
        active: ActiveDetection,
    ) -> PolicyDecision:
        """Create a Detection and evaluate its IDS policy."""

        if not active.alerts:
            raise IdsWorkerError(
                "cannot finalize empty detection"
            )

        timestamps: list[
            datetime
        ] = [
            (
                alert
                .canonical
                .event
                .timestamp
            )
            for alert in active.alerts
        ]

        detection = Detection(
            key=active.key,
            alerts=tuple(
                active.alerts
            ),
            first_seen=min(
                timestamps
            ),
            last_seen=max(
                timestamps
            ),
        )

        decision = evaluate_detection(
            detection,
            self.policy_config,
        )

        self._detections += 1
        self._decisions += 1

        return decision
