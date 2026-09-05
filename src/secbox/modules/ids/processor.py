"""High-level processing pipeline for Suricata IDS events."""

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from secbox.core.models import SecBoxConfig
from secbox.modules.ids.aggregation import (
    Detection,
    aggregate_alerts,
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


class IdsProcessorError(Exception):
    """Raised when the IDS pipeline cannot be executed."""


@dataclass(frozen=True)
class IdsProcessingResult:
    """Result of processing a collection of Suricata events."""

    observations: tuple[TrafficObservation, ...]

    correlated_alerts: tuple[
        CorrelatedAlert,
        ...,
    ]

    detections: tuple[Detection, ...]

    decisions: tuple[PolicyDecision, ...]

    parse_error_count: int = 0
    classification_error_count: int = 0

    @property
    def observation_count(self) -> int:
        """Return number of parsed and classified alert observations."""

        return len(self.observations)

    @property
    def logical_alert_count(self) -> int:
        """Return number of alerts after NAT correlation."""

        return len(self.correlated_alerts)

    @property
    def detection_count(self) -> int:
        """Return number of aggregated detections."""

        return len(self.detections)

    @property
    def decision_count(self) -> int:
        """Return number of policy decisions."""

        return len(self.decisions)


def process_eve_lines(
    lines: Iterable[str],
    config: SecBoxConfig,
    runtime_interfaces: list[
        NetworkInterfaceState
    ],
) -> IdsProcessingResult:
    """Process Suricata EVE lines through the complete IDS pipeline."""

    if not config.ids.enabled:
        return IdsProcessingResult(
            observations=(),
            correlated_alerts=(),
            detections=(),
            decisions=(),
        )

    try:
        network_context = (
            build_ids_network_context(
                config,
                runtime_interfaces,
            )
        )

        policy_config = (
            build_ids_policy_config(
                config
            )
        )

        nat_correlation_window = (
            get_nat_correlation_window(
                config.ids
            )
        )

        aggregation_window = (
            get_aggregation_window(
                config.ids
            )
        )

    except (
        IdsContextError,
        IdsRuntimeConfigError,
    ) as error:
        raise IdsProcessorError(
            f"failed to initialize IDS pipeline: {error}"
        ) from error

    observations: list[
        TrafficObservation
    ] = []

    parse_error_count = 0
    classification_error_count = 0

    for line in lines:
        try:
            event = parse_eve_line(
                line
            )
        except SuricataEveParseError:
            parse_error_count += 1
            continue

        if event is None:
            continue

        try:
            observation = classify_alert(
                event,
                network_context,
            )
        except TrafficClassificationError:
            classification_error_count += 1
            continue

        observations.append(
            observation
        )

    correlated_alerts = (
        correlate_nat_observations(
            observations,
            window=nat_correlation_window,
        )
    )

    detections = aggregate_alerts(
        correlated_alerts,
        window=aggregation_window,
    )

    decisions = [
        evaluate_detection(
            detection,
            policy_config,
        )
        for detection in detections
    ]

    return IdsProcessingResult(
        observations=tuple(
            observations
        ),
        correlated_alerts=tuple(
            correlated_alerts
        ),
        detections=tuple(
            detections
        ),
        decisions=tuple(
            decisions
        ),
        parse_error_count=(
            parse_error_count
        ),
        classification_error_count=(
            classification_error_count
        ),
    )


def process_eve_file(
    config: SecBoxConfig,
    runtime_interfaces: list[
        NetworkInterfaceState
    ],
    path: Path | None = None,
) -> IdsProcessingResult:
    """Process an EVE JSON file through the complete IDS pipeline."""

    eve_path = (
        path
        if path is not None
        else config.ids.eve_path
    )

    try:
        with eve_path.open(
            mode="r",
            encoding="utf-8",
        ) as eve_file:
            return process_eve_lines(
                eve_file,
                config,
                runtime_interfaces,
            )

    except OSError as error:
        raise IdsProcessorError(
            f"failed to read EVE file "
            f"{eve_path}: {error}"
        ) from error
