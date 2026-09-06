"""Long-running runtime loop for the SecBox IDS subsystem."""

import logging
import signal
import time
from collections.abc import Callable
from dataclasses import dataclass
from threading import Event

from secbox.modules.ids.policy import PolicyDecision
from secbox.modules.ids.reader import EveReaderError, EveTailReader
from secbox.modules.ids.worker import StreamingIdsWorker


LOGGER = logging.getLogger(__name__)


class IdsDaemonError(Exception):
    """Raised when the IDS daemon cannot continue."""


@dataclass(frozen=True)
class IdsDaemonStats:
    """Runtime statistics for the IDS daemon loop."""

    iterations: int
    lines_read: int
    decisions_emitted: int
    reader_resets: int


DecisionHandler = Callable[
    [PolicyDecision],
    None,
]

RuntimeRefreshHandler = Callable[
    [],
    None,
]


class IdsDaemon:
    """Continuously connect EVE log input to the IDS worker."""

    def __init__(
        self,
        reader: EveTailReader,
        worker: StreamingIdsWorker,
        *,
        decision_handler: DecisionHandler | None = None,
        runtime_refresh_handler: (
            RuntimeRefreshHandler | None
        ) = None,
        runtime_refresh_interval: float = 5.0,
    ) -> None:
        self.reader = reader
        self.worker = worker

        self.decision_handler = (
            decision_handler
            if decision_handler is not None
            else log_policy_decision
        )

        if runtime_refresh_interval <= 0:
            raise ValueError(
                "runtime_refresh_interval must "
                "be greater than zero"
            )

        self.runtime_refresh_handler = (
            runtime_refresh_handler
        )

        self.runtime_refresh_interval = (
            runtime_refresh_interval
        )

        self._last_runtime_refresh: (
            float | None
        ) = None

        self._iterations = 0
        self._lines_read = 0
        self._decisions_emitted = 0
        self._reader_resets = 0

    def process_once(
        self,
        *,
        now: float | None = None,
    ) -> list[PolicyDecision]:
        """Process currently available events and flush timers once."""

        if now is None:
            now = time.monotonic()

        try:
            lines = self.reader.read_available()
        except EveReaderError as error:
            raise IdsDaemonError(
                f"failed to read Suricata EVE log: {error}"
            ) from error

        self._iterations += 1
        self._lines_read += len(lines)

        self.refresh_runtime_if_due(
            now=now,
        )

        decisions: list[
            PolicyDecision
        ] = []

        for line in lines:
            decisions.extend(
                self.worker.ingest_line(
                    line,
                    now=now,
                )
            )

        decisions.extend(
            self.worker.flush(
                now=now,
            )
        )

        self._emit_decisions(
            decisions
        )

        return decisions

    def refresh_reader(
        self,
    ) -> bool:
        """Handle EVE log rotation or truncation."""

        try:
            reset = self.reader.refresh()
        except EveReaderError as error:
            raise IdsDaemonError(
                f"failed to refresh EVE reader: {error}"
            ) from error

        if reset:
            self._reader_resets += 1

        return reset

    def refresh_runtime_if_due(
        self,
        *,
        now: float,
    ) -> bool:
        """Refresh runtime state if interval elapsed."""

        if self.runtime_refresh_handler is None:
            return False

        if self._last_runtime_refresh is not None:
            elapsed = (
                now
                - self._last_runtime_refresh
            )

            if (
                elapsed
                < self.runtime_refresh_interval
            ):
                return False

        self.runtime_refresh_handler()

        self._last_runtime_refresh = (
            now
        )

        return True

    def run(
        self,
        stop_event: Event,
    ) -> None:
        """Run until stop_event is set."""

        try:
            self.reader.open()

            while not stop_event.is_set():
                self.process_once()

                self.refresh_reader()

                stop_event.wait(
                    self.reader.poll_interval
                )

        except EveReaderError as error:
            raise IdsDaemonError(
                f"failed to initialize EVE reader: {error}"
            ) from error

        finally:
            self.reader.close()

            decisions = self.worker.close()

            self._emit_decisions(
                decisions
            )

    def stats(
        self,
    ) -> IdsDaemonStats:
        """Return current daemon counters."""

        return IdsDaemonStats(
            iterations=self._iterations,
            lines_read=self._lines_read,
            decisions_emitted=(
                self._decisions_emitted
            ),
            reader_resets=(
                self._reader_resets
            ),
        )

    def _emit_decisions(
        self,
        decisions: list[
            PolicyDecision
        ],
    ) -> None:
        """Deliver decisions to the configured handler."""

        for decision in decisions:
            self.decision_handler(
                decision
            )

            self._decisions_emitted += 1


def log_policy_decision(
    decision: PolicyDecision,
) -> None:
    """Write one policy decision to the application log."""

    detection = decision.detection

    LOGGER.info(
        (
            "IDS decision "
            "action=%s "
            "source=%s "
            "destination=%s "
            "sid=%s "
            "severity=%s "
            "count=%s "
            "signature=%r "
            "reason=%r"
        ),
        decision.action.value,
        detection.source_ip,
        detection.destination_ip,
        detection.signature_id,
        detection.severity,
        detection.count,
        detection.signature,
        decision.reason,
    )


def install_signal_handlers(
    stop_event: Event,
) -> None:
    """Convert SIGTERM and SIGINT into a graceful shutdown request."""

    def handle_signal(
        signum: int,
        frame: object,
    ) -> None:
        LOGGER.info(
            "IDS daemon received signal %s",
            signum,
        )

        stop_event.set()

    signal.signal(
        signal.SIGTERM,
        handle_signal,
    )

    signal.signal(
        signal.SIGINT,
        handle_signal,
    )
