"""Long-running automatic VPN failover daemon."""

import logging
from dataclasses import dataclass
from pathlib import Path
from threading import Event

from secbox.modules.vpn.controller import (
    ControllerResult,
    evaluate_once,
)
from secbox.modules.vpn.models import VpnConfig
from secbox.modules.vpn.runtime import (
    VpnEventStore,
    VpnRuntimeStore,
    runtime_from_result,
    switch_event_from_result,
)


LOGGER = logging.getLogger(__name__)


class VpnDaemonError(RuntimeError):
    """Raised when the VPN daemon cannot continue."""


@dataclass(frozen=True)
class VpnDaemonStats:
    iterations: int
    switches: int


class VpnDaemon:
    """Continuously evaluate VPN health and failover."""

    def __init__(
        self,
        vpn: VpnConfig,
        *,
        state_path: Path,
        interval: float = 3.0,
        runtime_store: VpnRuntimeStore | None = None,
        event_store: VpnEventStore | None = None,
    ) -> None:
        if interval <= 0:
            raise ValueError(
                "VPN daemon interval must be greater than zero"
            )

        self.vpn = vpn
        self.state_path = state_path
        self.interval = interval
        self.runtime_store = (
            runtime_store
            if runtime_store is not None
            else VpnRuntimeStore()
        )
        self.event_store = (
            event_store
            if event_store is not None
            else VpnEventStore()
        )

        self._iterations = 0
        self._switches = 0

    def process_once(self) -> ControllerResult:
        """Evaluate VPN pool once."""

        try:
            result = evaluate_once(
                self.vpn,
                state_path=self.state_path,
            )
        except Exception as error:
            raise VpnDaemonError(
                f"VPN failover evaluation failed: {error}"
            ) from error

        self._iterations += 1

        self.runtime_store.save(
            runtime_from_result(result)
        )

        if result.switched:
            self._switches += 1
            self.event_store.append(
                switch_event_from_result(result)
            )

        return result


    def run(self, stop_event: Event) -> None:
        """Run until stop_event is set."""

        while not stop_event.is_set():
            result = self.process_once()

            if result.switched:
                LOGGER.warning(
                    "VPN switch %s -> %s: %s",
                    result.active_before,
                    result.active_after,
                    result.reason,
                )
            else:
                LOGGER.debug(
                    "VPN active=%s: %s",
                    result.active_after,
                    result.reason,
                )

            stop_event.wait(self.interval)

    def stats(self) -> VpnDaemonStats:
        """Return current daemon statistics."""

        return VpnDaemonStats(
            iterations=self._iterations,
            switches=self._switches,
        )


def install_signal_handlers(
    stop_event: Event,
) -> None:
    """Request graceful daemon shutdown on SIGTERM/SIGINT."""

    import signal

    def handle_signal(
        signum: int,
        _frame,
    ) -> None:
        LOGGER.info(
            "VPN daemon received signal %s",
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
