"""Automatic response actions for IDS policy decisions."""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from secbox.modules.blacklist.service import (
    BlacklistError,
    parse_timeout,
)
from secbox.modules.ids.action_client import (
    IdsActionClientError,
    add_ids_blackhole_via_helper,
)
from secbox.modules.ids.policy import (
    PolicyAction,
    PolicyDecision,
)


LOGGER = logging.getLogger(__name__)


class IdsResponseError(Exception):
    """Raised when an IDS response action cannot be completed."""


BlacklistAddFunction = Callable[..., None]


@dataclass(frozen=True)
class IdsResponseResult:
    """Result of handling one IDS policy decision."""

    blocked: bool
    address: str | None
    reason: str


class IdsResponseHandler:
    """Translate IDS policy decisions into response actions."""

    def __init__(
        self,
        *,
        automatic_blackhole_enabled: bool,
        automatic_blackhole_timeout: str,
        protected_networks: tuple[str, ...],
        blacklist_add: BlacklistAddFunction = (
            add_ids_blackhole_via_helper
        ),
    ) -> None:
        self.automatic_blackhole_enabled = (
            automatic_blackhole_enabled
        )

        try:
            parse_timeout(
                automatic_blackhole_timeout
            )

        except (
            BlacklistError,
            IdsActionClientError,
        ) as error:
            raise IdsResponseError(
                "invalid automatic blackhole timeout: "
                f"{automatic_blackhole_timeout}: {error}"
            ) from error

        self.automatic_blackhole_timeout = (
            automatic_blackhole_timeout
        )

        self.protected_networks = (
            protected_networks
        )

        self.blacklist_add = blacklist_add

    def refresh_protected_networks(
        self,
        protected_networks: tuple[
            str,
            ...,
        ],
    ) -> None:
        """Replace runtime protected networks."""

        self.protected_networks = (
            protected_networks
        )

    def handle(
        self,
        decision: PolicyDecision,
    ) -> IdsResponseResult:
        """Handle one IDS policy decision."""

        detection = decision.detection

        if (
            decision.action
            != PolicyAction.BLOCK_CANDIDATE
        ):
            return IdsResponseResult(
                blocked=False,
                address=None,
                reason=(
                    "policy decision does not request blocking"
                ),
            )

        if not self.automatic_blackhole_enabled:
            LOGGER.info(
                (
                    "IDS automatic blackhole skipped "
                    "source=%s reason=%r"
                ),
                detection.source_ip,
                "automatic blackhole is disabled",
            )

            return IdsResponseResult(
                blocked=False,
                address=detection.source_ip,
                reason=(
                    "automatic blackhole is disabled"
                ),
            )

        reason = (
            "ids:"
            f"sid={detection.signature_id};"
            f"severity={detection.severity};"
            f"count={detection.count}"
        )

        try:
            self.blacklist_add(
                address=detection.source_ip,
                signature_id=(
                    detection.signature_id
                ),
                severity=detection.severity,
                count=detection.count,
            )

        except (
            BlacklistError,
            IdsActionClientError,
        ) as error:
            raise IdsResponseError(
                (
                    "failed to blacklist IDS source "
                    f"{detection.source_ip}: {error}"
                )
            ) from error

        LOGGER.warning(
            (
                "IDS automatic blackhole applied "
                "source=%s "
                "timeout=%s "
                "sid=%s "
                "severity=%s "
                "count=%s"
            ),
            detection.source_ip,
            self.automatic_blackhole_timeout,
            detection.signature_id,
            detection.severity,
            detection.count,
        )

        return IdsResponseResult(
            blocked=True,
            address=detection.source_ip,
            reason=reason,
        )
