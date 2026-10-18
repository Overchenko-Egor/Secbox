"""Tests for automatic IDS response handling."""

from types import SimpleNamespace
from typing import cast

import pytest

from secbox.modules.blacklist.service import (
    BlacklistError,
)
from secbox.modules.ids.policy import (
    PolicyAction,
    PolicyDecision,
)
from secbox.modules.ids.action_client import (
    IdsActionClientError,
)

from secbox.modules.ids.response import (
    IdsResponseError,
    IdsResponseHandler,
)


def make_decision(
    action: PolicyAction,
    *,
    source_ip: str = "203.0.113.50",
) -> PolicyDecision:
    """Create a minimal policy decision for response tests."""

    detection = SimpleNamespace(
        source_ip=source_ip,
        destination_ip="192.168.1.63",
        signature_id=100001,
        severity=1,
        count=5,
        signature="SECBOX RESPONSE TEST",
    )

    decision = SimpleNamespace(
        action=action,
        detection=detection,
        reason="test",
    )

    return cast(
        PolicyDecision,
        decision,
    )


@pytest.mark.parametrize(
    "action",
    [
        PolicyAction.IGNORE,
        PolicyAction.LOG,
        PolicyAction.ALERT,
    ],
)
def test_non_block_decisions_do_not_call_blacklist(
    action: PolicyAction,
) -> None:
    """Only BLOCK_CANDIDATE may reach the blacklist service."""

    calls: list[
        dict[str, object]
    ] = []

    def fake_add(
        **kwargs: object,
    ) -> None:
        calls.append(kwargs)

    handler = IdsResponseHandler(
        automatic_blackhole_enabled=True,
        automatic_blackhole_timeout="15m",
        protected_networks=(
            "192.168.100.0/24",
        ),
        blacklist_add=fake_add,
    )

    result = handler.handle(
        make_decision(action)
    )

    assert result.blocked is False
    assert result.address is None
    assert calls == []


def test_block_candidate_is_skipped_when_disabled() -> None:
    """Disabled automatic blackhole must not call blacklist."""

    calls: list[
        dict[str, object]
    ] = []

    def fake_add(
        **kwargs: object,
    ) -> None:
        calls.append(kwargs)

    handler = IdsResponseHandler(
        automatic_blackhole_enabled=False,
        automatic_blackhole_timeout="15m",
        protected_networks=(
            "192.168.100.0/24",
        ),
        blacklist_add=fake_add,
    )

    result = handler.handle(
        make_decision(
            PolicyAction.BLOCK_CANDIDATE
        )
    )

    assert result.blocked is False
    assert result.address == "203.0.113.50"
    assert (
        result.reason
        == "automatic blackhole is disabled"
    )
    assert calls == []


def test_block_candidate_calls_blacklist_when_enabled() -> None:
    """Eligible BLOCK_CANDIDATE reaches blacklist service."""

    calls: list[
        dict[str, object]
    ] = []

    def fake_add(
        **kwargs: object,
    ) -> None:
        calls.append(kwargs)

    handler = IdsResponseHandler(
        automatic_blackhole_enabled=True,
        automatic_blackhole_timeout="15m",
        protected_networks=(
            "192.168.100.0/24",
            "192.168.1.63/32",
            "192.168.50.1/32",
            "192.168.100.2/32",
        ),
        blacklist_add=fake_add,
    )

    result = handler.handle(
        make_decision(
            PolicyAction.BLOCK_CANDIDATE
        )
    )

    assert result.blocked is True
    assert result.address == "203.0.113.50"

    assert len(calls) == 1

    call = calls[0]

    assert (
        call["address"]
        == "203.0.113.50"
    )

    assert (
        call["signature_id"]
        == 100001
    )

    assert (
        call["severity"]
        == 1
    )

    assert (
        call["count"]
        == 5
    )

    assert "timeout" not in call
    assert "source" not in call
    assert "protected_networks" not in call

    assert "reason" not in call


def test_blacklist_error_becomes_ids_response_error() -> None:
    """Normalize blacklist failures into IDS response failures."""

    def fake_add(
        **kwargs: object,
    ) -> None:
        raise IdsActionClientError(
            "simulated privileged helper failure"
        )

    handler = IdsResponseHandler(
        automatic_blackhole_enabled=True,
        automatic_blackhole_timeout="15m",
        protected_networks=(),
        blacklist_add=fake_add,
    )

    with pytest.raises(
        IdsResponseError,
        match=(
            "failed to blacklist IDS source "
            "203.0.113.50"
        ),
    ):
        handler.handle(
            make_decision(
                PolicyAction.BLOCK_CANDIDATE
            )
        )


def test_protected_networks_are_not_forwarded_to_helper() -> None:
    """Privileged helper must derive protected networks itself."""

    calls: list[
        dict[str, object]
    ] = []

    def fake_add(
        **kwargs: object,
    ) -> None:
        calls.append(kwargs)

    handler = IdsResponseHandler(
        automatic_blackhole_enabled=True,
        automatic_blackhole_timeout="15m",
        protected_networks=(
            "127.0.0.1/32",
            "192.168.100.0/24",
        ),
        blacklist_add=fake_add,
    )

    handler.handle(
        make_decision(
            PolicyAction.BLOCK_CANDIDATE
        )
    )

    assert len(calls) == 1

    assert (
        "protected_networks"
        not in calls[0]
    )

    assert (
        "timeout"
        not in calls[0]
    )


@pytest.mark.parametrize(
    "timeout",
    [
        "",
        "0m",
        "-1h",
        "15x",
        "abc",
    ],
)
def test_invalid_automatic_blackhole_timeout_is_rejected(
    timeout: str,
) -> None:
    """Invalid response timeout must fail during construction."""

    with pytest.raises(
        IdsResponseError,
        match="invalid automatic blackhole timeout",
    ):
        IdsResponseHandler(
            automatic_blackhole_enabled=True,
            automatic_blackhole_timeout=timeout,
            protected_networks=(),
        )


def test_valid_automatic_blackhole_timeout_is_accepted() -> None:
    """Valid timeout is checked before the daemon starts."""

    handler = IdsResponseHandler(
        automatic_blackhole_enabled=True,
        automatic_blackhole_timeout="15m",
        protected_networks=(),
    )

    assert (
        handler.automatic_blackhole_timeout
        == "15m"
    )

