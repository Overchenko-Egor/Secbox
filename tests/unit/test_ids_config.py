"""Tests for IDS configuration models."""

import pytest
from pydantic import ValidationError

from secbox.core.models import SecBoxConfig
from secbox.modules.ids.config import (
    AutomaticBlackholeSettings,
    IdsConfig,
    IdsPolicySettings,
)


def test_ids_default_configuration() -> None:
    """Create IDS configuration using safe defaults."""

    config = IdsConfig()

    assert config.enabled is True

    assert str(config.eve_path) == (
        "/var/log/suricata/eve.json"
    )

    assert (
        config.nat_correlation_window_ms
        == 10
    )

    assert (
        config.aggregation_window_seconds
        == 30
    )

    assert (
        config.policy.minimum_alert_count
        == 2
    )

    assert (
        config.policy.minimum_block_count
        == 5
    )

    assert (
        config.policy.maximum_alert_severity
        == 2
    )

    assert (
        config.policy.maximum_block_severity
        == 1
    )

    assert (
        config.automatic_blackhole.enabled
        is False
    )

    assert (
        config.automatic_blackhole.timeout
        == "15m"
    )


def test_ids_is_present_in_root_config() -> None:
    """Root SecBox configuration contains IDS settings."""

    config = SecBoxConfig()

    assert isinstance(
        config.ids,
        IdsConfig,
    )


def test_invalid_detection_counts_fail() -> None:
    """Reject block count lower than alert count."""

    with pytest.raises(
        ValidationError,
        match="minimum_block_count",
    ):
        IdsPolicySettings(
            minimum_alert_count=10,
            minimum_block_count=5,
        )


def test_invalid_severity_relationship_fails() -> None:
    """Reject block severity weaker than alert severity."""

    with pytest.raises(
        ValidationError,
        match="maximum_block_severity",
    ):
        IdsPolicySettings(
            maximum_alert_severity=2,
            maximum_block_severity=3,
        )


def test_zero_correlation_window_fails() -> None:
    """Reject zero NAT correlation window."""

    with pytest.raises(
        ValidationError,
    ):
        IdsConfig(
            nat_correlation_window_ms=0,
        )


def test_zero_aggregation_window_fails() -> None:
    """Reject zero aggregation window."""

    with pytest.raises(
        ValidationError,
    ):
        IdsConfig(
            aggregation_window_seconds=0,
        )


def test_blackhole_disabled_by_default() -> None:
    """Automatic response is disabled by default."""

    config = AutomaticBlackholeSettings()

    assert config.enabled is False


def test_unknown_ids_field_fails() -> None:
    """Reject unknown IDS configuration fields."""

    with pytest.raises(
        ValidationError,
    ):
        IdsConfig.model_validate(
            {
                "enabled": True,
                "something_unknown": True,
            }
        )
