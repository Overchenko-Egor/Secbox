"""Configuration models for the SecBox IDS subsystem."""

from pathlib import Path

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)


class IdsPolicySettings(BaseModel):
    """Policy thresholds for IDS detections."""

    model_config = ConfigDict(
        extra="forbid",
    )

    minimum_alert_count: int = Field(
        default=2,
        ge=1,
    )

    minimum_block_count: int = Field(
        default=5,
        ge=1,
    )

    maximum_alert_severity: int = Field(
        default=2,
        ge=1,
        le=3,
    )

    maximum_block_severity: int = Field(
        default=1,
        ge=1,
        le=3,
    )

    @model_validator(mode="after")
    def validate_thresholds(
        self,
    ) -> "IdsPolicySettings":
        """Validate relationships between policy thresholds."""

        if (
            self.minimum_block_count
            < self.minimum_alert_count
        ):
            raise ValueError(
                "minimum_block_count must be greater "
                "than or equal to minimum_alert_count"
            )

        if (
            self.maximum_block_severity
            > self.maximum_alert_severity
        ):
            raise ValueError(
                "maximum_block_severity cannot be "
                "less restrictive than "
                "maximum_alert_severity"
            )

        return self


class AutomaticBlackholeSettings(BaseModel):
    """Automatic IDS-driven dynamic blackhole settings."""

    model_config = ConfigDict(
        extra="forbid",
    )

    enabled: bool = False

    timeout: str = Field(
        default="15m",
        min_length=2,
        max_length=32,
    )


class IdsConfig(BaseModel):
    """Configuration of the SecBox IDS subsystem."""

    model_config = ConfigDict(
        extra="forbid",
    )

    enabled: bool = True

    eve_path: Path = Path(
        "/var/log/suricata/eve.json"
    )

    nat_correlation_window_ms: int = Field(
        default=10,
        ge=1,
        le=5000,
    )

    aggregation_window_seconds: int = Field(
        default=30,
        ge=1,
        le=3600,
    )

    policy: IdsPolicySettings = Field(
        default_factory=IdsPolicySettings,
    )

    automatic_blackhole: AutomaticBlackholeSettings = (
        Field(
            default_factory=AutomaticBlackholeSettings,
        )
    )
