import pytest
from pydantic import ValidationError

from secbox.core.models import SecBoxConfig, SystemConfig


def test_default_config() -> None:
    config = SecBoxConfig()

    assert config.schema_version == 1
    assert config.system.hostname == "secbox"


def test_hostname_is_normalized_to_lowercase() -> None:
    config = SystemConfig(hostname="SecBox-Gateway")

    assert config.hostname == "secbox-gateway"


@pytest.mark.parametrize(
    "hostname",
    [
        "-secbox",
        "secbox-",
        "secbox gateway",
        "secbox.local",
        "secbox_gateway",
    ],
)
def test_invalid_hostname_is_rejected(hostname: str) -> None:
    with pytest.raises(ValidationError):
        SystemConfig(hostname=hostname)
