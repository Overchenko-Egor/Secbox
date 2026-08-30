"""Parser for Suricata EVE JSON events."""

import json

from pydantic import ValidationError

from secbox.modules.ids.models import SuricataAlertEvent


class SuricataEveParseError(Exception):
    """Raised when a Suricata EVE event cannot be parsed."""


def parse_eve_line(
    line: str,
) -> SuricataAlertEvent | None:
    """Parse one line from Suricata eve.json.

    Non-alert EVE events are intentionally ignored.
    """

    try:
        payload = json.loads(line)
    except json.JSONDecodeError as error:
        raise SuricataEveParseError(
            f"invalid EVE JSON: {error}"
        ) from error

    if not isinstance(payload, dict):
        raise SuricataEveParseError(
            "EVE event must be a JSON object"
        )

    if payload.get("event_type") != "alert":
        return None

    try:
        return SuricataAlertEvent.model_validate(
            payload
        )
    except ValidationError as error:
        raise SuricataEveParseError(
            f"invalid Suricata alert event: {error}"
        ) from error
