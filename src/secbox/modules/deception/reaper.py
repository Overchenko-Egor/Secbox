"""Periodic cleanup of expired Deception quarantine cases."""

import json

from secbox.actions.deception import (
    reap_expired_cases_action,
)


def main() -> None:
    result = reap_expired_cases_action()

    print(
        json.dumps(
            result,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
