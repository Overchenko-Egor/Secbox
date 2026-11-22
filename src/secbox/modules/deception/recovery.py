"""Recovery of persistent Deception quarantine state."""

from __future__ import annotations

import json

from datetime import UTC, datetime
from pathlib import Path

from secbox.actions.deception import (
    stop_observe_case_action,
)
from secbox.modules.deception.store import (
    DeceptionCaseStore,
)
from secbox.modules.deception.steering import (
    DEFAULT_STATE_PATH,
    add_source,
    load_state,
    remove_source,
)


def recover(
    *,
    now: datetime | None = None,
    case_store: DeceptionCaseStore | None = None,
    state_path: Path = DEFAULT_STATE_PATH,
) -> dict[str, object]:
    """Make quarantine state consistent with case metadata."""

    current = now or datetime.now(UTC)
    store = case_store or DeceptionCaseStore()

    cases = store.list_cases()

    by_id = {
        case.case_id: case
        for case in cases
    }

    removed_refs: list[str] = []
    restored_refs: list[str] = []
    stopped_cases: list[str] = []

    state = load_state(
        state_path
    )

    sources = state["sources"]

    assert isinstance(
        sources,
        dict,
    )

    #
    # 1. Remove references which cannot represent
    #    an active quarantine anymore.
    #
    snapshot = list(
        sources.items()
    )

    for source_ip, entry in snapshot:
        if not isinstance(
            source_ip,
            str,
        ):
            continue

        if not isinstance(
            entry,
            dict,
        ):
            continue

        raw_cases = entry.get(
            "cases"
        )

        if not isinstance(
            raw_cases,
            list,
        ):
            continue

        for case_id in list(
            raw_cases
        ):
            if not isinstance(
                case_id,
                str,
            ):
                continue

            case = by_id.get(
                case_id
            )

            stale = (
                case is None
                or case.status != "observing"
                or case.source_ip != source_ip
            )

            if not stale:
                continue

            if remove_source(
                source_ip=source_ip,
                case_id=case_id,
                path=state_path,
            ):
                removed_refs.append(
                    case_id
                )

    #
    # 2. Determine canonical active IDS case
    #    for each source.
    #
    active_by_source: dict[
        str,
        list[object],
    ] = {}

    for case in cases:
        if case.status != "observing":
            continue

        if case.trigger.source != "ids":
            continue

        active_by_source.setdefault(
            case.source_ip,
            [],
        ).append(
            case
        )

    for source_ip, source_cases in (
        active_by_source.items()
    ):
        source_cases.sort(
            key=lambda item:
                item.created_at,
            reverse=True,
        )

        valid = []

        for case in source_cases:
            if (
                case.expires_at is not None
                and case.expires_at <= current
            ):
                stop_observe_case_action(
                    case_id=case.case_id,
                    case_store=store,
                )

                remove_source(
                    source_ip=source_ip,
                    case_id=case.case_id,
                    path=state_path,
                )

                stopped_cases.append(
                    case.case_id
                )

                continue

            valid.append(
                case
            )

        if not valid:
            continue

        canonical = valid[0]

        #
        # Any additional observing IDS cases for
        # one source are historical race leftovers.
        #
        for duplicate in valid[1:]:
            stop_observe_case_action(
                case_id=duplicate.case_id,
                case_store=store,
            )

            remove_source(
                source_ip=source_ip,
                case_id=duplicate.case_id,
                path=state_path,
            )

            stopped_cases.append(
                duplicate.case_id
            )

        changed = add_source(
            source_ip=source_ip,
            case_id=canonical.case_id,
            path=state_path,
        )

        if changed:
            restored_refs.append(
                canonical.case_id
            )

    return {
        "removed_count":
            len(removed_refs),
        "removed_refs":
            removed_refs,
        "restored_count":
            len(restored_refs),
        "restored_refs":
            restored_refs,
        "stopped_count":
            len(stopped_cases),
        "stopped_cases":
            stopped_cases,
    }


def main() -> None:
    print(
        json.dumps(
            recover(),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
