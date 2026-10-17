"""Privileged read-only nftables runtime inspection."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
from typing import Any


NFT_BIN = "/usr/sbin/nft"
IP_FORWARD_PATH = Path(
    "/proc/sys/net/ipv4/ip_forward"
)


class FirewallRuntimeError(RuntimeError):
    """Firewall runtime inspection failed."""


def _nft_json(
    *arguments: str,
) -> dict[str, Any]:
    try:
        result = subprocess.run(
            [
                NFT_BIN,
                "-j",
                *arguments,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (
        OSError,
        subprocess.TimeoutExpired,
    ) as error:
        raise FirewallRuntimeError(
            f"nft execution failed: {error}"
        ) from error

    if result.returncode != 0:
        message = (
            result.stderr.strip()
            or result.stdout.strip()
            or f"exit code {result.returncode}"
        )

        raise FirewallRuntimeError(
            f"nft failed: {message}"
        )

    try:
        payload = json.loads(
            result.stdout
        )
    except json.JSONDecodeError as error:
        raise FirewallRuntimeError(
            "nft returned invalid JSON"
        ) from error

    if not isinstance(payload, dict):
        raise FirewallRuntimeError(
            "nft returned unexpected JSON"
        )

    return payload


def _walk(value: object):
    if isinstance(value, dict):
        yield value

        for child in value.values():
            yield from _walk(child)

    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _counter_from_rule(
    rule: dict[str, Any],
) -> tuple[int, int]:
    packets = 0
    bytes_count = 0

    for item in _walk(
        rule.get("expr", [])
    ):
        counter = item.get("counter")

        if not isinstance(counter, dict):
            continue

        try:
            packets += int(
                counter.get("packets", 0)
            )
            bytes_count += int(
                counter.get("bytes", 0)
            )
        except (
            TypeError,
            ValueError,
        ):
            continue

    return packets, bytes_count


def _contains_key(
    value: object,
    key: str,
) -> bool:
    return any(
        key in item
        for item in _walk(value)
    )


def _extract_oifnames(
    value: object,
) -> list[str]:
    names: set[str] = set()

    for item in _walk(value):
        match = item.get("match")

        if not isinstance(match, dict):
            continue

        left = match.get("left")
        right = match.get("right")

        if not isinstance(left, dict):
            continue

        meta = left.get("meta")

        if (
            isinstance(meta, dict)
            and meta.get("key") == "oifname"
            and isinstance(right, str)
        ):
            names.add(right)

    return sorted(names)


def get_firewall_runtime_action(
) -> dict[str, object]:
    payload = _nft_json(
        "list",
        "ruleset",
    )

    objects = payload.get(
        "nftables",
        []
    )

    if not isinstance(objects, list):
        raise FirewallRuntimeError(
            "nftables object list is missing"
        )

    filter_table = False
    nat_table = False

    chains: dict[str, dict[str, object]] = {}

    rule_counts = {
        "input": 0,
        "forward": 0,
        "output": 0,
    }

    counters = {
        "input": {
            "packets": 0,
            "bytes": 0,
        },
        "forward": {
            "packets": 0,
            "bytes": 0,
        },
        "output": {
            "packets": 0,
            "bytes": 0,
        },
    }

    masquerade_interfaces: set[str] = set()
    blacklist_entries = 0

    for wrapper in objects:
        if not isinstance(wrapper, dict):
            continue

        table = wrapper.get("table")

        if isinstance(table, dict):
            if (
                table.get("family") == "inet"
                and table.get("name")
                == "secbox_filter"
            ):
                filter_table = True

            if (
                table.get("family") == "ip"
                and table.get("name")
                == "secbox_nat"
            ):
                nat_table = True

        chain = wrapper.get("chain")

        if isinstance(chain, dict):
            if (
                chain.get("family") == "inet"
                and chain.get("table")
                == "secbox_filter"
                and chain.get("name")
                in {"input", "forward", "output"}
            ):
                name = str(
                    chain["name"]
                )

                chains[name] = {
                    "policy": chain.get(
                        "policy"
                    ),
                    "hook": chain.get(
                        "hook"
                    ),
                    "type": chain.get(
                        "type"
                    ),
                }

        rule = wrapper.get("rule")

        if isinstance(rule, dict):
            family = rule.get("family")
            table_name = rule.get("table")
            chain_name = rule.get("chain")

            if (
                family == "inet"
                and table_name
                == "secbox_filter"
                and chain_name
                in rule_counts
            ):
                chain_key = str(
                    chain_name
                )

                rule_counts[
                    chain_key
                ] += 1

                packets, bytes_count = (
                    _counter_from_rule(
                        rule
                    )
                )

                counters[
                    chain_key
                ]["packets"] += packets

                counters[
                    chain_key
                ]["bytes"] += bytes_count

            if (
                family == "ip"
                and table_name
                == "secbox_nat"
                and _contains_key(
                    rule.get("expr", []),
                    "masquerade",
                )
            ):
                masquerade_interfaces.update(
                    _extract_oifnames(
                        rule.get(
                            "expr",
                            [],
                        )
                    )
                )

        set_object = wrapper.get("set")

        if (
            isinstance(set_object, dict)
            and set_object.get("family")
            == "inet"
            and set_object.get("table")
            == "secbox_filter"
            and set_object.get("name")
            == "blacklist_v4"
        ):
            elements = (
                set_object.get("elem")
                or set_object.get("elements")
                or []
            )

            if isinstance(elements, list):
                blacklist_entries = len(
                    elements
                )

    try:
        ipv4_forwarding = (
            IP_FORWARD_PATH.read_text().strip()
            == "1"
        )
    except OSError:
        ipv4_forwarding = False

    return {
        "filter_table": filter_table,
        "nat_table": nat_table,
        "ipv4_forwarding": ipv4_forwarding,
        "chains": chains,
        "rule_counts": rule_counts,
        "counters": counters,
        "masquerade_interfaces": sorted(
            masquerade_interfaces
        ),
        "blacklist_entries": (
            blacklist_entries
        ),
    }
