"""Runtime reconciliation for transparent Deception quarantine."""

from __future__ import annotations

import ipaddress
import re
import subprocess

from pathlib import Path

from secbox.modules.deception import routing
from secbox.modules.deception.steering import (
    DEFAULT_STATE_PATH,
    active_sources,
)


NFT_BIN = "/usr/sbin/nft"

NFT_FAMILY = "inet"
NFT_TABLE = "secbox_filter"
NFT_SET = "deception_sources_v4"

NAMESPACE = "secbox-deception"
NAMESPACE_INTERFACE = "eth0"
NAMESPACE_HOST_GATEWAY = "10.250.0.1"


class DeceptionRuntimeError(RuntimeError):
    """Failed to reconcile Deception quarantine runtime."""


def _run(
    command: list[str],
    *,
    input_text: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )

    if check and result.returncode != 0:
        message = (
            result.stderr.strip()
            or result.stdout.strip()
            or f"exit code {result.returncode}"
        )

        raise DeceptionRuntimeError(
            f"{' '.join(command)}: {message}"
        )

    return result


def _preflight() -> None:
    if not Path(
        f"/sys/class/net/{routing.HOST_INTERFACE}"
    ).exists():
        raise DeceptionRuntimeError(
            f"{routing.HOST_INTERFACE} does not exist"
        )

    namespaces = _run(
        [
            routing.IP_BIN,
            "netns",
            "list",
        ]
    ).stdout

    if NAMESPACE not in {
        line.split()[0]
        for line in namespaces.splitlines()
        if line.strip()
    }:
        raise DeceptionRuntimeError(
            f"network namespace {NAMESPACE} does not exist"
        )

    _run(
        [
            NFT_BIN,
            "list",
            "set",
            NFT_FAMILY,
            NFT_TABLE,
            NFT_SET,
        ]
    )


def _policy_rule_lines() -> list[str]:
    return _run(
        [
            routing.IP_BIN,
            "-4",
            "rule",
            "show",
        ]
    ).stdout.splitlines()


def _ensure_policy_rule() -> None:
    lines = _policy_rule_lines()

    priority_lines = [
        line
        for line in lines
        if line.lstrip().startswith(
            f"{routing.RULE_PRIORITY}:"
        )
    ]

    ours = [
        line
        for line in priority_lines
        if (
            "fwmark 0x400/0x400" in line
            and "lookup 260" in line
        )
    ]

    if priority_lines and not ours:
        raise DeceptionRuntimeError(
            f"ip rule priority {routing.RULE_PRIORITY} "
            "is already occupied"
        )

    if len(ours) > 1:
        raise DeceptionRuntimeError(
            "duplicate Deception policy rules detected"
        )

    if not ours:
        _run(
            routing.policy_rule_add_command()
        )


def _ensure_policy_routes() -> None:
    _run(
        routing.quarantine_connected_route_command()
    )

    _run(
        routing.quarantine_default_route_command()
    )

    blackholes = _run(
        [
            routing.IP_BIN,
            "-4",
            "route",
            "show",
            "table",
            str(routing.ROUTING_TABLE),
            "type",
            "blackhole",
        ]
    ).stdout

    if "blackhole default" not in blackholes:
        _run(
            routing.fail_closed_route_command()
        )


def _managed_namespace_routes() -> set[str]:
    output = _run(
        [
            routing.IP_BIN,
            "-n",
            NAMESPACE,
            "-4",
            "route",
            "show",
        ]
    ).stdout

    result: set[str] = set()

    pattern = re.compile(
        r"^(\d+\.\d+\.\d+\.\d+)(?:/32)? "
        r"via 10\.250\.0\.1 "
        r"dev eth0(?:\s|$)"
    )

    for line in output.splitlines():
        match = pattern.match(
            line.strip()
        )

        if not match:
            continue

        try:
            address = str(
                ipaddress.IPv4Address(
                    match.group(1)
                )
            )
        except ipaddress.AddressValueError:
            continue

        result.add(address)

    return result


def _add_namespace_routes(
    desired: set[str],
) -> None:
    current = _managed_namespace_routes()

    for source_ip in sorted(
        desired - current,
        key=lambda value: int(
            ipaddress.IPv4Address(value)
        ),
    ):
        _run(
            routing.namespace_source_route_add_command(
                source_ip
            )
        )


def _remove_stale_namespace_routes(
    desired: set[str],
) -> None:
    current = _managed_namespace_routes()

    for source_ip in sorted(
        current - desired,
        key=lambda value: int(
            ipaddress.IPv4Address(value)
        ),
    ):
        _run(
            routing.namespace_source_route_delete_command(
                source_ip
            )
        )


def _nft_sync_script(
    sources: set[str],
) -> str:
    lines = [
        (
            f"flush set {NFT_FAMILY} "
            f"{NFT_TABLE} {NFT_SET}"
        )
    ]

    if sources:
        elements = ", ".join(
            sorted(
                sources,
                key=lambda value: int(
                    ipaddress.IPv4Address(value)
                ),
            )
        )

        lines.append(
            f"add element {NFT_FAMILY} "
            f"{NFT_TABLE} {NFT_SET} "
            f"{{ {elements} }}"
        )

    return "\n".join(lines) + "\n"


def _sync_nft_set(
    sources: set[str],
) -> None:
    _run(
        [
            NFT_BIN,
            "-f",
            "-",
        ],
        input_text=_nft_sync_script(
            sources
        ),
    )


def reconcile(
    state_path: Path = DEFAULT_STATE_PATH,
) -> dict[str, object]:
    """Reconcile persistent quarantine state into kernel runtime."""

    sources = set(
        active_sources(
            state_path
        )
    )

    _preflight()

    # Prepare the fail-closed path before activating any source.
    _ensure_policy_routes()
    _ensure_policy_rule()

    # Replies from the deception namespace need one explicit /32 per source.
    _add_namespace_routes(
        sources
    )

    # Activation is atomic and deliberately happens after routing is ready.
    _sync_nft_set(
        sources
    )

    # Removing stale routes happens only after sources were removed from nft.
    _remove_stale_namespace_routes(
        sources
    )

    return {
        "sources":
            sorted(
                sources,
                key=lambda value:
                    int(
                        ipaddress.IPv4Address(
                            value
                        )
                    ),
            ),
        "source_count":
            len(sources),
        "routing_table":
            routing.ROUTING_TABLE,
        "fwmark":
            hex(routing.FWMARK),
    }


def main() -> None:
    import json

    print(
        json.dumps(
            reconcile(),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
