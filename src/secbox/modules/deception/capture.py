"""Restricted packet capture entry point for one deception case."""

from __future__ import annotations

import argparse
import ipaddress
import os

from pathlib import Path

from secbox.modules.deception.store import (
    DEFAULT_CASE_ROOT,
    validate_case_id,
)


TCPDUMP = "/usr/bin/tcpdump"


def build_capture_argv(
    *,
    case_id: str,
    case_root: Path = DEFAULT_CASE_ROOT,
) -> list[str]:
    """Build fixed tcpdump argv for one case."""

    validate_case_id(
        case_id
    )

    case_path = (
        case_root
        / case_id
    )

    source_path = (
        case_path
        / "source_ip"
    )

    try:
        source = (
            source_path
            .read_text(
                encoding="utf-8"
            )
            .strip()
        )

    except OSError as error:
        raise RuntimeError(
            "failed to read case source IP"
        ) from error

    try:
        address = (
            ipaddress.ip_address(
                source
            )
        )

    except ValueError as error:
        raise RuntimeError(
            "invalid case source IP"
        ) from error

    if not isinstance(
        address,
        ipaddress.IPv4Address,
    ):
        raise RuntimeError(
            "only IPv4 capture is supported"
        )

    capture_dir = (
        case_path
        / "capture"
    )

    output = (
        capture_dir
        / "traffic.pcap"
    )

    return [
        TCPDUMP,
        "-i",
        "any",
        "-p",
        "-nn",
        "-U",
        "-s",
        "0",
        "-B",
        "4096",
        "-C",
        "16",
        "-W",
        "4",
        "-w",
        str(output),
        "host",
        str(address),
    ]


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--case-id",
        required=True,
    )

    arguments = parser.parse_args()

    argv = build_capture_argv(
        case_id=arguments.case_id
    )

    os.execv(
        TCPDUMP,
        argv,
    )


if __name__ == "__main__":
    main()
