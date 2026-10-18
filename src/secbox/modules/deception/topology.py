"""Synthetic enterprise topology for SecBox Deception."""

from __future__ import annotations

import ipaddress
import subprocess

from dataclasses import dataclass


IP_BIN = "/usr/bin/ip"
NAMESPACE = "secbox-deception"
LOOPBACK = "lo"


class DeceptionTopologyError(RuntimeError):
    """Invalid or unavailable synthetic Deception topology."""


@dataclass(frozen=True)
class FakeHost:
    address: str
    hostname: str
    role: str
    os_family: str
    services: tuple[int, ...]


ENTERPRISE_HOSTS: tuple[FakeHost, ...] = (
    FakeHost(
        address="10.61.14.12",
        hostname="dc01.corp.local",
        role="domain-controller",
        os_family="windows",
        services=(53, 88, 135, 389, 445, 636),
    ),
    FakeHost(
        address="10.61.21.34",
        hostname="gitlab.corp.local",
        role="git-service",
        os_family="linux",
        services=(22, 80, 443),
    ),
    FakeHost(
        address="10.61.32.18",
        hostname="intranet.corp.local",
        role="intranet",
        os_family="linux",
        services=(80, 443),
    ),
    FakeHost(
        address="10.62.4.9",
        hostname="backup01.corp.local",
        role="backup",
        os_family="linux",
        services=(22, 445),
    ),
    FakeHost(
        address="10.62.18.23",
        hostname="postgres01.corp.local",
        role="database",
        os_family="linux",
        services=(22, 5432),
    ),
    FakeHost(
        address="10.62.30.15",
        hostname="nas01.corp.local",
        role="storage",
        os_family="linux",
        services=(22, 139, 445),
    ),
    FakeHost(
        address="10.63.7.11",
        hostname="zabbix.corp.local",
        role="monitoring",
        os_family="linux",
        services=(22, 80, 443, 10051),
    ),
    FakeHost(
        address="10.63.17.51",
        hostname="monitoring.corp.local",
        role="observability",
        os_family="linux",
        services=(22, 3000, 9090),
    ),
    FakeHost(
        address="10.63.24.8",
        hostname="logs.corp.local",
        role="logging",
        os_family="linux",
        services=(22, 9200),
    ),
)


def validate_inventory(
    hosts: tuple[FakeHost, ...] = ENTERPRISE_HOSTS,
) -> None:
    addresses: set[str] = set()
    hostnames: set[str] = set()

    allowed_ranges = (
        ipaddress.IPv4Network("10.61.0.0/16"),
        ipaddress.IPv4Network("10.62.0.0/16"),
        ipaddress.IPv4Network("10.63.0.0/16"),
    )

    for host in hosts:
        try:
            address = ipaddress.IPv4Address(
                host.address
            )
        except ipaddress.AddressValueError as error:
            raise DeceptionTopologyError(
                f"invalid fake host address: {host.address}"
            ) from error

        if not any(
            address in network
            for network in allowed_ranges
        ):
            raise DeceptionTopologyError(
                f"fake host outside shadow ranges: {address}"
            )

        if str(address) in addresses:
            raise DeceptionTopologyError(
                f"duplicate fake host address: {address}"
            )

        if host.hostname in hostnames:
            raise DeceptionTopologyError(
                f"duplicate fake hostname: {host.hostname}"
            )

        addresses.add(
            str(address)
        )
        hostnames.add(
            host.hostname
        )


def addresses() -> list[str]:
    validate_inventory()

    return sorted(
        (
            host.address
            for host in ENTERPRISE_HOSTS
        ),
        key=lambda value:
            int(
                ipaddress.IPv4Address(
                    value
                )
            ),
    )


def get_host(
    address: str,
) -> FakeHost | None:
    normalized = str(
        ipaddress.IPv4Address(
            address
        )
    )

    for host in ENTERPRISE_HOSTS:
        if host.address == normalized:
            return host

    return None


def _run(
    command: list[str],
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        message = (
            result.stderr.strip()
            or result.stdout.strip()
            or f"exit code {result.returncode}"
        )

        raise DeceptionTopologyError(
            f"{' '.join(command)}: {message}"
        )

    return result


def current_addresses() -> set[str]:
    output = _run(
        [
            IP_BIN,
            "-n",
            NAMESPACE,
            "-4",
            "-o",
            "addr",
            "show",
            "dev",
            LOOPBACK,
        ]
    ).stdout

    result: set[str] = set()

    for line in output.splitlines():
        fields = line.split()

        try:
            index = fields.index("inet")
        except ValueError:
            continue

        if index + 1 >= len(fields):
            continue

        interface = ipaddress.IPv4Interface(
            fields[index + 1]
        )

        address = str(
            interface.ip
        )

        if address.startswith(
            (
                "10.61.",
                "10.62.",
                "10.63.",
            )
        ):
            result.add(
                address
            )

    return result


def reconcile_addresses() -> dict[str, object]:
    desired = set(
        addresses()
    )

    current = current_addresses()

    added: list[str] = []
    removed: list[str] = []

    for address in sorted(
        desired - current,
        key=lambda value:
            int(
                ipaddress.IPv4Address(
                    value
                )
            ),
    ):
        _run(
            [
                IP_BIN,
                "-n",
                NAMESPACE,
                "addr",
                "add",
                f"{address}/32",
                "dev",
                LOOPBACK,
            ]
        )

        added.append(
            address
        )

    for address in sorted(
        current - desired,
        key=lambda value:
            int(
                ipaddress.IPv4Address(
                    value
                )
            ),
    ):
        _run(
            [
                IP_BIN,
                "-n",
                NAMESPACE,
                "addr",
                "del",
                f"{address}/32",
                "dev",
                LOOPBACK,
            ]
        )

        removed.append(
            address
        )

    return {
        "host_count":
            len(desired),
        "added":
            added,
        "removed":
            removed,
        "addresses":
            addresses(),
    }


def main() -> None:
    import json

    print(
        json.dumps(
            reconcile_addresses(),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
