"""Network namespace for the SecBox Deception environment."""

from __future__ import annotations

import argparse
import json
import subprocess


IP = "/usr/bin/ip"

NAMESPACE = "secbox-deception"

HOST_INTERFACE = "veth-dec-host"
NAMESPACE_INTERFACE = "eth0"

HOST_ADDRESS = "10.250.0.1/24"
NAMESPACE_ADDRESS = "10.250.0.2/24"

NETWORK = "10.250.0.0/24"


class DeceptionNetworkError(
    RuntimeError
):
    """Deception network operation failed."""


def _run(
    argv: list[str],
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    if (
        check
        and result.returncode != 0
    ):
        detail = (
            result.stderr.strip()
            or result.stdout.strip()
            or (
                "exit code "
                f"{result.returncode}"
            )
        )

        raise DeceptionNetworkError(
            f"{' '.join(argv)} failed: "
            f"{detail}"
        )

    return result


def namespace_exists() -> bool:
    result = _run(
        [
            IP,
            "netns",
            "list",
        ]
    )

    for line in (
        result.stdout
        .splitlines()
    ):
        name = (
            line.split(
                None,
                1,
            )[0]
            if line.strip()
            else ""
        )

        if name == NAMESPACE:
            return True

    return False


def link_exists(
    name: str,
) -> bool:
    result = _run(
        [
            IP,
            "link",
            "show",
            "dev",
            name,
        ],
        check=False,
    )

    return (
        result.returncode
        == 0
    )


def down() -> None:
    """Remove the complete deception network."""

    if namespace_exists():
        _run(
            [
                IP,
                "netns",
                "delete",
                NAMESPACE,
            ]
        )

    # Normally deleting the namespace also removes
    # the namespace side of the veth pair.
    # Delete any stale host side explicitly.
    if link_exists(
        HOST_INTERFACE
    ):
        _run(
            [
                IP,
                "link",
                "delete",
                "dev",
                HOST_INTERFACE,
            ]
        )


def up() -> None:
    """Create the isolated deception namespace."""

    # Idempotent reconciliation.
    down()

    created_namespace = False

    try:
        _run(
            [
                IP,
                "netns",
                "add",
                NAMESPACE,
            ]
        )

        created_namespace = True

        _run(
            [
                IP,
                "link",
                "add",
                HOST_INTERFACE,
                "type",
                "veth",
                "peer",
                "name",
                "veth-dec-peer",
            ]
        )

        _run(
            [
                IP,
                "link",
                "set",
                "dev",
                "veth-dec-peer",
                "netns",
                NAMESPACE,
            ]
        )

        # Prevent automatic IPv6 link-local addresses.
        _run(
            [
                IP,
                "link",
                "set",
                "dev",
                HOST_INTERFACE,
                "addrgenmode",
                "none",
            ]
        )

        _run(
            [
                IP,
                "-n",
                NAMESPACE,
                "link",
                "set",
                "dev",
                "veth-dec-peer",
                "name",
                NAMESPACE_INTERFACE,
            ]
        )

        _run(
            [
                IP,
                "-n",
                NAMESPACE,
                "link",
                "set",
                "dev",
                NAMESPACE_INTERFACE,
                "addrgenmode",
                "none",
            ]
        )

        _run(
            [
                IP,
                "address",
                "add",
                HOST_ADDRESS,
                "dev",
                HOST_INTERFACE,
            ]
        )

        _run(
            [
                IP,
                "link",
                "set",
                "dev",
                HOST_INTERFACE,
                "up",
            ]
        )

        _run(
            [
                IP,
                "-n",
                NAMESPACE,
                "address",
                "add",
                NAMESPACE_ADDRESS,
                "dev",
                NAMESPACE_INTERFACE,
            ]
        )

        _run(
            [
                IP,
                "-n",
                NAMESPACE,
                "link",
                "set",
                "dev",
                "lo",
                "up",
            ]
        )

        _run(
            [
                IP,
                "-n",
                NAMESPACE,
                "link",
                "set",
                "dev",
                NAMESPACE_INTERFACE,
                "up",
            ]
        )

        # Defense against accidental IPv6 configuration.
        _run(
            [
                IP,
                "-n",
                NAMESPACE,
                "-6",
                "address",
                "flush",
                "dev",
                NAMESPACE_INTERFACE,
                "scope",
                "link",
            ],
            check=False,
        )

        verify()

    except Exception:
        if created_namespace:
            try:
                down()
            except Exception:
                pass

        raise


def routes() -> list[dict[str, object]]:
    result = _run(
        [
            IP,
            "-n",
            NAMESPACE,
            "-j",
            "-4",
            "route",
            "show",
        ]
    )

    try:
        value = json.loads(
            result.stdout
        )

    except json.JSONDecodeError as error:
        raise DeceptionNetworkError(
            "failed to parse namespace routes"
        ) from error

    if not isinstance(
        value,
        list,
    ):
        raise DeceptionNetworkError(
            "invalid namespace route response"
        )

    return value


def verify() -> None:
    """Verify the expected isolation invariant."""

    if not namespace_exists():
        raise DeceptionNetworkError(
            "deception namespace is missing"
        )

    if not link_exists(
        HOST_INTERFACE
    ):
        raise DeceptionNetworkError(
            "deception host interface is missing"
        )

    route_list = routes()

    default_routes = [
        route
        for route
        in route_list
        if route.get(
            "dst"
        ) == "default"
    ]

    if default_routes:
        raise DeceptionNetworkError(
            "deception namespace has a default route"
        )

    unexpected = []

    for route in route_list:
        destination = route.get(
            "dst"
        )

        if destination not in {
            NETWORK,
        }:
            unexpected.append(
                destination
            )

    if unexpected:
        raise DeceptionNetworkError(
            "deception namespace contains "
            "unexpected routes: "
            f"{unexpected}"
        )


def status() -> dict[str, object]:
    if not namespace_exists():
        return {
            "active": False,
            "namespace":
                NAMESPACE,
        }

    verify()

    return {
        "active":
            True,
        "namespace":
            NAMESPACE,
        "host_interface":
            HOST_INTERFACE,
        "namespace_interface":
            NAMESPACE_INTERFACE,
        "host_address":
            HOST_ADDRESS,
        "namespace_address":
            NAMESPACE_ADDRESS,
        "routes":
            routes(),
    }


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "operation",
        choices=(
            "up",
            "down",
            "verify",
            "status",
        ),
    )

    arguments = (
        parser.parse_args()
    )

    if arguments.operation == "up":
        up()
        return

    if arguments.operation == "down":
        down()
        return

    if arguments.operation == "verify":
        verify()
        return

    print(
        json.dumps(
            status(),
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
