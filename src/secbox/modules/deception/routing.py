"""Policy routing primitives for Deception quarantine."""

from __future__ import annotations

import ipaddress


IP_BIN = "/usr/bin/ip"

ROUTING_TABLE = 260
RULE_PRIORITY = 80

FWMARK = 0x400
FWMASK = 0x400

HOST_INTERFACE = "veth-dec-host"
NAMESPACE_GATEWAY = "10.250.0.2"

MANAGEMENT_INTERFACE = "ens38"


class DeceptionRoutingError(RuntimeError):
    """Invalid Deception policy-routing configuration."""


def normalize_source_ip(
    source_ip: str,
) -> str:
    try:
        address = ipaddress.ip_address(
            source_ip
        )
    except ValueError as error:
        raise DeceptionRoutingError(
            "invalid source IPv4 address"
        ) from error

    if not isinstance(
        address,
        ipaddress.IPv4Address,
    ):
        raise DeceptionRoutingError(
            "only IPv4 sources are supported"
        )

    return str(address)


def validate_ingress_interfaces(
    interfaces: list[str],
    *,
    management_interface: str = MANAGEMENT_INTERFACE,
) -> list[str]:
    result: list[str] = []

    for interface in interfaces:
        value = interface.strip()

        if not value:
            raise DeceptionRoutingError(
                "empty ingress interface"
            )

        if value == management_interface:
            raise DeceptionRoutingError(
                "management interface must not be quarantined"
            )

        if value not in result:
            result.append(
                value
            )

    if not result:
        raise DeceptionRoutingError(
            "at least one ingress interface is required"
        )

    return result


def policy_rule_add_command() -> list[str]:
    return [
        IP_BIN,
        "-4",
        "rule",
        "add",
        "priority",
        str(RULE_PRIORITY),
        "fwmark",
        f"{hex(FWMARK)}/{hex(FWMASK)}",
        "lookup",
        str(ROUTING_TABLE),
    ]


def policy_rule_delete_command() -> list[str]:
    return [
        IP_BIN,
        "-4",
        "rule",
        "delete",
        "priority",
        str(RULE_PRIORITY),
        "fwmark",
        f"{hex(FWMARK)}/{hex(FWMASK)}",
        "lookup",
        str(ROUTING_TABLE),
    ]


def quarantine_connected_route_command() -> list[str]:
    return [
        IP_BIN,
        "-4",
        "route",
        "replace",
        "table",
        str(ROUTING_TABLE),
        "10.250.0.0/24",
        "dev",
        HOST_INTERFACE,
        "scope",
        "link",
    ]


def quarantine_default_route_command() -> list[str]:
    return [
        IP_BIN,
        "-4",
        "route",
        "replace",
        "table",
        str(ROUTING_TABLE),
        "default",
        "via",
        NAMESPACE_GATEWAY,
        "dev",
        HOST_INTERFACE,
        "metric",
        "10",
    ]


def fail_closed_route_command() -> list[str]:
    return [
        IP_BIN,
        "-4",
        "route",
        "add",
        "table",
        str(ROUTING_TABLE),
        "blackhole",
        "default",
        "metric",
        "32760",
    ]


def flush_table_command() -> list[str]:
    return [
        IP_BIN,
        "-4",
        "route",
        "flush",
        "table",
        str(ROUTING_TABLE),
    ]


def namespace_source_route_add_command(
    source_ip: str,
) -> list[str]:
    address = normalize_source_ip(
        source_ip
    )

    return [
        IP_BIN,
        "-n",
        "secbox-deception",
        "-4",
        "route",
        "replace",
        f"{address}/32",
        "via",
        "10.250.0.1",
        "dev",
        "eth0",
    ]


def namespace_source_route_delete_command(
    source_ip: str,
) -> list[str]:
    address = normalize_source_ip(
        source_ip
    )

    return [
        IP_BIN,
        "-n",
        "secbox-deception",
        "-4",
        "route",
        "delete",
        f"{address}/32",
    ]
