"""Runtime IPv4 routing information."""

import json
import subprocess
from pydantic import BaseModel, ConfigDict


class NetworkRoute(BaseModel):
    """Observed IPv4 route."""

    model_config = ConfigDict(extra="forbid")

    destination: str
    gateway: str | None = None
    interface: str | None = None
    source: str | None = None
    protocol: str | None = None
    metric: int | None = None
    table: int | str | None = None


class RouteDiscoveryError(Exception):
    """Raised when routing information cannot be obtained."""


def discover_ipv4_routes() -> list[NetworkRoute]:
    """Return current IPv4 routes from the kernel."""

    try:
        result = subprocess.run(
            [
                "ip",
                "-4",
                "-json",
                "route",
                "show",
                "table",
                "all",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise RouteDiscoveryError(
            f"failed to discover IPv4 routes: {error}"
        ) from error

    try:
        raw_routes = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RouteDiscoveryError(
            f"invalid routing JSON returned by iproute2: {error}"
        ) from error

    if not isinstance(raw_routes, list):
        raise RouteDiscoveryError(
            "unexpected IPv4 routing JSON structure"
        )

    routes: list[NetworkRoute] = []

    for raw_route in raw_routes:
        if not isinstance(raw_route, dict):
            continue

        destination = raw_route.get("dst", "default")

        gateway = raw_route.get("gateway")
        interface = raw_route.get("dev")
        source = raw_route.get("prefsrc")
        protocol = raw_route.get("protocol")
        metric = raw_route.get("metric")
        table = raw_route.get("table")

        if isinstance(table, str) and table.isdigit():
            table = int(table)

        if not isinstance(destination, str):
            continue

        routes.append(
            NetworkRoute(
                destination=destination,
                gateway=gateway if isinstance(gateway, str) else None,
                interface=interface if isinstance(interface, str) else None,
                source=source if isinstance(source, str) else None,
                protocol=protocol if isinstance(protocol, str) else None,
                metric=metric if isinstance(metric, int) else None,
                table=table if isinstance(table, (int, str)) else None,
            )
        )

    return routes
