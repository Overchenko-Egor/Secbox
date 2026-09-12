"""Parser for managed DoH resolver feeds."""

from ipaddress import IPv4Address, ip_address


class DohFeedParseError(Exception):
    """Raised when a DoH resolver feed cannot be parsed."""


def parse_doh_feed(text: str) -> list[IPv4Address]:
    """Parse IPv4 resolver addresses from a text feed."""

    addresses: set[IPv4Address] = set()

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        token = line.split()[0]

        try:
            parsed = ip_address(token)
        except ValueError:
            continue

        if not isinstance(parsed, IPv4Address):
            continue

        addresses.add(parsed)

    if not addresses:
        raise DohFeedParseError(
            "DoH feed contains no valid IPv4 addresses"
        )

    return sorted(
        addresses,
        key=int,
    )
