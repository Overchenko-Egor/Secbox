"""Classification of Suricata observations."""

import ipaddress
from dataclasses import dataclass
from enum import StrEnum

from secbox.modules.ids.models import SuricataAlertEvent


class TrafficClass(StrEnum):
    """Network position of a Suricata alert."""

    LAN_OUTBOUND_PRE_NAT = "lan_outbound_pre_nat"
    WAN_OUTBOUND_POST_NAT = "wan_outbound_post_nat"
    WAN_INBOUND = "wan_inbound"
    LAN_INBOUND = "lan_inbound"
    UNKNOWN = "unknown"


class TrafficClassificationError(Exception):
    """Raised when an IDS event cannot be classified."""


@dataclass(frozen=True)
class IdsNetworkContext:
    """Network information required for IDS classification."""

    wan_interface: str
    lan_interface: str

    wan_ipv4_addresses: tuple[
        ipaddress.IPv4Address,
        ...,
    ]

    lan_ipv4_networks: tuple[
        ipaddress.IPv4Network,
        ...,
    ]


@dataclass(frozen=True)
class TrafficObservation:
    """Classified Suricata alert observation."""

    event: SuricataAlertEvent
    traffic_class: TrafficClass

    @property
    def interface(self) -> str | None:
        """Return interface where the event was observed."""

        return self.event.in_iface

    @property
    def source_ip(self) -> str:
        """Return source IP address."""

        return self.event.src_ip

    @property
    def destination_ip(self) -> str:
        """Return destination IP address."""

        return self.event.dest_ip


def parse_ip_address(
    address: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parse and validate an IP address."""

    try:
        return ipaddress.ip_address(address)
    except ValueError as error:
        raise TrafficClassificationError(
            f"invalid IP address: {address}"
        ) from error


def address_in_lan(
    address: ipaddress.IPv4Address,
    networks: tuple[
        ipaddress.IPv4Network,
        ...,
    ],
) -> bool:
    """Check whether an address belongs to a configured LAN."""

    return any(
        address in network
        for network in networks
    )


def classify_alert(
    event: SuricataAlertEvent,
    context: IdsNetworkContext,
) -> TrafficObservation:
    """Classify a Suricata alert by network observation point."""

    source = parse_ip_address(
        event.src_ip
    )
    destination = parse_ip_address(
        event.dest_ip
    )

    if (
        not isinstance(
            source,
            ipaddress.IPv4Address,
        )
        or not isinstance(
            destination,
            ipaddress.IPv4Address,
        )
    ):
        return TrafficObservation(
            event=event,
            traffic_class=TrafficClass.UNKNOWN,
        )

    if event.in_iface == context.lan_interface:
        source_is_lan = address_in_lan(
            source,
            context.lan_ipv4_networks,
        )
        destination_is_lan = address_in_lan(
            destination,
            context.lan_ipv4_networks,
        )

        if (
            source_is_lan
            and not destination_is_lan
        ):
            traffic_class = (
                TrafficClass.LAN_OUTBOUND_PRE_NAT
            )

        elif (
            not source_is_lan
            and destination_is_lan
        ):
            traffic_class = (
                TrafficClass.LAN_INBOUND
            )

        else:
            traffic_class = TrafficClass.UNKNOWN

        return TrafficObservation(
            event=event,
            traffic_class=traffic_class,
        )

    if event.in_iface == context.wan_interface:
        source_is_wan = (
            source
            in context.wan_ipv4_addresses
        )

        destination_is_wan = (
            destination
            in context.wan_ipv4_addresses
        )

        if (
            source_is_wan
            and not destination_is_wan
        ):
            traffic_class = (
                TrafficClass.WAN_OUTBOUND_POST_NAT
            )

        elif (
            not source_is_wan
            and destination_is_wan
        ):
            traffic_class = (
                TrafficClass.WAN_INBOUND
            )

        else:
            traffic_class = TrafficClass.UNKNOWN

        return TrafficObservation(
            event=event,
            traffic_class=traffic_class,
        )

    return TrafficObservation(
        event=event,
        traffic_class=TrafficClass.UNKNOWN,
    )
