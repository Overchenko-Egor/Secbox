"""Minimal authoritative DNS for the synthetic corp.local topology."""

from __future__ import annotations

import asyncio
import ipaddress
import struct

from secbox.modules.deception.topology import ENTERPRISE_HOSTS


DNS_ADDRESS = "10.61.14.12"
DNS_PORT = 53
TTL = 300

TYPE_A = 1
TYPE_PTR = 12
TYPE_SRV = 33
CLASS_IN = 1


class DnsProtocolError(RuntimeError):
    pass


def encode_name(name: str) -> bytes:
    name = name.rstrip(".")

    if not name:
        return b"\x00"

    result = bytearray()

    for label in name.split("."):
        raw = label.encode("ascii")

        if not raw or len(raw) > 63:
            raise DnsProtocolError(
                f"invalid DNS label: {label!r}"
            )

        result.append(len(raw))
        result.extend(raw)

    result.append(0)

    return bytes(result)


def decode_name(
    packet: bytes,
    offset: int,
) -> tuple[str, int]:
    labels: list[str] = []

    while True:
        if offset >= len(packet):
            raise DnsProtocolError(
                "truncated DNS name"
            )

        length = packet[offset]
        offset += 1

        if length == 0:
            break

        if length & 0xC0:
            raise DnsProtocolError(
                "compressed query names not supported"
            )

        if offset + length > len(packet):
            raise DnsProtocolError(
                "truncated DNS label"
            )

        labels.append(
            packet[
                offset:offset + length
            ].decode(
                "ascii",
                errors="strict",
            )
        )

        offset += length

    return (
        ".".join(labels).lower(),
        offset,
    )


A_RECORDS = {
    host.hostname.lower():
        host.address
    for host in ENTERPRISE_HOSTS
}

PTR_RECORDS = {
    ipaddress.ip_address(
        host.address
    ).reverse_pointer:
        host.hostname.lower()
    for host in ENTERPRISE_HOSTS
}

SRV_RECORDS = {
    "_ldap._tcp.corp.local":
        (0, 100, 389, "dc01.corp.local"),
    "_ldap._tcp.dc._msdcs.corp.local":
        (0, 100, 389, "dc01.corp.local"),
    "_kerberos._tcp.corp.local":
        (0, 100, 88, "dc01.corp.local"),
    "_kerberos._udp.corp.local":
        (0, 100, 88, "dc01.corp.local"),
}


KNOWN_NAMES = (
    set(A_RECORDS)
    | set(PTR_RECORDS)
    | set(SRV_RECORDS)
    | {"corp.local"}
)


def parse_question(
    packet: bytes,
) -> tuple[str, int, int, int]:
    if len(packet) < 12:
        raise DnsProtocolError(
            "truncated DNS header"
        )

    (
        _txid,
        _flags,
        qdcount,
        _ancount,
        _nscount,
        _arcount,
    ) = struct.unpack(
        "!HHHHHH",
        packet[:12],
    )

    if qdcount != 1:
        raise DnsProtocolError(
            "exactly one DNS question required"
        )

    name, offset = decode_name(
        packet,
        12,
    )

    if offset + 4 > len(packet):
        raise DnsProtocolError(
            "truncated DNS question"
        )

    qtype, qclass = struct.unpack(
        "!HH",
        packet[offset:offset + 4],
    )

    return (
        name,
        qtype,
        qclass,
        offset + 4,
    )


def _answer(
    record_type: int,
    rdata: bytes,
) -> bytes:
    return (
        b"\xc0\x0c"
        + struct.pack(
            "!HHIH",
            record_type,
            CLASS_IN,
            TTL,
            len(rdata),
        )
        + rdata
    )


def build_response(
    packet: bytes,
) -> bytes:
    name, qtype, qclass, question_end = (
        parse_question(packet)
    )

    txid, request_flags = struct.unpack(
        "!HH",
        packet[:4],
    )

    answers: list[bytes] = []

    if qclass == CLASS_IN:
        if (
            qtype == TYPE_A
            and name in A_RECORDS
        ):
            answers.append(
                _answer(
                    TYPE_A,
                    ipaddress.IPv4Address(
                        A_RECORDS[name]
                    ).packed,
                )
            )

        elif (
            qtype == TYPE_PTR
            and name in PTR_RECORDS
        ):
            answers.append(
                _answer(
                    TYPE_PTR,
                    encode_name(
                        PTR_RECORDS[name]
                    ),
                )
            )

        elif (
            qtype == TYPE_SRV
            and name in SRV_RECORDS
        ):
            (
                priority,
                weight,
                port,
                target,
            ) = SRV_RECORDS[name]

            answers.append(
                _answer(
                    TYPE_SRV,
                    struct.pack(
                        "!HHH",
                        priority,
                        weight,
                        port,
                    )
                    + encode_name(target),
                )
            )

    rcode = (
        0
        if name in KNOWN_NAMES
        else 3
    )

    flags = (
        0x8400
        | (request_flags & 0x0100)
        | rcode
    )

    header = struct.pack(
        "!HHHHHH",
        txid,
        flags,
        1,
        len(answers),
        0,
        0,
    )

    return (
        header
        + packet[12:question_end]
        + b"".join(answers)
    )


def question_details(
    packet: bytes,
) -> dict[str, object]:
    name, qtype, qclass, _ = (
        parse_question(packet)
    )

    return {
        "qname": name,
        "qtype": qtype,
        "qclass": qclass,
    }


class DnsDatagramProtocol(
    asyncio.DatagramProtocol
):
    def __init__(
        self,
        event_callback=None,
    ):
        self.transport = None
        self.event_callback = (
            event_callback
        )

    def connection_made(
        self,
        transport,
    ):
        self.transport = transport

    def datagram_received(
        self,
        data: bytes,
        addr,
    ):
        try:
            response = build_response(
                data
            )

            details = question_details(
                data
            )
        except DnsProtocolError:
            return

        details["transport"] = "udp"

        if self.event_callback:
            self.event_callback(
                protocol="dns",
                source_ip=str(addr[0]),
                source_port=int(addr[1]),
                event="query",
                details=details,
            )

        self.transport.sendto(
            response,
            addr,
        )


async def handle_tcp(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    event_callback=None,
) -> None:
    peer = writer.get_extra_info(
        "peername"
    )

    try:
        length_raw = await reader.readexactly(
            2
        )

        length = struct.unpack(
            "!H",
            length_raw,
        )[0]

        packet = await reader.readexactly(
            length
        )

        response = build_response(
            packet
        )

        details = question_details(
            packet
        )
        details["transport"] = "tcp"

        if event_callback:
            event_callback(
                protocol="dns",
                source_ip=(
                    str(peer[0])
                    if peer
                    else "unknown"
                ),
                source_port=(
                    int(peer[1])
                    if peer
                    else None
                ),
                event="query",
                details=details,
            )

        writer.write(
            struct.pack(
                "!H",
                len(response),
            )
            + response
        )

        await writer.drain()

    except (
        asyncio.IncompleteReadError,
        DnsProtocolError,
    ):
        pass

    finally:
        writer.close()
        await writer.wait_closed()
