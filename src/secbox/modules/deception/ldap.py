"""Minimal LDAPv3 responder for synthetic corp.local."""

from __future__ import annotations

import asyncio


LDAP_ADDRESS = "10.61.14.12"
LDAP_PORT = 389
LDAPS_PORT = 636

BASE_DN = "DC=corp,DC=local"
DC_HOSTNAME = "dc01.corp.local"


class LdapProtocolError(RuntimeError):
    pass


def enc_len(value: int) -> bytes:
    if value < 0x80:
        return bytes((value,))

    raw = value.to_bytes(
        (value.bit_length() + 7) // 8,
        "big",
    )

    return bytes(
        (0x80 | len(raw),)
    ) + raw


def tlv(
    tag: int,
    payload: bytes,
) -> bytes:
    return (
        bytes((tag,))
        + enc_len(len(payload))
        + payload
    )


def integer(value: int) -> bytes:
    if value == 0:
        raw = b"\x00"
    else:
        raw = value.to_bytes(
            max(
                1,
                (value.bit_length() + 7) // 8,
            ),
            "big",
        )

        if raw[0] & 0x80:
            raw = b"\x00" + raw

    return tlv(
        0x02,
        raw,
    )


def enum(value: int) -> bytes:
    return tlv(
        0x0A,
        bytes((value,)),
    )


def octet(value: str) -> bytes:
    return tlv(
        0x04,
        value.encode("utf-8"),
    )


def read_length(
    data: bytes,
    offset: int,
) -> tuple[int, int]:
    if offset >= len(data):
        raise LdapProtocolError(
            "missing BER length"
        )

    first = data[offset]
    offset += 1

    if first < 0x80:
        return first, offset

    count = first & 0x7F

    if (
        count == 0
        or count > 4
        or offset + count > len(data)
    ):
        raise LdapProtocolError(
            "invalid BER length"
        )

    value = int.from_bytes(
        data[offset:offset + count],
        "big",
    )

    return (
        value,
        offset + count,
    )


def read_tlv(
    data: bytes,
    offset: int,
) -> tuple[int, bytes, int]:
    if offset >= len(data):
        raise LdapProtocolError(
            "missing BER tag"
        )

    tag = data[offset]
    length, start = read_length(
        data,
        offset + 1,
    )

    end = start + length

    if end > len(data):
        raise LdapProtocolError(
            "truncated BER value"
        )

    return (
        tag,
        data[start:end],
        end,
    )


def parse_message(
    packet: bytes,
) -> tuple[int, int, bytes]:
    tag, body, end = read_tlv(
        packet,
        0,
    )

    if tag != 0x30 or end != len(packet):
        raise LdapProtocolError(
            "invalid LDAP message"
        )

    tag, raw_id, offset = read_tlv(
        body,
        0,
    )

    if tag != 0x02:
        raise LdapProtocolError(
            "missing LDAP message id"
        )

    message_id = int.from_bytes(
        raw_id,
        "big",
    )

    op_tag, op_body, _ = read_tlv(
        body,
        offset,
    )

    return (
        message_id,
        op_tag,
        op_body,
    )


def ldap_message(
    message_id: int,
    operation: bytes,
) -> bytes:
    return tlv(
        0x30,
        integer(message_id)
        + operation,
    )


def ldap_result(
    tag: int,
    message_id: int,
    code: int = 0,
    message: str = "",
) -> bytes:
    operation = tlv(
        tag,
        enum(code)
        + octet("")
        + octet(message),
    )

    return ldap_message(
        message_id,
        operation,
    )


def attribute(
    name: str,
    values: tuple[str, ...],
) -> bytes:
    value_set = tlv(
        0x31,
        b"".join(
            octet(value)
            for value in values
        ),
    )

    return tlv(
        0x30,
        octet(name)
        + value_set,
    )


def search_entry(
    message_id: int,
    dn: str,
    attributes: dict[str, tuple[str, ...]],
) -> bytes:
    attrs = tlv(
        0x30,
        b"".join(
            attribute(
                name,
                values,
            )
            for name, values
            in attributes.items()
        ),
    )

    operation = tlv(
        0x64,
        octet(dn)
        + attrs,
    )

    return ldap_message(
        message_id,
        operation,
    )


ROOT_DSE = {
    "defaultNamingContext": (
        BASE_DN,
    ),
    "namingContexts": (
        BASE_DN,
    ),
    "dnsHostName": (
        DC_HOSTNAME,
    ),
    "supportedLDAPVersion": (
        "3",
    ),
    "supportedSASLMechanisms": (
        "GSSAPI",
        "GSS-SPNEGO",
    ),
}


DOMAIN_ENTRY = {
    "objectClass": (
        "top",
        "domain",
    ),
    "dc": (
        "corp",
    ),
    "distinguishedName": (
        BASE_DN,
    ),
}


def search_base(
    operation: bytes,
) -> str:
    tag, value, _ = read_tlv(
        operation,
        0,
    )

    if tag != 0x04:
        raise LdapProtocolError(
            "missing search base DN"
        )

    return value.decode(
        "utf-8",
        errors="replace",
    )


def build_responses(
    packet: bytes,
) -> list[bytes]:
    message_id, op_tag, operation = (
        parse_message(
            packet
        )
    )

    # BindRequest
    if op_tag == 0x60:
        return [
            ldap_result(
                0x61,
                message_id,
                0,
            )
        ]

    # SearchRequest
    if op_tag == 0x63:
        base = search_base(
            operation
        )

        responses: list[bytes] = []

        if base == "":
            responses.append(
                search_entry(
                    message_id,
                    "",
                    ROOT_DSE,
                )
            )

        elif base.lower() == BASE_DN.lower():
            responses.append(
                search_entry(
                    message_id,
                    BASE_DN,
                    DOMAIN_ENTRY,
                )
            )

        responses.append(
            ldap_result(
                0x65,
                message_id,
                0,
            )
        )

        return responses

    return [
        ldap_result(
            0x65,
            message_id,
            2,
            "Unsupported operation",
        )
    ]


async def read_message(
    reader: asyncio.StreamReader,
) -> bytes:
    tag = await reader.readexactly(
        1
    )

    if tag != b"\x30":
        raise LdapProtocolError(
            "invalid LDAP outer tag"
        )

    first = await reader.readexactly(
        1
    )

    length_byte = first[0]

    if length_byte < 0x80:
        length = length_byte
        prefix = first
    else:
        count = length_byte & 0x7F

        raw = await reader.readexactly(
            count
        )

        length = int.from_bytes(
            raw,
            "big",
        )

        prefix = first + raw

    body = await reader.readexactly(
        length
    )

    return (
        b"\x30"
        + prefix
        + body
    )


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    event_callback=None,
) -> None:
    peer = writer.get_extra_info(
        "peername"
    )

    try:
        while True:
            try:
                packet = await read_message(
                    reader
                )
            except asyncio.IncompleteReadError:
                break

            message_id, op_tag, operation = (
                parse_message(
                    packet
                )
            )

            details = {
                "message_id": message_id,
                "operation_tag": op_tag,
            }

            if op_tag == 0x63:
                details["base_dn"] = (
                    search_base(
                        operation
                    )
                )

            if event_callback:
                event_callback(
                    protocol="ldap",
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
                    event="request",
                    details=details,
                )

            for response in build_responses(
                packet
            ):
                writer.write(
                    response
                )

            await writer.drain()

    except LdapProtocolError:
        pass

    finally:
        writer.close()
        await writer.wait_closed()
