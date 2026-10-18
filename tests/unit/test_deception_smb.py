import struct
import uuid

from secbox.modules.deception import smb


def negotiate(
    dialects,
):
    header = (
        b"\xfeSMB"
        + struct.pack("<H", 64)
        + b"\x00\x00"
        + b"\x00" * 4
        + struct.pack("<H", 0)
        + b"\x01\x00"
        + b"\x00" * 8
        + struct.pack("<Q", 7)
        + b"\x00" * 8
        + b"\x00" * 8
        + b"\x00" * 16
    )

    body = struct.pack(
        "<HHHHI",
        36,
        len(dialects),
        1,
        0,
        0,
    )

    body += uuid.UUID(
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    ).bytes_le

    body += b"\x00" * 8

    body += b"".join(
        struct.pack("<H", x)
        for x in dialects
    )

    return header + body


def test_reads_dialects():
    packet = negotiate(
        [0x0202, 0x0210, 0x0302]
    )

    assert smb.read_dialects(
        packet
    ) == [
        0x0202,
        0x0210,
        0x0302,
    ]


def test_selects_smb_302():
    packet = negotiate(
        [0x0202, 0x0210, 0x0302]
    )

    response, selected = (
        smb.build_negotiate_response(
            packet,
            uuid.uuid4().bytes_le,
        )
    )

    assert selected == 0x0302
    assert response[:4] == b"\xfeSMB"

    status = struct.unpack_from(
        "<I",
        response,
        8,
    )[0]

    assert status == 0


def test_rejects_unsupported_dialect():
    packet = negotiate(
        [0x0311]
    )

    response, selected = (
        smb.build_negotiate_response(
            packet,
            uuid.uuid4().bytes_le,
        )
    )

    assert selected is None

    status = struct.unpack_from(
        "<I",
        response,
        8,
    )[0]

    assert status == (
        smb.STATUS_NOT_SUPPORTED
    )


def test_client_guid():
    packet = negotiate(
        [0x0202]
    )

    assert smb.client_guid(
        packet
    ) == (
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    )
