"""Minimal SMB2 negotiate responder for synthetic hosts."""

from __future__ import annotations

import asyncio
import struct
import time
import uuid


SMB2_MAGIC = b"\xfeSMB"
SMB2_NEGOTIATE = 0

DIALECTS = (
    0x0302,
    0x0300,
    0x0210,
    0x0202,
)

STATUS_SUCCESS = 0x00000000
STATUS_NOT_SUPPORTED = 0xC00000BB


class SmbProtocolError(RuntimeError):
    pass


def filetime_now() -> int:
    return int(
        (time.time() + 11644473600)
        * 10_000_000
    )


def read_dialects(packet: bytes) -> list[int]:
    if len(packet) < 64 + 36:
        raise SmbProtocolError(
            "short SMB2 negotiate request"
        )

    if packet[:4] != SMB2_MAGIC:
        raise SmbProtocolError(
            "not SMB2"
        )

    command = struct.unpack_from(
        "<H",
        packet,
        12,
    )[0]

    if command != SMB2_NEGOTIATE:
        raise SmbProtocolError(
            "not SMB2 negotiate"
        )

    dialect_count = struct.unpack_from(
        "<H",
        packet,
        66,
    )[0]

    start = 64 + 36
    end = start + dialect_count * 2

    if end > len(packet):
        raise SmbProtocolError(
            "truncated dialect list"
        )

    return list(
        struct.unpack_from(
            f"<{dialect_count}H",
            packet,
            start,
        )
    )


def client_guid(packet: bytes) -> str | None:
    if len(packet) < 92:
        return None

    raw = packet[76:92]

    try:
        return str(
            uuid.UUID(
                bytes_le=raw
            )
        )
    except ValueError:
        return None


def select_dialect(
    offered: list[int],
) -> int | None:
    for dialect in DIALECTS:
        if dialect in offered:
            return dialect

    return None


def response_header(
    request: bytes,
    status: int,
) -> bytes:
    message_id = (
        request[24:32]
        if len(request) >= 32
        else b"\x00" * 8
    )

    return (
        SMB2_MAGIC
        + struct.pack(
            "<H",
            64,
        )
        + struct.pack("<H", 0)
        + struct.pack("<I", status)
        + struct.pack(
            "<H",
            SMB2_NEGOTIATE,
        )
        + struct.pack("<H", 1)
        + struct.pack("<I", 1)
        + struct.pack("<I", 0)
        + message_id
        + b"\x00" * 16
        + b"\x00" * 16
    )


def build_negotiate_response(
    request: bytes,
    server_guid: bytes,
) -> tuple[bytes, int | None]:
    offered = read_dialects(
        request
    )

    selected = select_dialect(
        offered
    )

    if selected is None:
        return (
            response_header(
                request,
                STATUS_NOT_SUPPORTED,
            ),
            None,
        )

    now = filetime_now()

    body = struct.pack(
        "<HHH",
        65,
        0x0001,
        selected,
    )

    body += struct.pack("<H", 0)
    body += server_guid

    body += struct.pack(
        "<IIII",
        0,
        1024 * 1024,
        1024 * 1024,
        1024 * 1024,
    )

    body += struct.pack(
        "<QQ",
        now,
        now - 86400 * 10_000_000,
    )

    body += struct.pack(
        "<HHI",
        0,
        0,
        0,
    )

    return (
        response_header(
            request,
            STATUS_SUCCESS,
        )
        + body,
        selected,
    )


async def read_frame(
    reader: asyncio.StreamReader,
) -> tuple[int, bytes]:
    header = await reader.readexactly(
        4
    )

    frame_type = header[0]

    length = int.from_bytes(
        header[1:4],
        "big",
    )

    if length > 1024 * 1024:
        raise SmbProtocolError(
            "SMB frame too large"
        )

    payload = await reader.readexactly(
        length
    )

    return (
        frame_type,
        payload,
    )


def frame(
    payload: bytes,
    frame_type: int = 0,
) -> bytes:
    return (
        bytes((frame_type,))
        + len(payload).to_bytes(
            3,
            "big",
        )
        + payload
    )


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    event_callback=None,
) -> None:
    peer = writer.get_extra_info(
        "peername"
    )

    local = writer.get_extra_info(
        "sockname"
    )

    source_ip = (
        str(peer[0])
        if peer
        else "unknown"
    )

    source_port = (
        int(peer[1])
        if peer
        else None
    )

    target_ip = (
        str(local[0])
        if local
        else "unknown"
    )

    target_port = (
        int(local[1])
        if local
        else None
    )

    try:
        frame_type, payload = (
            await read_frame(
                reader
            )
        )

        # NetBIOS Session Request on TCP/139.
        if (
            target_port == 139
            and frame_type == 0x81
        ):
            writer.write(
                b"\x82\x00\x00\x00"
            )
            await writer.drain()

            frame_type, payload = (
                await read_frame(
                    reader
                )
            )

        if frame_type != 0x00:
            raise SmbProtocolError(
                "unsupported NetBIOS frame"
            )

        offered = read_dialects(
            payload
        )

        response, selected = (
            build_negotiate_response(
                payload,
                server_guid=uuid.UUID(
                    "7d2c53cf-5e38-4ee8-9f75-5da804f32811"
                ).bytes_le,
            )
        )

        if event_callback:
            event_callback(
                protocol="smb",
                source_ip=source_ip,
                source_port=source_port,
                event="negotiate",
                details={
                    "target_ip":
                        target_ip,
                    "target_port":
                        target_port,
                    "dialects":
                        [
                            f"0x{x:04x}"
                            for x in offered
                        ],
                    "selected_dialect":
                        (
                            f"0x{selected:04x}"
                            if selected
                            else None
                        ),
                    "client_guid":
                        client_guid(
                            payload
                        ),
                },
            )

        writer.write(
            frame(
                response
            )
        )

        await writer.drain()

    except (
        asyncio.IncompleteReadError,
        SmbProtocolError,
    ):
        pass

    finally:
        writer.close()
        await writer.wait_closed()
