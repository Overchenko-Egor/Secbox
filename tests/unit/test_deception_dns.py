import struct

from secbox.modules.deception import dns


def query(
    name: str,
    qtype: int,
) -> bytes:
    return (
        struct.pack(
            "!HHHHHH",
            0x1234,
            0x0100,
            1,
            0,
            0,
            0,
        )
        + dns.encode_name(name)
        + struct.pack(
            "!HH",
            qtype,
            1,
        )
    )


def header(packet: bytes):
    return struct.unpack(
        "!HHHHHH",
        packet[:12],
    )


def test_a_gitlab():
    response = dns.build_response(
        query(
            "gitlab.corp.local",
            dns.TYPE_A,
        )
    )

    values = header(response)

    assert values[3] == 1
    assert b"\x0a\x3d\x15\x22" in response


def test_ptr_gitlab():
    response = dns.build_response(
        query(
            "34.21.61.10.in-addr.arpa",
            dns.TYPE_PTR,
        )
    )

    assert header(response)[3] == 1
    assert (
        dns.encode_name(
            "gitlab.corp.local"
        )
        in response
    )


def test_srv_ldap():
    response = dns.build_response(
        query(
            "_ldap._tcp.corp.local",
            dns.TYPE_SRV,
        )
    )

    assert header(response)[3] == 1
    assert (
        dns.encode_name(
            "dc01.corp.local"
        )
        in response
    )


def test_unknown_is_nxdomain():
    response = dns.build_response(
        query(
            "nosuch.corp.local",
            dns.TYPE_A,
        )
    )

    flags = header(response)[1]

    assert flags & 0xF == 3
    assert header(response)[3] == 0


def test_known_aaaa_is_noerror_empty():
    response = dns.build_response(
        query(
            "gitlab.corp.local",
            28,
        )
    )

    flags = header(response)[1]

    assert flags & 0xF == 0
    assert header(response)[3] == 0
