from secbox.modules.deception import ldap


def message(
    message_id: int,
    operation: bytes,
) -> bytes:
    return ldap.ldap_message(
        message_id,
        operation,
    )


def test_bind_success():
    bind = ldap.tlv(
        0x60,
        ldap.integer(3)
        + ldap.octet("")
        + ldap.tlv(
            0x80,
            b"",
        ),
    )

    responses = ldap.build_responses(
        message(
            1,
            bind,
        )
    )

    assert len(responses) == 1

    message_id, tag, body = (
        ldap.parse_message(
            responses[0]
        )
    )

    assert message_id == 1
    assert tag == 0x61


def test_root_dse_search():
    search = ldap.tlv(
        0x63,
        ldap.octet("")
        + b"\x0a\x01\x00"
        + b"\x0a\x01\x00"
        + b"\x02\x01\x00"
        + b"\x02\x01\x00"
        + b"\x01\x01\x00"
        + b"\x87\x0bobjectClass"
        + b"\x30\x00",
    )

    responses = ldap.build_responses(
        message(
            2,
            search,
        )
    )

    assert len(responses) == 2
    assert b"defaultNamingContext" in responses[0]
    assert b"DC=corp,DC=local" in responses[0]

    _, tag, _ = ldap.parse_message(
        responses[1]
    )

    assert tag == 0x65


def test_domain_search():
    search = ldap.tlv(
        0x63,
        ldap.octet(
            "DC=corp,DC=local"
        )
        + b"\x0a\x01\x00"
        + b"\x0a\x01\x00"
        + b"\x02\x01\x00"
        + b"\x02\x01\x00"
        + b"\x01\x01\x00"
        + b"\x87\x0bobjectClass"
        + b"\x30\x00",
    )

    responses = ldap.build_responses(
        message(
            3,
            search,
        )
    )

    assert b"distinguishedName" in responses[0]
    assert b"corp" in responses[0]
