from secbox.modules.deception.capture import (
    build_capture_argv,
)


def test_capture_argv_is_fixed(
    tmp_path,
):
    case_id = (
        "case-20261017T120000Z-"
        "1234abcd"
    )

    case = (
        tmp_path
        / case_id
    )

    case.mkdir()

    (
        case
        / "capture"
    ).mkdir()

    (
        case
        / "source_ip"
    ).write_text(
        "203.0.113.10\n"
    )

    argv = build_capture_argv(
        case_id=case_id,
        case_root=tmp_path,
    )

    assert argv[0] == (
        "/usr/bin/tcpdump"
    )

    assert argv[-2:] == [
        "host",
        "203.0.113.10",
    ]

    assert "-p" in argv
    assert "-C" in argv
    assert "-W" in argv
