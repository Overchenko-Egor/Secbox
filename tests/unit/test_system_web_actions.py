import json
import socket
import threading

from pathlib import Path

from secbox.web import (
    system_actions,
)


def serve_once(
    path: Path,
    response: dict,
    observed: list,
):
    ready = threading.Event()

    def worker():
        server = socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        )

        server.bind(
            str(path)
        )

        server.listen(1)

        ready.set()

        connection, _ = (
            server.accept()
        )

        raw = b""

        while True:
            chunk = connection.recv(
                4096
            )

            if not chunk:
                break

            raw += chunk

        observed.append(
            json.loads(
                raw.decode()
            )
        )

        connection.sendall(
            (
                json.dumps(
                    response
                )
                + "\n"
            ).encode()
        )

        connection.close()
        server.close()

    thread = threading.Thread(
        target=worker,
        daemon=True,
    )

    thread.start()

    assert ready.wait(2)

    return thread


def test_runtime_client(
    tmp_path,
    monkeypatch,
):
    path = (
        tmp_path
        / "action.sock"
    )

    monkeypatch.setattr(
        system_actions,
        "ACTION_SOCKET",
        path,
    )

    observed = []

    thread = serve_once(
        path,
        {
            "ok": True,
            "result": {
                "hostname": "secbox",
            },
        },
        observed,
    )

    result = (
        system_actions
        .get_system_runtime_via_helper()
    )

    thread.join(2)

    assert (
        result["hostname"]
        == "secbox"
    )

    assert observed == [
        {
            "action":
                "get-system-runtime"
        }
    ]


def test_power_client(
    tmp_path,
    monkeypatch,
):
    path = (
        tmp_path
        / "action.sock"
    )

    monkeypatch.setattr(
        system_actions,
        "ACTION_SOCKET",
        path,
    )

    observed = []

    thread = serve_once(
        path,
        {
            "ok": True,
            "result": {
                "accepted": True,
                "operation": "reboot",
            },
        },
        observed,
    )

    result = (
        system_actions
        .system_power_via_helper(
            operation="reboot",
            confirmation="REBOOT",
        )
    )

    thread.join(2)

    assert (
        result["accepted"]
        is True
    )

    assert observed == [
        {
            "action":
                "system-power",
            "operation":
                "reboot",
            "confirmation":
                "REBOOT",
        }
    ]
