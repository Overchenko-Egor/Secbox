import json
import socket
import threading

from pathlib import Path

from secbox.web import (
    blackhole_actions,
)


def serve_once(
    path: Path,
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
            b'{"ok":true,"result":{"consistent":true}}\n'
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
        blackhole_actions,
        "ACTION_SOCKET",
        path,
    )

    observed = []

    thread = serve_once(
        path,
        observed,
    )

    result = (
        blackhole_actions
        .get_blackhole_runtime_via_helper()
    )

    thread.join(2)

    assert result[
        "consistent"
    ] is True

    assert observed == [
        {
            "action":
                "get-blackhole-runtime"
        }
    ]
