"""Tests for IDS privileged action client."""

import json
import socket
import threading

from pathlib import Path

import pytest

from secbox.modules.ids import action_client


def serve_once(
    socket_path: Path,
    response: dict[str, object],
    observed: list[
        dict[str, object]
    ],
) -> threading.Thread:
    ready = threading.Event()

    def run() -> None:
        server = socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        )

        server.bind(
            str(socket_path)
        )

        server.listen(1)

        ready.set()

        connection, _ = server.accept()

        data = b""

        while True:
            chunk = connection.recv(
                4096
            )

            if not chunk:
                break

            data += chunk

        observed.append(
            json.loads(
                data.decode(
                    "utf-8"
                )
            )
        )

        connection.sendall(
            json.dumps(
                response
            ).encode(
                "utf-8"
            )
            + b"\n"
        )

        connection.close()
        server.close()

    thread = threading.Thread(
        target=run,
        daemon=True,
    )

    thread.start()

    assert ready.wait(2)

    return thread


def test_ids_blackhole_client_sends_only_minimal_metadata(
    tmp_path: Path,
    monkeypatch,
) -> None:
    socket_path = (
        tmp_path / "action.sock"
    )

    monkeypatch.setattr(
        action_client,
        "ACTION_SOCKET",
        socket_path,
    )

    observed = []

    thread = serve_once(
        socket_path,
        {
            "ok": True,
            "result": {
                "address":
                    "203.0.113.50",
            },
        },
        observed,
    )

    action_client.add_ids_blackhole_via_helper(
        address="203.0.113.50",
        signature_id=100001,
        severity=1,
        count=5,
    )

    thread.join(2)

    assert observed == [
        {
            "action":
                "ids-blackhole-add",
            "address":
                "203.0.113.50",
            "signature_id":
                100001,
            "severity":
                1,
            "count":
                5,
        }
    ]


def test_ids_blackhole_client_surfaces_helper_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    socket_path = (
        tmp_path / "action.sock"
    )

    monkeypatch.setattr(
        action_client,
        "ACTION_SOCKET",
        socket_path,
    )

    observed = []

    thread = serve_once(
        socket_path,
        {
            "ok": False,
            "error":
                "ids_blackhole_failed",
            "detail":
                "simulated rejection",
        },
        observed,
    )

    with pytest.raises(
        action_client.IdsActionClientError,
        match="simulated rejection",
    ):
        (
            action_client
            .add_ids_blackhole_via_helper(
                address=
                    "203.0.113.50",
                signature_id=100001,
                severity=1,
                count=5,
            )
        )

    thread.join(2)


def test_ids_runtime_config_client_uses_restricted_action(
    tmp_path: Path,
    monkeypatch,
) -> None:
    socket_path = (
        tmp_path / "runtime-config.sock"
    )

    monkeypatch.setattr(
        action_client,
        "ACTION_SOCKET",
        socket_path,
    )

    observed = []

    thread = serve_once(
        socket_path,
        {
            "ok": True,
            "result": {
                "config": {
                    "network": {
                        "interfaces": []
                    },
                    "firewall": None,
                    "ids": {
                        "enabled": True
                    },
                }
            },
        },
        observed,
    )

    config = (
        action_client
        .get_ids_runtime_config_via_helper()
    )

    thread.join(2)

    assert observed == [
        {
            "action":
                "get-ids-runtime-config"
        }
    ]

    assert config.ids.enabled is True


def test_ids_deception_client_sends_minimal_metadata(
    monkeypatch,
):
    captured = {}

    def fake_exchange(request):
        captured.update(request)
        return {
            "ok": True,
            "result": {
                "status": "quarantined",
                "case_id": "case-test",
            },
        }

    monkeypatch.setattr(
        action_client,
        "_exchange",
        fake_exchange,
    )

    result = (
        action_client
        .add_ids_deception_via_helper(
            address="198.18.0.2",
            signature_id=100001,
            severity=1,
            count=5,
        )
    )

    assert captured == {
        "action": "ids-deception-start",
        "address": "198.18.0.2",
        "signature_id": 100001,
        "severity": 1,
        "count": 5,
    }

    assert result["status"] == "quarantined"
