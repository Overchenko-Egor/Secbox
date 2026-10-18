"""Tests for Deception honeypot runtime."""

import asyncio
import hashlib

from secbox.modules.deception import honeypot


def test_find_case_id_missing_root(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        honeypot,
        "CASE_ROOT",
        tmp_path / "missing",
    )

    assert (
        honeypot.find_case_id(
            "203.0.113.10"
        )
        is None
    )


def test_log_event_does_not_store_password(
    tmp_path,
    monkeypatch,
):
    event_path = (
        tmp_path / "events.jsonl"
    )

    monkeypatch.setattr(
        honeypot,
        "EVENT_PATH",
        event_path,
    )

    password = "secret-password"

    honeypot.log_event(
        protocol="telnet",
        source_ip="203.0.113.10",
        source_port=12345,
        event="authentication",
        details={
            "username": "admin",
            "password_sha256":
                hashlib.sha256(
                    password.encode()
                ).hexdigest(),
            "password_length":
                len(password),
        },
    )

    raw = event_path.read_text()

    assert password not in raw
    assert "password_sha256" in raw
    assert "password_length" in raw


def test_http_handler_returns_503(
    monkeypatch,
):
    events = []

    monkeypatch.setattr(
        honeypot,
        "log_event",
        lambda **event:
            events.append(event),
    )

    async def run():
        server = await asyncio.start_server(
            honeypot.handle_http,
            "127.0.0.1",
            0,
        )

        port = (
            server.sockets[0]
            .getsockname()[1]
        )

        reader, writer = (
            await asyncio.open_connection(
                "127.0.0.1",
                port,
            )
        )

        writer.write(
            b"GET / HTTP/1.1\r\n"
            b"Host: test\r\n"
            b"Authorization: secret\r\n"
            b"\r\n"
        )

        await writer.drain()

        response = await reader.read()

        writer.close()
        await writer.wait_closed()

        server.close()
        await server.wait_closed()

        return response

    response = asyncio.run(
        run()
    )

    assert (
        b"503 Service Unavailable"
        in response
    )

    assert events
    details = events[0]["details"]

    assert (
        "authorization"
        not in details["headers"]
    )


def test_listener_configuration():
    assert honeypot.LISTEN_ADDRESS == (
        "10.250.0.2"
    )


def test_listener_plan_keeps_base_honeypot():
    listeners = {
        (
            protocol,
            address,
            port,
        )
        for (
            protocol,
            address,
            port,
            handler,
        )
        in honeypot.listener_plan()
    }

    assert (
        "ssh",
        "10.250.0.2",
        22,
    ) in listeners

    assert (
        "telnet",
        "10.250.0.2",
        23,
    ) in listeners

    assert (
        "http",
        "10.250.0.2",
        80,
    ) in listeners


def test_listener_plan_contains_fake_gitlab():
    listeners = {
        (
            protocol,
            address,
            port,
        )
        for (
            protocol,
            address,
            port,
            handler,
        )
        in honeypot.listener_plan()
    }

    assert (
        "ssh",
        "10.61.21.34",
        22,
    ) in listeners

    assert (
        "http",
        "10.61.21.34",
        80,
    ) in listeners


def test_listener_plan_contains_fake_database_ssh():
    listeners = {
        (
            protocol,
            address,
            port,
        )
        for (
            protocol,
            address,
            port,
            handler,
        )
        in honeypot.listener_plan()
    }

    assert (
        "ssh",
        "10.62.18.23",
        22,
    ) in listeners


def test_still_unimplemented_services_not_exposed():
    listeners = {
        (
            address,
            port,
        )
        for (
            protocol,
            address,
            port,
            handler,
        )
        in honeypot.listener_plan()
    }

    assert (
        "10.61.21.34",
        443,
    ) not in listeners

    assert (
        "10.63.7.11",
        10051,
    ) not in listeners


def test_http_profile_base_listener():
    status, server, body = (
        honeypot.http_profile(
            "10.250.0.2"
        )
    )

    assert status == (
        "503 Service Unavailable"
    )
    assert "System Administration" in body


def test_http_profile_gitlab():
    status, server, body = (
        honeypot.http_profile(
            "10.61.21.34"
        )
    )

    assert status == "200 OK"
    assert "GitLab" in body


def test_http_profile_intranet():
    status, server, body = (
        honeypot.http_profile(
            "10.61.32.18"
        )
    )

    assert status == "200 OK"
    assert "Corporate Intranet" in body


def test_http_profile_zabbix():
    status, server, body = (
        honeypot.http_profile(
            "10.63.7.11"
        )
    )

    assert status == "200 OK"
    assert "Zabbix" in body


def test_stage4b4_listener_plan():
    listeners = {
        (protocol, address, port)
        for (
            protocol,
            address,
            port,
            handler,
        )
        in honeypot.listener_plan()
    }

    assert (
        "postgresql",
        "10.62.18.23",
        5432,
    ) in listeners

    assert (
        "grafana",
        "10.63.17.51",
        3000,
    ) in listeners

    assert (
        "prometheus",
        "10.63.17.51",
        9090,
    ) in listeners

    assert (
        "elasticsearch",
        "10.63.24.8",
        9200,
    ) in listeners


def test_elasticsearch_profile():
    status, content_type, server, body = (
        honeypot.shadow_http_profile(
            "elasticsearch",
            "/",
        )
    )

    assert status == "200 OK"
    assert b"corp-logs" in body
    assert b"8.14.3" in body


def test_grafana_health_profile():
    status, content_type, server, body = (
        honeypot.shadow_http_profile(
            "grafana",
            "/api/health",
        )
    )

    assert status == "200 OK"
    assert b'"database":"ok"' in body


def test_prometheus_health_profile():
    status, content_type, server, body = (
        honeypot.shadow_http_profile(
            "prometheus",
            "/-/healthy",
        )
    )

    assert status == "200 OK"
    assert b"Healthy" in body


def test_https_bindings():
    bindings = set(
        honeypot.https_bindings()
    )

    assert (
        "10.61.21.34",
        "gitlab.corp.local",
    ) in bindings

    assert (
        "10.61.32.18",
        "intranet.corp.local",
    ) in bindings

    assert (
        "10.63.7.11",
        "zabbix.corp.local",
    ) in bindings

    assert len(bindings) == 3
