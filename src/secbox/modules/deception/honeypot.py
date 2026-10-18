"""SecBox Deception honeypot runtime."""

from __future__ import annotations

import asyncio
import ssl
import json

from datetime import UTC, datetime
from pathlib import Path

from secbox.modules.deception.smb import (
    handle_client as handle_smb_client,
)

from secbox.modules.deception.ldap import (
    LDAP_ADDRESS,
    LDAP_PORT,
    LDAPS_PORT,
    handle_client as handle_ldap_client,
)

from secbox.modules.deception.dns import (
    DNS_ADDRESS,
    DNS_PORT,
    DnsDatagramProtocol,
    handle_tcp as handle_dns_tcp,
)

from secbox.modules.deception.topology import (
    ENTERPRISE_HOSTS,
    get_host,
)


LISTEN_ADDRESS = "10.250.0.2"

EVENT_PATH = Path(
    "/var/lib/secbox/deception/honeypot/events.jsonl"
)

CASE_ROOT = Path(
    "/var/lib/secbox/deception/cases"
)


def utc_now() -> str:
    return datetime.now(
        UTC
    ).isoformat()


def find_case_id(
    source_ip: str,
) -> str | None:
    try:
        if not CASE_ROOT.exists():
            return None
    except OSError:
        return None

    try:
        candidates = sorted(
            (
                path
                for path in CASE_ROOT.iterdir()
                if path.is_dir()
            ),
            reverse=True,
        )
    except OSError:
        return None

    for case_path in candidates:
        source_path = (
            case_path
            / "source_ip"
        )

        try:
            value = (
                source_path
                .read_text(
                    encoding="utf-8"
                )
                .strip()
            )
        except OSError:
            continue

        if value == source_ip:
            return case_path.name

    return None


def log_event(
    *,
    protocol: str,
    source_ip: str,
    source_port: int | None,
    event: str,
    details: dict[str, object] | None = None,
) -> None:
    payload = {
        "timestamp":
            utc_now(),
        "protocol":
            protocol,
        "event":
            event,
        "source_ip":
            source_ip,
        "source_port":
            source_port,
        "case_id":
            find_case_id(
                source_ip
            ),
        "details":
            details or {},
    }

    EVENT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with EVENT_PATH.open(
        "a",
        encoding="utf-8",
    ) as file:
        file.write(
            json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )

        file.write(
            "\n"
        )


def connection_target(
    writer: asyncio.StreamWriter,
):
    local = writer.get_extra_info(
        "sockname"
    )

    if (
        isinstance(local, tuple)
        and len(local) >= 1
    ):
        address = str(local[0])
    else:
        address = LISTEN_ADDRESS

    return (
        address,
        get_host(address),
    )


def http_profile(
    address: str,
):
    host = get_host(address)

    if host is None:
        return (
            "503 Service Unavailable",
            "nginx/1.18.0",
            (
                "<html><body>"
                "<h1>System Administration</h1>"
                "<p>Service temporarily unavailable.</p>"
                "</body></html>"
            ),
        )

    if host.role == "git-service":
        return (
            "200 OK",
            "nginx",
            (
                "<html><head>"
                "<title>Sign in · GitLab</title>"
                "</head><body>"
                "<h1>GitLab</h1>"
                "<p>Sign in to continue</p>"
                "</body></html>"
            ),
        )

    if host.role == "intranet":
        return (
            "200 OK",
            "nginx/1.22.1",
            (
                "<html><head>"
                "<title>Corporate Intranet</title>"
                "</head><body>"
                "<h1>Corporate Intranet</h1>"
                "<p>Employee portal</p>"
                "</body></html>"
            ),
        )

    if host.role == "monitoring":
        return (
            "200 OK",
            "nginx/1.20.2",
            (
                "<html><head>"
                "<title>Zabbix</title>"
                "</head><body>"
                "<h1>Zabbix</h1>"
                "<p>Monitoring console</p>"
                "</body></html>"
            ),
        )

    return (
        "404 Not Found",
        "nginx",
        (
            "<html><body>"
            "<h1>404 Not Found</h1>"
            "</body></html>"
        ),
    )


async def read_limited(
    reader: asyncio.StreamReader,
    limit: int = 4096,
    timeout: float = 10.0,
) -> bytes:
    try:
        return await asyncio.wait_for(
            reader.read(
                limit
            ),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return b""


async def handle_http(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    peer = writer.get_extra_info(
        "peername"
    )

    if (
        isinstance(peer, tuple)
        and len(peer) >= 2
    ):
        source_ip = str(
            peer[0]
        )

        source_port = int(
            peer[1]
        )
    else:
        source_ip = "unknown"
        source_port = None

    target_ip, target_host = (
        connection_target(
            writer
        )
    )

    data = await read_limited(
        reader
    )

    text = data.decode(
        "iso-8859-1",
        errors="replace",
    )

    lines = text.splitlines()

    request_line = (
        lines[0][:512]
        if lines
        else ""
    )

    headers = {}

    for line in lines[1:]:
        if ":" not in line:
            continue

        key, value = line.split(
            ":",
            1,
        )

        key = (
            key.strip()
            .lower()
        )

        if key in {
            "host",
            "user-agent",
            "accept",
        }:
            headers[key] = (
                value.strip()[:512]
            )

    log_event(
        protocol="http",
        source_ip=source_ip,
        source_port=source_port,
        event="request",
        details={
            "request_line":
                request_line,
            "headers":
                headers,
            "target_ip":
                target_ip,
            "target_hostname":
                (
                    target_host.hostname
                    if target_host
                    else None
                ),
            "target_role":
                (
                    target_host.role
                    if target_host
                    else None
                ),
        },
    )

    status, server, body_text = (
        http_profile(
            target_ip
        )
    )

    body = body_text.encode(
        "utf-8"
    )

    response = (
        f"HTTP/1.1 {status}\r\n"
        f"Server: {server}\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Connection: close\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    ).encode(
        "ascii"
    ) + body

    writer.write(
        response
    )

    await writer.drain()

    writer.close()

    await writer.wait_closed()


async def handle_ssh(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    peer = writer.get_extra_info("peername")

    if isinstance(peer, tuple) and len(peer) >= 2:
        source_ip = str(peer[0])
        source_port = int(peer[1])
    else:
        source_ip = "unknown"
        source_port = None

    target_ip, target_host = (
        connection_target(
            writer
        )
    )

    log_event(
        protocol="ssh",
        source_ip=source_ip,
        source_port=source_port,
        event="connect",
        details={
            "target_ip":
                target_ip,
            "target_hostname":
                (
                    target_host.hostname
                    if target_host
                    else None
                ),
            "target_role":
                (
                    target_host.role
                    if target_host
                    else None
                ),
        },
    )

    if (
        target_host is not None
        and target_host.role
        == "git-service"
    ):
        ssh_banner = (
            b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14\r\n"
        )
    elif (
        target_host is not None
        and target_host.role
        in {
            "database",
            "storage",
            "backup",
        }
    ):
        ssh_banner = (
            b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13\r\n"
        )
    else:
        ssh_banner = (
            b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n"
        )

    writer.write(
        ssh_banner
    )
    await writer.drain()

    data = await read_limited(
        reader,
        limit=512,
        timeout=5.0,
    )

    banner = (
        data.split(b"\n", 1)[0]
        .decode(
            "utf-8",
            errors="replace",
        )
        .strip()[:256]
    )

    log_event(
        protocol="ssh",
        source_ip=source_ip,
        source_port=source_port,
        event="client_banner",
        details={
            "banner": banner,
        },
    )

    writer.close()
    await writer.wait_closed()


async def read_line(
    reader: asyncio.StreamReader,
) -> str:
    try:
        data = await asyncio.wait_for(
            reader.readline(),
            timeout=10.0,
        )
    except asyncio.TimeoutError:
        return ""

    return (
        data.decode(
            "utf-8",
            errors="replace",
        )
        .strip()[:256]
    )


async def handle_telnet(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    import hashlib

    peer = writer.get_extra_info("peername")

    if isinstance(peer, tuple) and len(peer) >= 2:
        source_ip = str(peer[0])
        source_port = int(peer[1])
    else:
        source_ip = "unknown"
        source_port = None

    log_event(
        protocol="telnet",
        source_ip=source_ip,
        source_port=source_port,
        event="connect",
    )

    writer.write(
        b"Ubuntu 22.04 LTS\r\n\r\nlogin: "
    )
    await writer.drain()

    username = await read_line(
        reader
    )

    writer.write(
        b"Password: "
    )
    await writer.drain()

    password = await read_line(
        reader
    )

    digest = hashlib.sha256(
        password.encode(
            "utf-8",
            errors="replace",
        )
    ).hexdigest()

    log_event(
        protocol="telnet",
        source_ip=source_ip,
        source_port=source_port,
        event="authentication",
        details={
            "username":
                username,
            "password_sha256":
                digest,
            "password_length":
                len(password),
        },
    )

    writer.write(
        b"\r\nLogin incorrect\r\n"
    )
    await writer.drain()

    writer.close()
    await writer.wait_closed()



def shadow_http_profile(
    service: str,
    path: str,
):
    if service == "grafana":
        if path.startswith("/api/health"):
            return (
                "200 OK",
                "application/json",
                "nginx/1.22.1",
                b'{"commit":"8f4c5e7","database":"ok","version":"10.4.2"}',
            )

        return (
            "200 OK",
            "text/html; charset=utf-8",
            "nginx/1.22.1",
            (
                b"<html><head><title>Grafana</title></head>"
                b"<body><h1>Grafana</h1>"
                b"<p>Sign in to Grafana</p></body></html>"
            ),
        )

    if service == "prometheus":
        if path.startswith("/-/healthy"):
            return (
                "200 OK",
                "text/plain; charset=utf-8",
                "Prometheus",
                b"Prometheus Server is Healthy.\n",
            )

        if path.startswith("/api/v1/status/buildinfo"):
            return (
                "200 OK",
                "application/json",
                "Prometheus",
                (
                    b'{"status":"success","data":{'
                    b'"version":"2.53.1",'
                    b'"revision":"shadow",'
                    b'"branch":"HEAD"}}'
                ),
            )

        return (
            "302 Found",
            "text/plain; charset=utf-8",
            "Prometheus",
            b"Found\n",
        )

    if service == "elasticsearch":
        if path.startswith("/_cluster/health"):
            return (
                "200 OK",
                "application/json",
                "elasticsearch",
                (
                    b'{"cluster_name":"corp-logs",'
                    b'"status":"yellow",'
                    b'"number_of_nodes":3,'
                    b'"active_primary_shards":12}'
                ),
            )

        return (
            "200 OK",
            "application/json",
            "elasticsearch",
            (
                b'{"name":"logs01",'
                b'"cluster_name":"corp-logs",'
                b'"version":{"number":"8.14.3"},'
                b'"tagline":"You Know, for Search"}'
            ),
        )

    return (
        "404 Not Found",
        "text/plain",
        "nginx",
        b"Not Found\n",
    )


async def handle_shadow_http(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    service: str,
) -> None:
    peer = writer.get_extra_info("peername")

    if isinstance(peer, tuple) and len(peer) >= 2:
        source_ip = str(peer[0])
        source_port = int(peer[1])
    else:
        source_ip = "unknown"
        source_port = None

    target_ip, target_host = connection_target(
        writer
    )

    data = await read_limited(
        reader,
        limit=4096,
        timeout=5.0,
    )

    text = data.decode(
        "iso-8859-1",
        errors="replace",
    )

    lines = text.splitlines()

    request_line = (
        lines[0][:512]
        if lines
        else ""
    )

    fields = request_line.split()

    path = (
        fields[1][:512]
        if len(fields) >= 2
        else "/"
    )

    log_event(
        protocol=service,
        source_ip=source_ip,
        source_port=source_port,
        event="request",
        details={
            "request_line": request_line,
            "target_ip": target_ip,
            "target_hostname": (
                target_host.hostname
                if target_host
                else None
            ),
            "target_role": (
                target_host.role
                if target_host
                else None
            ),
        },
    )

    (
        status,
        content_type,
        server,
        body,
    ) = shadow_http_profile(
        service,
        path,
    )

    response = (
        f"HTTP/1.1 {status}\r\n"
        f"Server: {server}\r\n"
        f"Content-Type: {content_type}\r\n"
        "Connection: close\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    ).encode("ascii") + body

    writer.write(response)
    await writer.drain()

    writer.close()
    await writer.wait_closed()


async def handle_grafana(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    await handle_shadow_http(
        reader,
        writer,
        "grafana",
    )


async def handle_prometheus(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    await handle_shadow_http(
        reader,
        writer,
        "prometheus",
    )


async def handle_elasticsearch(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    await handle_shadow_http(
        reader,
        writer,
        "elasticsearch",
    )


async def handle_postgres(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    peer = writer.get_extra_info("peername")

    if isinstance(peer, tuple) and len(peer) >= 2:
        source_ip = str(peer[0])
        source_port = int(peer[1])
    else:
        source_ip = "unknown"
        source_port = None

    target_ip, target_host = connection_target(
        writer
    )

    data = await read_limited(
        reader,
        limit=2048,
        timeout=5.0,
    )

    protocol = None

    if len(data) >= 8:
        protocol = int.from_bytes(
            data[4:8],
            "big",
        )

    log_event(
        protocol="postgresql",
        source_ip=source_ip,
        source_port=source_port,
        event="startup",
        details={
            "target_ip": target_ip,
            "target_hostname": (
                target_host.hostname
                if target_host
                else None
            ),
            "target_role": (
                target_host.role
                if target_host
                else None
            ),
            "startup_code": protocol,
            "received_bytes": len(data),
        },
    )

    if protocol == 80877103:
        writer.write(b"N")
        await writer.drain()

        data = await read_limited(
            reader,
            limit=2048,
            timeout=5.0,
        )

    payload = (
        b"S"
        b"FATAL\x00"
        b"C"
        b"28P01\x00"
        b"M"
        b"password authentication failed for user \"admin\"\x00"
        b"\x00"
    )

    packet = (
        b"E"
        + (len(payload) + 4).to_bytes(
            4,
            "big",
        )
        + payload
    )

    writer.write(packet)
    await writer.drain()

    writer.close()
    await writer.wait_closed()



async def handle_dns(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    await handle_dns_tcp(
        reader,
        writer,
        event_callback=log_event,
    )




TLS_DIRECTORY = Path(
    "/var/lib/secbox/deception/tls"
)


def https_bindings():
    return (
        (
            "10.61.21.34",
            "gitlab.corp.local",
        ),
        (
            "10.61.32.18",
            "intranet.corp.local",
        ),
        (
            "10.63.7.11",
            "zabbix.corp.local",
        ),
    )


def tls_context(
    hostname: str,
) -> ssl.SSLContext:
    context = ssl.SSLContext(
        ssl.PROTOCOL_TLS_SERVER
    )

    context.minimum_version = (
        ssl.TLSVersion.TLSv1_2
    )

    context.load_cert_chain(
        certfile=str(
            TLS_DIRECTORY
            / f"{hostname}.crt"
        ),
        keyfile=str(
            TLS_DIRECTORY
            / f"{hostname}.key"
        ),
    )

    return context


async def handle_https(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    await handle_http(
        reader,
        writer,
    )




async def handle_ldap(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    await handle_ldap_client(
        reader,
        writer,
        event_callback=log_event,
    )




async def handle_smb(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    await handle_smb_client(
        reader,
        writer,
        event_callback=log_event,
    )



def listener_plan():
    listeners = [
        (
            "ssh",
            LISTEN_ADDRESS,
            22,
            handle_ssh,
        ),
        (
            "telnet",
            LISTEN_ADDRESS,
            23,
            handle_telnet,
        ),
        (
            "http",
            LISTEN_ADDRESS,
            80,
            handle_http,
        ),
    ]

    implemented = {
        22: (
            "ssh",
            handle_ssh,
        ),
        23: (
            "telnet",
            handle_telnet,
        ),
        53: (
            "dns",
            handle_dns,
        ),
        80: (
            "http",
            handle_http,
        ),
        139: (
            "smb",
            handle_smb,
        ),
        389: (
            "ldap",
            handle_ldap,
        ),
        445: (
            "smb",
            handle_smb,
        ),
        3000: (
            "grafana",
            handle_grafana,
        ),
        5432: (
            "postgresql",
            handle_postgres,
        ),
        9090: (
            "prometheus",
            handle_prometheus,
        ),
        9200: (
            "elasticsearch",
            handle_elasticsearch,
        ),
    }

    for host in ENTERPRISE_HOSTS:
        for port in host.services:
            service = implemented.get(
                port
            )

            if service is None:
                continue

            protocol, handler = service

            listeners.append(
                (
                    protocol,
                    host.address,
                    port,
                    handler,
                )
            )

    return tuple(
        listeners
    )


async def serve() -> None:
    servers = []

    loop = asyncio.get_running_loop()

    dns_udp_transport, _ = (
        await loop.create_datagram_endpoint(
            lambda:
                DnsDatagramProtocol(
                    log_event
                ),
            local_addr=(
                DNS_ADDRESS,
                DNS_PORT,
            ),
        )
    )

    ldaps_server = await asyncio.start_server(
        handle_ldap,
        host=LDAP_ADDRESS,
        port=LDAPS_PORT,
        ssl=tls_context(
            "dc01.corp.local"
        ),
    )

    servers.append(
        ldaps_server
    )

    log_event(
        protocol="runtime",
        source_ip="local",
        source_port=None,
        event="listener_started",
        details={
            "protocol": "ldaps",
            "address": LDAP_ADDRESS,
            "hostname": "dc01.corp.local",
            "port": LDAPS_PORT,
        },
    )

    for (
        address,
        hostname,
    ) in https_bindings():
        server = await asyncio.start_server(
            handle_https,
            host=address,
            port=443,
            ssl=tls_context(
                hostname
            ),
        )

        servers.append(
            server
        )

        log_event(
            protocol="runtime",
            source_ip="local",
            source_port=None,
            event="listener_started",
            details={
                "protocol": "https",
                "address": address,
                "hostname": hostname,
                "port": 443,
            },
        )

    for (
        protocol,
        address,
        port,
        handler,
    ) in listener_plan():
        server = await asyncio.start_server(
            handler,
            host=address,
            port=port,
        )

        servers.append(
            server
        )

        log_event(
            protocol="runtime",
            source_ip="local",
            source_port=None,
            event="listener_started",
            details={
                "protocol":
                    protocol,
                "address":
                    address,
                "port":
                    port,
            },
        )

    try:
        await asyncio.gather(
            *(
                server.serve_forever()
                for server
                in servers
            )
        )
    finally:
        dns_udp_transport.close()


def main() -> None:
    asyncio.run(
        serve()
    )


if __name__ == "__main__":
    main()
