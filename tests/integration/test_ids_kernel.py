"""Opt-in IDS -> kernel checks, ONLY inside a separate network namespace.

Run via systemd-run with PrivateNetwork=yes; see docs/development.md.
Synthetic EVE input tests the SecBox pipeline, not Suricata's detection engine.
"""

import json
import os
import socket
import subprocess
import time
from pathlib import Path

import pytest

from secbox.core.models import SecBoxConfig
from secbox.modules.blacklist.service import add_blacklist_entry, list_blacklist_entries, reconcile_blacklist
from secbox.modules.blacklist.store import BlacklistStore
from secbox.modules.firewall.models import FirewallConfig
from secbox.modules.firewall.renderer import render_nftables_config
from secbox.modules.ids.policy import PolicyAction
from secbox.modules.ids.response import IdsResponseHandler
from secbox.modules.ids.worker import StreamingIdsWorker
from secbox.modules.network.state import NetworkAddress, NetworkInterfaceState

pytestmark = pytest.mark.skipif(os.environ.get("SECBOX_KERNEL_TEST") != "1", reason="opt-in isolated kernel test")
SOURCE = "203.0.113.77"
DESTINATION = "198.51.100.1"


def run(*command: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, capture_output=True, text=True, timeout=10)


def test_ids_blackhole_drops_burst_and_expires(tmp_path: Path) -> None:
    # Refuse even when explicitly opted in if the caller forgot network isolation.
    assert os.geteuid() == 0, "This kernel test requires root in an isolated network namespace"
    assert os.stat("/proc/self/ns/net").st_ino != os.stat("/proc/1/ns/net").st_ino, "REFUSING host network namespace"
    run("ip", "link", "set", "lo", "up")
    run("ip", "address", "add", SOURCE + "/32", "dev", "lo")
    run("ip", "address", "add", DESTINATION + "/32", "dev", "lo")
    rules = render_nftables_config(FirewallConfig(
        wan_interface="wan0", lan_interface="lan0", management_interface="mgmt0",
    ), tmp_path / "firewall.nft")
    run("/usr/sbin/nft", "-c", "-f", str(rules))
    run("/usr/sbin/nft", "-f", str(rules))

    config = SecBoxConfig.model_validate({
        "network": {"interfaces": [{"name": "wan0", "role": "wan", "ipv4_method": "dhcp"}, {"name": "lan0", "role": "lan", "ipv4_method": "static", "ipv4_address": "192.0.2.1/24"}]},
    })
    runtime = [
        NetworkInterfaceState(
            name="wan0", mtu=1500, operstate="UP", flags=["UP"], is_loopback=False,
            addresses=[NetworkAddress(family="inet", address=DESTINATION, prefixlen=32)],
        ),
        NetworkInterfaceState(
            name="lan0", mtu=1500, operstate="UP", flags=["UP"], is_loopback=False,
            addresses=[NetworkAddress(family="inet", address="192.0.2.1", prefixlen=24)],
        ),
    ]
    worker = StreamingIdsWorker(config, runtime)
    for index in range(5):
        worker.ingest_line(json.dumps({
            "timestamp": f"2026-09-06T10:00:0{index}+00:00", "event_type": "alert",
            "in_iface": "wan0", "src_ip": SOURCE, "dest_ip": DESTINATION,
            "proto": "UDP", "src_port": 40000, "dest_port": 44444,
            "alert": {"action": "allowed", "gid": 1, "signature_id": 9000001, "rev": 1,
                      "signature": "SecBox isolated test", "category": "Attempted Admin", "severity": 1},
        }), now=float(index))
    decisions = worker.close()
    assert len(decisions) == 1
    assert decisions[0].action == PolicyAction.BLOCK_CANDIDATE
    store = BlacklistStore(tmp_path / "blacklist.json")
    def add(
        *,
        address: str,
        signature_id: int,
        severity: int,
        count: int,
    ) -> None:
        """Adapt IDS response metadata to the blacklist service."""
        add_blacklist_entry(
            address=address,
            timeout="2s",
            reason=(
                f"ids:sid={signature_id};"
                f"severity={severity};"
                f"count={count}"
            ),
            source="ids",
            store=store,
            protected_networks=[DESTINATION + "/32"],
        )
    disabled = IdsResponseHandler(
        automatic_blackhole_enabled=False, automatic_blackhole_timeout="2s",
        protected_networks=(), blacklist_add=add,
    )
    assert not disabled.handle(decisions[0]).blocked
    assert SOURCE not in list_blacklist_entries()
    enabled = IdsResponseHandler(
        automatic_blackhole_enabled=True, automatic_blackhole_timeout="2s",
        protected_networks=(DESTINATION + "/32",), blacklist_add=add,
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, socket.socket(
        socket.AF_INET, socket.SOCK_DGRAM,
    ) as sender:
        receiver.bind((DESTINATION, 44444))
        receiver.settimeout(0.4)
        sender.bind((SOURCE, 40000))
        sender.sendto(b"baseline", (DESTINATION, 44444))
        assert receiver.recv(128) == b"baseline"

        assert enabled.handle(decisions[0]).blocked
        assert SOURCE in list_blacklist_entries()
        assert store.load()[0].source == "ids"
        for _ in range(100):
            sender.sendto(b"blocked", (DESTINATION, 44444))
        with pytest.raises(TimeoutError):
            receiver.recv(128)

        # Renew an existing kernel element and verify there is just one persistent entry.
        enabled.handle(decisions[0])
        assert len(store.load()) == 1
        time.sleep(2.2)
        assert SOURCE not in list_blacklist_entries()
        sender.sendto(b"expired", (DESTINATION, 44444))
        assert receiver.recv(128) == b"expired"
        assert reconcile_blacklist(store=store) == (0, 1)
        assert store.load() == []
