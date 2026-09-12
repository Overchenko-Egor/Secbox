from pathlib import Path

import pytest

from secbox.modules.firewall.models import FirewallConfig
from secbox.modules.firewall.renderer import render_nftables_config
from secbox.modules.firewall.validator import (
    FirewallPreflightError,
    validate_firewall_preflight,
)
from secbox.modules.network.models import (
    NetworkConfig,
    NetworkInterfaceConfig,
)


def make_network() -> NetworkConfig:
    return NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens33",
                role="wan",
                ipv4_method="dhcp",
            ),
            NetworkInterfaceConfig(
                name="ens36",
                role="lan",
                ipv4_method="static",
                ipv4_address="192.168.50.1/24",
            ),
            NetworkInterfaceConfig(
                name="ens38",
                role="mgmt",
                ipv4_method="dhcp",
            ),
        ]
    )

def make_firewall() -> FirewallConfig:
    return FirewallConfig(
        wan_interface="ens33",
        lan_interface="ens36",
        management_interface="ens38",
    )

def test_firewall_preflight_passes() -> None:
    validate_firewall_preflight(
        make_firewall(),
        make_network(),
    )


def test_wrong_wan_role_is_rejected() -> None:
    network = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens33",
                role="lan",
                ipv4_method="dhcp",
            ),
            NetworkInterfaceConfig(
                name="ens36",
                role="lan",
                ipv4_method="static",
                ipv4_address="192.168.50.1/24",
            ),
            NetworkInterfaceConfig(
                name="ens38",
                role="mgmt",
                ipv4_method="dhcp",
            ),
        ]
    )

    with pytest.raises(
        FirewallPreflightError,
        match="does not have WAN role",
    ):
        validate_firewall_preflight(
            make_firewall(),
            network,
        )


def test_render_firewall(tmp_path: Path) -> None:
    output = tmp_path / "secbox.nft"

    render_nftables_config(
        make_firewall(),
        output,
    )

    content = output.read_text(
        encoding="utf-8",
    )

    assert "table inet secbox_filter" in content
    assert "ct state established,related accept" in content
    assert (
        'iifname "ens36" oifname "ens33" ct state new accept'
        in content
    )
    assert "policy drop;" in content
    assert (
        'iifname "ens33" udp sport 67 udp dport 68 accept'
        in content
    )
    assert "set blacklist_v4" in content
    assert "type ipv4_addr;" in content
    assert "flags timeout;" in content
    assert "timeout 1h;" in content

    assert "ip saddr @blacklist_v4" in content

    assert 'log prefix "SECBOX_BLACKLIST_INPUT: "' in content
    assert 'log prefix "SECBOX_BLACKLIST_FORWARD: "' in content


def test_render_nat(tmp_path: Path) -> None:
    output = tmp_path / "secbox.nft"

    config = make_firewall()

    render_nftables_config(
        config,
        output,
    )

    content = output.read_text(
        encoding="utf-8",
    )

    assert "table ip secbox_nat" in content
    assert (
        'iifname "ens36" oifname "ens33" masquerade'
        in content
    )

def test_nat_can_be_disabled(tmp_path: Path) -> None:
    output = tmp_path / "secbox.nft"

    config = FirewallConfig(
        wan_interface="ens33",
        lan_interface="ens36",
        management_interface="ens38",
        enable_nat=False,
    )

    render_nftables_config(
        config,
        output,
    )

    content = output.read_text(
        encoding="utf-8",
    )

    assert "table ip secbox_nat" not in content


def test_dynamic_blacklist_can_be_disabled(
    tmp_path: Path,
) -> None:
    output = tmp_path / "secbox.nft"

    config = FirewallConfig(
        wan_interface="ens33",
        lan_interface="ens36",
        management_interface="ens38",
        dynamic_blacklist_enabled=False,
    )

    render_nftables_config(
        config,
        output,
    )

    content = output.read_text(
        encoding="utf-8",
    )

    assert "blacklist_v4" not in content


def test_blacklist_drop_does_not_depend_on_log_rate(tmp_path: Path) -> None:
    """Packets above the logging limit must still drop before established/loopback accepts."""
    output = render_nftables_config(make_firewall(), tmp_path / "firewall.nft")
    content = output.read_text()
    for name in ("input", "forward"):
        chain = content.split(f"chain {name} {{", 1)[1].split("    }", 1)[0]
        drop_rule = "ip saddr @blacklist_v4 counter drop"
        assert drop_rule in chain
        assert chain.index(drop_rule) < chain.index("ct state established,related accept")
        log_rule = next(line for line in chain.splitlines() if "log prefix" in line and "BLACKLIST" in line)
        assert log_rule.index("limit rate") < log_rule.index("log prefix")
        assert "drop" not in log_rule


def test_dns_bypass_is_blocked_before_forward_accept(
    tmp_path: Path,
) -> None:
    output = render_nftables_config(
        make_firewall(),
        tmp_path / "firewall.nft",
        enforce_lan_dns=True,
    )

    content = output.read_text(encoding="utf-8")

    chain = content.split(
        "chain forward {",
        1,
    )[1].split(
        "    }",
        1,
    )[0]

    udp_rule = (
        'iifname "ens36" '
        'udp dport 53 counter drop'
    )

    tcp_rule = (
        'iifname "ens36" '
        'tcp dport 53 counter drop'
    )

    allow_rule = (
        'iifname "ens36" oifname "ens33" '
        'ct state new accept'
    )

    established_rule = (
        "ct state established,related accept"
    )

    assert udp_rule in chain
    assert tcp_rule in chain

    assert chain.index(udp_rule) < chain.index(
        established_rule
    )

    assert chain.index(tcp_rule) < chain.index(
        established_rule
    )

    assert chain.index(udp_rule) < chain.index(
        allow_rule
    )

    assert chain.index(tcp_rule) < chain.index(
        allow_rule
    )


def test_dns_bypass_enforcement_is_disabled_by_default(
    tmp_path: Path,
) -> None:
    output = render_nftables_config(
        make_firewall(),
        tmp_path / "firewall.nft",
    )

    content = output.read_text(encoding="utf-8")

    assert (
        'iifname "ens36" '
        'udp dport 53 counter drop'
        not in content
    )

    assert (
        'iifname "ens36" '
        'tcp dport 53 counter drop'
        not in content
    )

    assert (
        'iifname "ens36" '
        'udp dport 853 counter drop'
        not in content
    )

    assert (
        'iifname "ens36" '
        'tcp dport 853 counter drop'
        not in content
    )


def test_secbox_dns_is_allowed_from_lan(
    tmp_path: Path,
) -> None:
    output = render_nftables_config(
        make_firewall(),
        tmp_path / "firewall.nft",
        enforce_lan_dns=True,
    )

    content = output.read_text(
        encoding="utf-8",
    )

    chain = content.split(
        "chain input {",
        1,
    )[1].split(
        "    }",
        1,
    )[0]

    udp_rule = (
        'iifname "ens36" '
        'udp dport 53 counter accept'
    )

    tcp_rule = (
        'iifname "ens36" '
        'tcp dport 53 counter accept'
    )

    assert udp_rule in chain
    assert tcp_rule in chain

    assert chain.index(udp_rule) < chain.index(
        'log prefix "SECBOX_INPUT_DROP: "'
    )

    assert chain.index(tcp_rule) < chain.index(
        'log prefix "SECBOX_INPUT_DROP: "'
    )


def test_encrypted_dns_bypass_is_blocked(
    tmp_path: Path,
) -> None:
    output = render_nftables_config(
        make_firewall(),
        tmp_path / "firewall.nft",
        block_dot=True,
        block_doq=True,
    )

    content = output.read_text(
        encoding="utf-8",
    )

    chain = content.split(
        "chain forward {",
        1,
    )[1].split(
        "    }",
        1,
    )[0]

    udp_rule = (
        'iifname "ens36" '
        'udp dport 853 counter drop'
    )

    tcp_rule = (
        'iifname "ens36" '
        'tcp dport 853 counter drop'
    )

    established_rule = (
        "ct state established,related accept"
    )

    assert udp_rule in chain
    assert tcp_rule in chain

    assert chain.index(udp_rule) < chain.index(
        established_rule
    )

    assert chain.index(tcp_rule) < chain.index(
        established_rule
    )



def test_dot_can_be_enabled_independently(
    tmp_path: Path,
) -> None:
    output = render_nftables_config(
        make_firewall(),
        tmp_path / "firewall.nft",
        block_dot=True,
        block_doq=False,
    )

    content = output.read_text(
        encoding="utf-8",
    )

    assert (
        'iifname "ens36" '
        'tcp dport 853 counter drop'
        in content
    )

    assert (
        'iifname "ens36" '
        'udp dport 853 counter drop'
        not in content
    )


def test_doq_can_be_enabled_independently(
    tmp_path: Path,
) -> None:
    output = render_nftables_config(
        make_firewall(),
        tmp_path / "firewall.nft",
        block_dot=False,
        block_doq=True,
    )

    content = output.read_text(
        encoding="utf-8",
    )

    assert (
        'iifname "ens36" '
        'udp dport 853 counter drop'
        in content
    )

    assert (
        'iifname "ens36" '
        'tcp dport 853 counter drop'
        not in content
    )


def test_doh_resolver_https_is_blocked(
    tmp_path: Path,
) -> None:
    from ipaddress import IPv4Address

    output = render_nftables_config(
        make_firewall(),
        tmp_path / "firewall.nft",
        doh_resolver_addresses=[
            IPv4Address("1.1.1.1"),
            IPv4Address("8.8.8.8"),
        ],
    )

    content = output.read_text(
        encoding="utf-8",
    )

    assert "set doh_resolvers_v4 {" in content
    assert "type ipv4_addr;" in content

    assert (
        "elements = { 1.1.1.1, 8.8.8.8 };"
        in content
    )

    chain = content.split(
        "chain forward {",
        1,
    )[1].split(
        "    }",
        1,
    )[0]

    tcp_rule = (
        'iifname "ens36" '
        'ip daddr @doh_resolvers_v4 '
        'tcp dport 443 counter drop'
    )

    udp_rule = (
        'iifname "ens36" '
        'ip daddr @doh_resolvers_v4 '
        'udp dport 443 counter drop'
    )

    established_rule = (
        "ct state established,related accept"
    )

    assert tcp_rule in chain
    assert udp_rule in chain

    assert chain.index(tcp_rule) < chain.index(
        established_rule
    )

    assert chain.index(udp_rule) < chain.index(
        established_rule
    )


def test_empty_doh_resolver_list_creates_no_rules(
    tmp_path: Path,
) -> None:
    output = render_nftables_config(
        make_firewall(),
        tmp_path / "firewall.nft",
        doh_resolver_addresses=[],
    )

    content = output.read_text(
        encoding="utf-8",
    )

    assert "doh_resolvers_v4" not in content


def test_enabled_doh_set_exists_when_empty(
    tmp_path: Path,
) -> None:
    output = render_nftables_config(
        make_firewall(),
        tmp_path / "firewall.nft",
        enable_doh_set=True,
        doh_resolver_addresses=[],
    )

    content = output.read_text(
        encoding="utf-8",
    )

    assert "set doh_resolvers_v4 {" in content

    assert (
        'ip daddr @doh_resolvers_v4 '
        'tcp dport 443 counter drop'
        in content
    )

    assert (
        'ip daddr @doh_resolvers_v4 '
        'udp dport 443 counter drop'
        in content
    )

    assert "elements = {" not in content
