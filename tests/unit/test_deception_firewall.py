from pathlib import Path

from secbox.modules.firewall.models import (
    FirewallConfig,
)
from secbox.modules.firewall.renderer import (
    render_nftables_config,
)


def make_firewall() -> FirewallConfig:
    return FirewallConfig(
        wan_interface="ens33",
        lan_interface="ens36",
        management_interface="ens38",
    )


def render(
    tmp_path: Path,
    *,
    vpn_interfaces: list[str] | None = None,
) -> str:
    output = (
        tmp_path
        / "secbox.nft"
    )

    render_nftables_config(
        make_firewall(),
        output,
        vpn_interfaces=vpn_interfaces,
    )

    return output.read_text(
        encoding="utf-8"
    )


def test_deception_set_exists(
    tmp_path: Path,
):
    content = render(
        tmp_path
    )

    assert (
        "set deception_sources_v4"
        in content
    )

    assert (
        "type ipv4_addr;"
        in content
    )


def test_prerouting_chain_exists(
    tmp_path: Path,
):
    content = render(
        tmp_path
    )

    assert (
        "chain deception_prerouting"
        in content
    )

    assert (
        "hook prerouting priority mangle"
        in content
    )


def test_new_connections_are_marked(
    tmp_path: Path,
):
    content = render(
        tmp_path,
        vpn_interfaces=[
            "wg0",
            "wg1",
            "wg2",
        ],
    )

    assert (
        "ip saddr @deception_sources_v4"
        in content
    )

    assert (
        "ct state new"
        in content
    )

    assert (
        "ct mark set 0x400"
        in content
    )

    assert (
        "meta mark set 0x400"
        in content
    )


def test_conntrack_mark_is_restored(
    tmp_path: Path,
):
    content = render(
        tmp_path
    )

    assert (
        "ct mark 0x400 "
        "meta mark set 0x400"
        in content
    )


def test_management_interface_not_used(
    tmp_path: Path,
):
    content = render(
        tmp_path,
        vpn_interfaces=[
            "wg0",
            "wg1",
            "wg2",
        ],
    )

    chain = (
        content
        .split(
            "chain deception_prerouting {",
            1,
        )[1]
        .split(
            "    }",
            1,
        )[0]
    )

    assert '"ens33"' in chain
    assert '"ens36"' in chain

    assert '"wg0"' in chain
    assert '"wg1"' in chain
    assert '"wg2"' in chain

    assert '"ens38"' not in chain


def test_existing_unmarked_connections_not_selected(
    tmp_path: Path,
):
    content = render(
        tmp_path
    )

    chain = (
        content
        .split(
            "chain deception_prerouting {",
            1,
        )[1]
        .split(
            "    }",
            1,
        )[0]
    )

    source_rule = next(
        line
        for line in chain.splitlines()
        if (
            "@deception_sources_v4"
            in line
        )
    )

    assert (
        "ct state new"
        in source_rule
    )


def test_mark_restore_only_on_deception_ingress(
    tmp_path: Path,
):
    content = render(
        tmp_path,
        vpn_interfaces=[
            "wg0",
            "wg1",
        ],
    )

    chain = (
        content
        .split(
            "chain deception_prerouting {",
            1,
        )[1]
        .split(
            "    }",
            1,
        )[0]
    )

    restore_rule = next(
        line
        for line in chain.splitlines()
        if (
            "ct mark 0x400"
            in line
            and "ct state new"
            not in line
        )
    )

    assert "iifname" in restore_rule
    assert '"ens33"' in restore_rule
    assert '"ens36"' in restore_rule
    assert '"wg0"' in restore_rule
    assert '"wg1"' in restore_rule

    assert '"ens38"' not in restore_rule
    assert '"veth-dec-host"' not in restore_rule


def test_quarantine_forward_allowed_before_blacklist(
    tmp_path: Path,
):
    content = render(
        tmp_path,
        vpn_interfaces=[
            "wg0",
            "wg1",
        ],
    )

    chain = (
        content
        .split(
            "chain forward {",
            1,
        )[1]
        .split(
            "    }",
            1,
        )[0]
    )

    quarantine_rule = (
        'meta mark 0x400 '
        'oifname "veth-dec-host" '
        'counter accept'
    )

    blacklist_rule = (
        "ip saddr @blacklist_v4 "
        "counter drop"
    )

    assert quarantine_rule in chain
    assert blacklist_rule in chain

    assert (
        chain.index(quarantine_rule)
        <
        chain.index(blacklist_rule)
    )


def test_quarantined_local_destination_is_dnat(
    tmp_path: Path,
):
    content = render(
        tmp_path,
        vpn_interfaces=[
            "wg0",
            "wg1",
        ],
    )

    assert (
        "chain deception_local_dnat"
        in content
    )

    chain = (
        content
        .split(
            "chain deception_local_dnat {",
            1,
        )[1]
        .split(
            "    }",
            1,
        )[0]
    )

    assert (
        "hook prerouting priority dstnat"
        in chain
    )

    assert (
        "ip saddr @deception_sources_v4"
        in chain
    )

    assert (
        "fib daddr type local"
        in chain
    )

    assert (
        "dnat ip to 10.250.0.2"
        in chain
    )


def test_management_ingress_is_not_local_dnat(
    tmp_path: Path,
):
    content = render(
        tmp_path,
        vpn_interfaces=[
            "wg0",
            "wg1",
        ],
    )

    chain = (
        content
        .split(
            "chain deception_local_dnat {",
            1,
        )[1]
        .split(
            "    }",
            1,
        )[0]
    )

    assert '"ens33"' in chain
    assert '"ens36"' in chain
    assert '"wg0"' in chain
    assert '"wg1"' in chain

    assert '"ens38"' not in chain


def test_quarantined_dns_is_dnat_to_synthetic_dns(tmp_path: Path):
    content = render(tmp_path, vpn_interfaces=["wg0", "wg1"])

    chain = content.split(
        "chain deception_local_dnat {", 1
    )[1].split("    }", 1)[0]

    assert (
        "udp dport 53 dnat ip to 10.61.14.12"
        in chain
    )
    assert (
        "tcp dport 53 dnat ip to 10.61.14.12"
        in chain
    )
