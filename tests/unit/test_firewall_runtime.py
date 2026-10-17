from secbox.actions import firewall_runtime


def test_firewall_runtime_parses_ruleset(
    monkeypatch,
    tmp_path,
):
    payload = {
        "nftables": [
            {
                "table": {
                    "family": "inet",
                    "name": "secbox_filter",
                }
            },
            {
                "chain": {
                    "family": "inet",
                    "table": "secbox_filter",
                    "name": "input",
                    "type": "filter",
                    "hook": "input",
                    "policy": "drop",
                }
            },
            {
                "rule": {
                    "family": "inet",
                    "table": "secbox_filter",
                    "chain": "input",
                    "expr": [
                        {
                            "counter": {
                                "packets": 10,
                                "bytes": 1000,
                            }
                        }
                    ],
                }
            },
            {
                "table": {
                    "family": "ip",
                    "name": "secbox_nat",
                }
            },
            {
                "rule": {
                    "family": "ip",
                    "table": "secbox_nat",
                    "chain": "postrouting",
                    "expr": [
                        {
                            "match": {
                                "left": {
                                    "meta": {
                                        "key": "oifname"
                                    }
                                },
                                "op": "==",
                                "right": "wg0",
                            }
                        },
                        {
                            "masquerade": None
                        },
                    ],
                }
            },
        ]
    }

    monkeypatch.setattr(
        firewall_runtime,
        "_nft_json",
        lambda *args: payload,
    )

    ip_forward = tmp_path / "ip_forward"
    ip_forward.write_text("1\n")

    monkeypatch.setattr(
        firewall_runtime,
        "IP_FORWARD_PATH",
        ip_forward,
    )

    result = (
        firewall_runtime
        .get_firewall_runtime_action()
    )

    assert result["filter_table"] is True
    assert result["nat_table"] is True
    assert result["ipv4_forwarding"] is True
    assert result["chains"]["input"]["policy"] == "drop"
    assert result["rule_counts"]["input"] == 1
    assert result["counters"]["input"]["packets"] == 10
    assert result["counters"]["input"]["bytes"] == 1000
    assert result["masquerade_interfaces"] == ["wg0"]
