from pathlib import Path

import pytest

from secbox.modules.deception import runtime


def test_nft_script_empty():
    assert runtime._nft_sync_script(
        set()
    ) == (
        "flush set inet secbox_filter "
        "deception_sources_v4\n"
    )


def test_nft_script_multiple_sources_sorted():
    script = runtime._nft_sync_script(
        {
            "203.0.113.20",
            "192.0.2.5",
        }
    )

    assert (
        "flush set inet secbox_filter "
        "deception_sources_v4"
        in script
    )

    assert (
        "{ 192.0.2.5, 203.0.113.20 }"
        in script
    )


def test_managed_routes_are_filtered(
    monkeypatch: pytest.MonkeyPatch,
):
    class Result:
        stdout = (
            "10.250.0.0/24 dev eth0 proto kernel\n"
            "203.0.113.7 via 10.250.0.1 dev eth0\n"
            "192.0.2.9/32 via 10.250.0.1 dev eth0\n"
            "default via 10.250.0.1 dev eth0\n"
        )

    monkeypatch.setattr(
        runtime,
        "_run",
        lambda *args, **kwargs: Result(),
    )

    assert runtime._managed_namespace_routes() == {
        "203.0.113.7",
        "192.0.2.9",
    }


def test_policy_priority_conflict_rejected(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        runtime,
        "_policy_rule_lines",
        lambda: [
            "80: from all lookup main",
        ],
    )

    with pytest.raises(
        runtime.DeceptionRuntimeError,
        match="already occupied",
    ):
        runtime._ensure_policy_rule()


def test_existing_policy_rule_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        runtime,
        "_policy_rule_lines",
        lambda: [
            (
                "80: from all fwmark "
                "0x400/0x400 lookup 260"
            ),
        ],
    )

    calls = []

    monkeypatch.setattr(
        runtime,
        "_run",
        lambda *args, **kwargs:
            calls.append(args),
    )

    runtime._ensure_policy_rule()

    assert calls == []


def test_reconcile_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    events = []

    monkeypatch.setattr(
        runtime,
        "active_sources",
        lambda path: [
            "203.0.113.5",
        ],
    )

    monkeypatch.setattr(
        runtime,
        "_preflight",
        lambda:
            events.append("preflight"),
    )

    monkeypatch.setattr(
        runtime,
        "_ensure_policy_routes",
        lambda:
            events.append("routes"),
    )

    monkeypatch.setattr(
        runtime,
        "_ensure_policy_rule",
        lambda:
            events.append("rule"),
    )

    monkeypatch.setattr(
        runtime,
        "_add_namespace_routes",
        lambda sources:
            events.append("ns-add"),
    )

    monkeypatch.setattr(
        runtime,
        "_sync_nft_set",
        lambda sources:
            events.append("nft"),
    )

    monkeypatch.setattr(
        runtime,
        "_remove_stale_namespace_routes",
        lambda sources:
            events.append("ns-remove"),
    )

    result = runtime.reconcile(
        tmp_path / "state.json"
    )

    assert events == [
        "preflight",
        "routes",
        "rule",
        "ns-add",
        "nft",
        "ns-remove",
    ]

    assert result["sources"] == [
        "203.0.113.5"
    ]
