from pathlib import Path

import pytest
from pydantic import ValidationError

from secbox.modules.content_filter.models import (
    ContentFilterConfig,
    ContentFilterPolicyConfig,
    DnsFilterConfig,
    DohFilterConfig,
)
from secbox.modules.dhcp.models import DhcpServerConfig
from secbox.modules.dhcp.renderer import render_dnsmasq_config
from secbox.core.models import SecBoxConfig
from secbox.modules.content_filter.validator import (
    ContentFilterValidationError,
    validate_content_filter_config,
)
from secbox.modules.firewall.models import FirewallConfig
from secbox.modules.network.models import (
    NetworkConfig,
    NetworkInterfaceConfig,
)


def make_dhcp() -> DhcpServerConfig:
    return DhcpServerConfig(
        enabled=True,
        interface="ens36",
        network="192.168.50.0/24",
        range_start="192.168.50.100",
        range_end="192.168.50.200",
        gateway="192.168.50.1",
        dns_servers=["192.168.1.1"],
        lease_time="12h",
    )


def make_filter(
    *,
    enabled: bool = True,
    default_action: str = "allow",
    blocked_domains: list[str] | None = None,
    allowed_domains: list[str] | None = None,
) -> ContentFilterConfig:
    return ContentFilterConfig(
        enabled=enabled,
        dns=DnsFilterConfig(
            enabled=True,
            listen_interface="ens36",
            listen_address="192.168.50.1",
            upstream_servers=["1.1.1.1", "8.8.8.8"],
        ),
        policy=ContentFilterPolicyConfig(
            default_action=default_action,
            blocked_domains=blocked_domains or [],
            allowed_domains=allowed_domains or [],
        ),
    )


def test_disabled_filter_keeps_dns_disabled(
    tmp_path: Path,
) -> None:
    path = render_dnsmasq_config(
        [make_dhcp()],
        tmp_path / "dnsmasq.conf",
        content_filter=make_filter(enabled=False),
    )

    text = path.read_text()

    assert "port=0" in text
    assert "server=1.1.1.1" not in text
    assert (
        "dhcp-option=interface:ens36,6,192.168.1.1"
        in text
    )


def test_enabled_filter_advertises_secbox_dns(
    tmp_path: Path,
) -> None:
    path = render_dnsmasq_config(
        [make_dhcp()],
        tmp_path / "dnsmasq.conf",
        content_filter=make_filter(),
    )

    text = path.read_text()

    assert "port=0" not in text
    assert "interface=ens36" in text
    assert "listen-address=192.168.50.1" in text

    assert (
        "dhcp-option=interface:ens36,6,192.168.50.1"
        in text
    )

    assert (
        "dhcp-option=interface:ens36,6,192.168.1.1"
        not in text
    )


def test_enabled_filter_uses_explicit_upstreams(
    tmp_path: Path,
) -> None:
    path = render_dnsmasq_config(
        [make_dhcp()],
        tmp_path / "dnsmasq.conf",
        content_filter=make_filter(),
    )

    text = path.read_text()

    assert "no-resolv" in text
    assert "server=1.1.1.1" in text
    assert "server=8.8.8.8" in text


def test_blocked_domains_are_rendered(
    tmp_path: Path,
) -> None:
    path = render_dnsmasq_config(
        [make_dhcp()],
        tmp_path / "dnsmasq.conf",
        content_filter=make_filter(
            blocked_domains=[
                "example.com",
                "ads.example.net",
            ]
        ),
    )

    text = path.read_text()

    assert "address=/example.com/0.0.0.0" in text
    assert "address=/example.com/::" in text

    assert "address=/ads.example.net/0.0.0.0" in text
    assert "address=/ads.example.net/::" in text


def test_domain_names_are_normalized() -> None:
    policy = ContentFilterPolicyConfig(
        blocked_domains=[
            "Example.COM.",
            "ADS.Example.NET",
        ]
    )

    assert policy.blocked_domains == [
        "example.com",
        "ads.example.net",
    ]


def test_allow_block_conflict_is_rejected() -> None:
    with pytest.raises(
        ValidationError,
        match="domains cannot be both allowed and blocked",
    ):
        ContentFilterPolicyConfig(
            blocked_domains=["example.com"],
            allowed_domains=["EXAMPLE.COM."],
        )


def make_secbox_config(
    *,
    filter_enabled: bool = True,
    firewall_enabled: bool = True,
    default_action: str = "allow",
    allowed_domains: list[str] | None = None,
    listen_interface: str = "ens36",
    listen_address: str = "192.168.50.1",
    lan_method: str = "static",
    lan_address: str | None = "192.168.50.1/24",
) -> SecBoxConfig:
    lan_data: dict[str, object] = {
        "name": "ens36",
        "role": "lan",
        "ipv4_method": lan_method,
    }

    if lan_address is not None:
        lan_data["ipv4_address"] = lan_address

    network = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens33",
                role="wan",
                ipv4_method="dhcp",
            ),
            NetworkInterfaceConfig.model_validate(
                lan_data
            ),
            NetworkInterfaceConfig(
                name="ens38",
                role="mgmt",
                ipv4_method="static",
                ipv4_address="192.168.100.2/24",
            ),
        ]
    )

    firewall = FirewallConfig(
        enabled=firewall_enabled,
        wan_interface="ens33",
        lan_interface="ens36",
        management_interface="ens38",
    )

    content_filter = ContentFilterConfig(
        enabled=filter_enabled,
        dns=DnsFilterConfig(
            enabled=True,
            listen_interface=listen_interface,
            listen_address=listen_address,
            upstream_servers=[
                "1.1.1.1",
                "8.8.8.8",
            ],
        ),
        policy=ContentFilterPolicyConfig(
            default_action=default_action,
            allowed_domains=allowed_domains or [],
        ),
    )

    return SecBoxConfig.model_validate(
        {
            "schema_version": 1,
            "system": {
                "hostname": "secbox",
            },
            "network": network.model_dump(
                mode="json"
            ),
            "dhcp": [],
            "firewall": firewall.model_dump(
                mode="json"
            ),
            "content_filter": content_filter.model_dump(
                mode="json"
            ),
        }
    )


def test_content_filter_preflight_passes() -> None:
    config = make_secbox_config()

    validate_content_filter_config(config)


def test_disabled_content_filter_skips_preflight() -> None:
    config = make_secbox_config(
        filter_enabled=False,
        firewall_enabled=False,
    )

    validate_content_filter_config(config)


def test_enabled_filter_requires_firewall() -> None:
    config = make_secbox_config(
        firewall_enabled=False,
    )

    with pytest.raises(
        ContentFilterValidationError,
        match="requires enabled firewall",
    ):
        validate_content_filter_config(config)


def test_default_block_policy_passes_preflight() -> None:
    config = make_secbox_config(
        default_action="block",
        allowed_domains=["example.com"],
    )

    validate_content_filter_config(config)


def test_allowed_domains_pass_preflight() -> None:
    config = make_secbox_config(
        allowed_domains=["example.com"],
    )

    validate_content_filter_config(config)


def test_content_filter_must_use_lan_interface() -> None:
    config = make_secbox_config(
        listen_interface="ens33",
        listen_address="192.168.1.1",
    )

    with pytest.raises(
        ContentFilterValidationError,
        match="must listen on a LAN interface",
    ):
        validate_content_filter_config(config)


def test_content_filter_address_must_match_lan() -> None:
    config = make_secbox_config(
        listen_address="192.168.50.254",
    )

    with pytest.raises(
        ContentFilterValidationError,
        match="must match the LAN interface address",
    ):
        validate_content_filter_config(config)


def test_encrypted_dns_defaults_are_enabled() -> None:
    config = ContentFilterConfig(
        enabled=True,
        dns=DnsFilterConfig(
            enabled=True,
            listen_interface="ens36",
            listen_address="192.168.50.1",
            upstream_servers=["1.1.1.1"],
        ),
    )

    assert config.encrypted_dns.block_dot is True
    assert config.encrypted_dns.block_doq is True
    assert config.encrypted_dns.doh.enabled is True
    assert config.encrypted_dns.doh.resolver_addresses == []


def test_doh_resolver_addresses_are_accepted() -> None:
    config = DohFilterConfig(
        enabled=True,
        resolver_addresses=[
            "1.1.1.1",
            "8.8.8.8",
        ],
    )

    assert [
        str(address)
        for address in config.resolver_addresses
    ] == [
        "1.1.1.1",
        "8.8.8.8",
    ]


def test_doh_resolver_addresses_must_be_unique() -> None:
    with pytest.raises(
        ValidationError,
        match="DoH resolver addresses must be unique",
    ):
        DohFilterConfig(
            resolver_addresses=[
                "1.1.1.1",
                "1.1.1.1",
            ],
        )


def test_doh_managed_feed_is_disabled_by_default() -> None:
    config = DohFilterConfig()

    assert config.managed_feed_enabled is False


def test_managed_feed_url_accepts_https() -> None:
    config = DohFilterConfig(
        managed_feed_url=(
            "https://example.test/doh.txt"
        )
    )

    assert config.managed_feed_url == (
        "https://example.test/doh.txt"
    )


def test_managed_feed_url_rejects_http() -> None:
    import pytest

    with pytest.raises(
        ValueError,
        match="must use HTTPS",
    ):
        DohFilterConfig(
            managed_feed_url=(
                "http://example.test/doh.txt"
            )
        )


def test_default_block_renders_global_sinkhole(
    tmp_path: Path,
) -> None:
    path = render_dnsmasq_config(
        [make_dhcp()],
        tmp_path / "dnsmasq.conf",
        content_filter=make_filter(
            default_action="block",
            allowed_domains=[
                "example.com",
            ],
        ),
    )

    text = path.read_text()

    assert "address=/#/0.0.0.0" in text
    assert "address=/#/::" in text

    assert (
        "server=/example.com/1.1.1.1"
        in text
    )

    assert (
        "server=/example.com/8.8.8.8"
        in text
    )


def test_allowlist_can_override_blocked_parent(
    tmp_path: Path,
) -> None:
    path = render_dnsmasq_config(
        [make_dhcp()],
        tmp_path / "dnsmasq.conf",
        content_filter=make_filter(
            default_action="allow",
            blocked_domains=[
                "example.com",
            ],
            allowed_domains=[
                "safe.example.com",
            ],
        ),
    )

    text = path.read_text()

    assert (
        "address=/example.com/0.0.0.0"
        in text
    )

    assert (
        "server=/safe.example.com/1.1.1.1"
        in text
    )


def test_blocked_child_can_override_allowed_parent(
    tmp_path: Path,
) -> None:
    path = render_dnsmasq_config(
        [make_dhcp()],
        tmp_path / "dnsmasq.conf",
        content_filter=make_filter(
            default_action="block",
            allowed_domains=[
                "example.com",
            ],
            blocked_domains=[
                "ads.example.com",
            ],
        ),
    )

    text = path.read_text()

    assert (
        "server=/example.com/1.1.1.1"
        in text
    )

    assert (
        "address=/ads.example.com/0.0.0.0"
        in text
    )


def test_exact_allow_block_conflict_remains_rejected(
) -> None:
    with pytest.raises(
        ValidationError,
        match="domains cannot be both allowed and blocked",
    ):
        ContentFilterPolicyConfig(
            default_action="block",
            allowed_domains=[
                "example.com",
            ],
            blocked_domains=[
                "example.com",
            ],
        )


def _cf_with_managed_feed(
    config,
    *,
    enabled: bool,
    url: str = "https://example.test/doh.txt",
):
    content_filter = (
        config.content_filter.model_copy(
            deep=True
        )
    )

    doh = (
        content_filter
        .encrypted_dns
        .doh
        .model_copy(
            update={
                "managed_feed_enabled":
                    enabled,
                "managed_feed_url":
                    url,
            }
        )
    )

    encrypted_dns = (
        content_filter
        .encrypted_dns
        .model_copy(
            update={
                "doh": doh,
            }
        )
    )

    content_filter = (
        content_filter.model_copy(
            update={
                "encrypted_dns":
                    encrypted_dns,
            }
        )
    )

    return type(config).model_validate(
        config.model_copy(
            update={
                "content_filter":
                    content_filter,
            }
        ).model_dump(
            mode="json"
        )
    )


def test_content_filter_disable_feed_clears_state_and_timer(
    monkeypatch,
):
    from datetime import UTC, datetime
    from ipaddress import IPv4Address

    from secbox.actions import (
        content_filter as action,
    )
    from secbox.modules.content_filter.doh_feed.models import (
        DohFeedState,
    )

    previous = _cf_with_managed_feed(
        make_secbox_config(),
        enabled=True,
    )

    candidate = _cf_with_managed_feed(
        previous,
        enabled=False,
    )

    class FakeConfigStore:
        def __init__(self):
            self.current = previous

        def load(self):
            return self.current

        def save(self, value):
            self.current = value

    class FakeDohStore:
        def __init__(self):
            self.current = DohFeedState(
                addresses=[
                    IPv4Address(
                        "9.9.9.9"
                    ),
                ],
                updated_at=datetime.now(
                    UTC
                ),
            )

        def load(self):
            return self.current

        def save(self, value):
            self.current = value

    config_store = FakeConfigStore()
    doh_store = FakeDohStore()
    calls = []

    monkeypatch.setattr(
        action,
        "DohFeedStore",
        lambda: doh_store,
    )

    monkeypatch.setattr(
        action,
        "validate_content_filter_config",
        lambda config: None,
    )

    monkeypatch.setattr(
        action,
        "_apply_dns",
        lambda config: None,
    )

    monkeypatch.setattr(
        action,
        "_systemctl",
        lambda operation, unit: calls.append(
            (operation, unit)
        ),
    )

    result = (
        action.apply_content_filter_action(
            candidate.content_filter,
            store=config_store,
        )
    )

    assert result.managed_feed_enabled is False
    assert doh_store.current.addresses == []
    assert doh_store.current.updated_at is None

    assert (
        "stop",
        "secbox-doh-feed.service",
    ) in calls

    assert (
        "stop",
        "secbox-doh-feed.timer",
    ) in calls

    assert (
        "disable",
        "secbox-doh-feed.timer",
    ) in calls

    assert (
        "restart",
        "secbox-firewall.service",
    ) in calls


def test_content_filter_enable_feed_clears_stale_state_and_refreshes(
    monkeypatch,
):
    from datetime import UTC, datetime
    from ipaddress import IPv4Address

    from secbox.actions import (
        content_filter as action,
    )
    from secbox.modules.content_filter.doh_feed.models import (
        DohFeedState,
    )

    previous = _cf_with_managed_feed(
        make_secbox_config(),
        enabled=False,
    )

    candidate = _cf_with_managed_feed(
        previous,
        enabled=True,
    )

    class FakeConfigStore:
        def __init__(self):
            self.current = previous

        def load(self):
            return self.current

        def save(self, value):
            self.current = value

    class FakeDohStore:
        def __init__(self):
            self.current = DohFeedState(
                addresses=[
                    IPv4Address(
                        "9.9.9.9"
                    ),
                ],
                updated_at=datetime.now(
                    UTC
                ),
            )

        def load(self):
            return self.current

        def save(self, value):
            self.current = value

    config_store = FakeConfigStore()
    doh_store = FakeDohStore()
    calls = []

    monkeypatch.setattr(
        action,
        "DohFeedStore",
        lambda: doh_store,
    )

    monkeypatch.setattr(
        action,
        "validate_content_filter_config",
        lambda config: None,
    )

    monkeypatch.setattr(
        action,
        "_apply_dns",
        lambda config: None,
    )

    monkeypatch.setattr(
        action,
        "_systemctl",
        lambda operation, unit: calls.append(
            (operation, unit)
        ),
    )

    result = (
        action.apply_content_filter_action(
            candidate.content_filter,
            store=config_store,
        )
    )

    assert result.managed_feed_enabled is True

    # Stale state is removed before first fresh update.
    assert doh_store.current.addresses == []

    assert (
        "enable",
        "secbox-doh-feed.timer",
    ) in calls

    assert (
        "start",
        "secbox-doh-feed.timer",
    ) in calls

    assert (
        "start",
        "secbox-doh-feed.service",
    ) in calls


def test_content_filter_enable_failure_restores_config_state_and_timer(
    monkeypatch,
):
    from datetime import UTC, datetime
    from ipaddress import IPv4Address

    from secbox.actions import (
        content_filter as action,
    )
    from secbox.modules.content_filter.doh_feed.models import (
        DohFeedState,
    )

    previous = _cf_with_managed_feed(
        make_secbox_config(),
        enabled=False,
    )

    candidate = _cf_with_managed_feed(
        previous,
        enabled=True,
    )

    original_state = DohFeedState(
        addresses=[
            IPv4Address(
                "9.9.9.9"
            ),
        ],
        updated_at=datetime.now(
            UTC
        ),
    )

    class FakeConfigStore:
        def __init__(self):
            self.current = previous

        def load(self):
            return self.current

        def save(self, value):
            self.current = value

    class FakeDohStore:
        def __init__(self):
            self.current = original_state

        def load(self):
            return self.current

        def save(self, value):
            self.current = value

    config_store = FakeConfigStore()
    doh_store = FakeDohStore()
    calls = []

    monkeypatch.setattr(
        action,
        "DohFeedStore",
        lambda: doh_store,
    )

    monkeypatch.setattr(
        action,
        "validate_content_filter_config",
        lambda config: None,
    )

    monkeypatch.setattr(
        action,
        "_apply_dns",
        lambda config: None,
    )

    failed = False

    def fake_systemctl(
        operation,
        unit,
    ):
        nonlocal failed

        calls.append(
            (operation, unit)
        )

        if (
            not failed
            and operation == "start"
            and unit
            == "secbox-doh-feed.service"
        ):
            failed = True

            raise action.ContentFilterActionError(
                "simulated feed refresh failure"
            )

    monkeypatch.setattr(
        action,
        "_systemctl",
        fake_systemctl,
    )

    with pytest.raises(
        action.ContentFilterActionError,
        match="simulated feed refresh failure",
    ):
        action.apply_content_filter_action(
            candidate.content_filter,
            store=config_store,
        )

    assert (
        config_store
        .current
        .content_filter
        .encrypted_dns
        .doh
        .managed_feed_enabled
        is False
    )

    assert (
        doh_store.current
        == original_state
    )

    # Previous lifecycle was disabled, so rollback
    # must leave both service and timer stopped.
    assert (
        "disable",
        "secbox-doh-feed.timer",
    ) in calls
