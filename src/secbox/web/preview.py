"""Validate and render a candidate in a disposable directory."""

from pathlib import Path
from tempfile import TemporaryDirectory

from pydantic import BaseModel

from secbox.core.models import SecBoxConfig
from secbox.modules.content_filter.doh_feed.resolver import (
    resolve_effective_doh_addresses,
)
from secbox.modules.content_filter.doh_feed.store import (
    DohFeedStore,
    DohFeedStoreError,
)
from secbox.modules.content_filter.validator import validate_content_filter_config
from secbox.modules.dhcp.renderer import render_dnsmasq_config
from secbox.modules.dhcp.validator import validate_dhcp_preflight
from secbox.modules.firewall.renderer import render_nftables_config
from secbox.modules.vpn.firewall import get_vpn_firewall_interfaces
from secbox.modules.firewall.validator import validate_firewall_preflight
from secbox.modules.network.renderer import render_networkd
from secbox.modules.network.state import NetworkInterfaceState
from secbox.modules.network.validator import validate_management_interface, validate_network_preflight


class ConfigPreview(BaseModel):
    valid: bool = True
    applied: bool = False
    files: dict[str, str]
    notes: list[str]



def _load_doh_managed_state(config):
    """Load managed DoH state for firewall preview."""

    content_filter = config.content_filter

    if (
        content_filter is None
        or not content_filter.enabled
        or not content_filter.encrypted_dns.doh.enabled
        or not content_filter.encrypted_dns.doh.managed_feed_enabled
    ):
        return None

    try:
        return DohFeedStore().load()
    except DohFeedStoreError as error:
        raise RuntimeError(
            f"failed to load managed DoH state: {error}"
        ) from error


def preview_config(config: SecBoxConfig, interfaces: list[NetworkInterfaceState]) -> ConfigPreview:
    validate_network_preflight(config.network, interfaces)
    validate_management_interface(config.network, interfaces)
    validate_dhcp_preflight(config.dhcp, config.network, config.vpn)
    validate_content_filter_config(config)
    if config.firewall is not None and config.firewall.enabled:
        validate_firewall_preflight(config.firewall, config.network)

    files: dict[str, str] = {}
    notes = [
        "Configuration was not saved or applied.",
        "Checks cover the SecBox schema and cross-module consistency; native service syntax checks are not run.",
    ]
    with TemporaryDirectory(prefix="secbox-preview-") as temporary:
        root = Path(temporary)
        for path in render_networkd(config.network, root / "networkd"):
            files[f"networkd/{path.name}"] = path.read_text(encoding="utf-8")
        dns_enabled = (
            config.content_filter is not None
            and config.content_filter.enabled
            and config.content_filter.dns.enabled
        )

        if any(server.enabled for server in config.dhcp) or dns_enabled:
            path = render_dnsmasq_config(
                config.dhcp,
                root / "dnsmasq.conf",
                content_filter=config.content_filter,
            )
            files[path.name] = path.read_text(encoding="utf-8")
        if config.firewall is not None and config.firewall.enabled:
            path = render_nftables_config(
                config.firewall,
                root / "nftables.conf",
                enforce_lan_dns=dns_enabled,
                block_dot=(
                    config.content_filter is not None
                    and config.content_filter.enabled
                    and config.content_filter.encrypted_dns.block_dot
                ),
                block_doq=(
                    config.content_filter is not None
                    and config.content_filter.enabled
                    and config.content_filter.encrypted_dns.block_doq
                ),
                enable_doh_set=(
                    config.content_filter is not None
                    and config.content_filter.enabled
                    and config.content_filter.encrypted_dns.doh.enabled
                ),
                doh_resolver_addresses=(
                    resolve_effective_doh_addresses(
                        config.content_filter,
                        _load_doh_managed_state(config),
                    )
                ),
                vpn_interfaces=get_vpn_firewall_interfaces(config.vpn),
            )
            files[path.name] = path.read_text(encoding="utf-8")
        else:
            notes.append("Firewall is not configured or is disabled; no nftables file was generated.")
    return ConfigPreview(files=files, notes=notes)
