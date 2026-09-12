"""Validate and render a candidate in a disposable directory."""

from pathlib import Path
from tempfile import TemporaryDirectory

from pydantic import BaseModel

from secbox.core.models import SecBoxConfig
from secbox.modules.content_filter.validator import validate_content_filter_config
from secbox.modules.dhcp.renderer import render_dnsmasq_config
from secbox.modules.dhcp.validator import validate_dhcp_preflight
from secbox.modules.firewall.renderer import render_nftables_config
from secbox.modules.firewall.validator import validate_firewall_preflight
from secbox.modules.network.renderer import render_networkd
from secbox.modules.network.state import NetworkInterfaceState
from secbox.modules.network.validator import validate_management_interface, validate_network_preflight


class ConfigPreview(BaseModel):
    valid: bool = True
    applied: bool = False
    files: dict[str, str]
    notes: list[str]


def preview_config(config: SecBoxConfig, interfaces: list[NetworkInterfaceState]) -> ConfigPreview:
    validate_network_preflight(config.network, interfaces)
    validate_management_interface(config.network, interfaces)
    validate_dhcp_preflight(config.dhcp, config.network)
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
            )
            files[path.name] = path.read_text(encoding="utf-8")
        else:
            notes.append("Firewall is not configured or is disabled; no nftables file was generated.")
    return ConfigPreview(files=files, notes=notes)
