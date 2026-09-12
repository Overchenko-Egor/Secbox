"""Cross-module validation for content filtering."""

from secbox.core.models import SecBoxConfig


class ContentFilterValidationError(Exception):
    """Raised when content-filter configuration is invalid."""


def validate_content_filter_config(
    config: SecBoxConfig,
) -> None:
    """Validate content-filter settings against network config."""

    content_filter = config.content_filter

    if content_filter is None:
        return

    if not content_filter.enabled:
        return

    if config.firewall is None or not config.firewall.enabled:
        raise ContentFilterValidationError(
            "enabled content filter requires enabled firewall"
        )

    if content_filter.policy.default_action != "allow":
        raise ContentFilterValidationError(
            "default_action='block' is not supported yet"
        )

    if content_filter.policy.allowed_domains:
        raise ContentFilterValidationError(
            "allowed_domains is not supported yet"
        )

    interface_name = (
        content_filter.dns.listen_interface
    )

    listen_address = str(
        content_filter.dns.listen_address
    )

    matching_interfaces = [
        interface
        for interface in config.network.interfaces
        if interface.name == interface_name
    ]

    if not matching_interfaces:
        raise ContentFilterValidationError(
            f"content filter interface "
            f"{interface_name!r} is not configured"
        )

    interface = matching_interfaces[0]

    if interface.role != "lan":
        raise ContentFilterValidationError(
            "content filter must listen "
            "on a LAN interface"
        )

    if interface.ipv4_method != "static":
        raise ContentFilterValidationError(
            "content filter LAN interface "
            "must use static IPv4 configuration"
        )

    if interface.ipv4_address is None:
        raise ContentFilterValidationError(
            "content filter LAN interface "
            "has no IPv4 address"
        )

    configured_address = str(
        interface.ipv4_address.ip
    )

    if configured_address != listen_address:
        raise ContentFilterValidationError(
            "content filter listen_address "
            "must match the LAN interface address"
        )
