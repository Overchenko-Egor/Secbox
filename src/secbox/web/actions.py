"""Client for tightly constrained privileged SecBox actions."""

import json
import socket
from dataclasses import dataclass
from pathlib import Path

from secbox.core.models import SecBoxConfig
from secbox.modules.vpn.models import VpnConfig
from secbox.modules.network.models import NetworkConfig
from secbox.modules.dhcp.models import DhcpServerConfig
from secbox.modules.content_filter.models import (
    ContentFilterConfig,
)
from secbox.modules.firewall.models import FirewallConfig


ACTION_SOCKET = Path(
    "/run/secbox/action.sock"
)

ACTION_TIMEOUT_SECONDS = 45.0
MAX_RESPONSE_BYTES = 64 * 1024


class WebActionError(RuntimeError):
    """Base error for privileged Web actions."""


class WebActionBusyError(WebActionError):
    """Another configuration transaction is already running."""


class WebActionTimeoutError(WebActionError):
    """Privileged action timed out."""


@dataclass(frozen=True)
class WebVpnApplyResult:
    applied_tunnels: int
    removed_tunnels: int
    active_name: str | None
    active_interface: str | None


def _exchange(
    request: dict[str, object],
) -> dict[str, object]:
    payload = (
        json.dumps(
            request,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )

    client = socket.socket(
        socket.AF_UNIX,
        socket.SOCK_STREAM,
    )

    client.settimeout(
        ACTION_TIMEOUT_SECONDS
    )

    try:
        client.connect(
            str(ACTION_SOCKET)
        )

        client.sendall(
            payload
        )

        client.shutdown(
            socket.SHUT_WR
        )

        chunks: list[bytes] = []
        total = 0

        while True:
            chunk = client.recv(
                4096
            )

            if not chunk:
                break

            total += len(
                chunk
            )

            if total > MAX_RESPONSE_BYTES:
                raise WebActionError(
                    "privileged helper response is too large"
                )

            chunks.append(
                chunk
            )

    except socket.timeout as error:
        raise WebActionTimeoutError(
            "privileged VPN action timed out"
        ) from error

    except OSError as error:
        raise WebActionError(
            "privileged action socket is unavailable"
        ) from error

    finally:
        client.close()

    raw = b"".join(
        chunks
    )

    try:
        response = json.loads(
            raw.decode("utf-8")
        )

    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as error:
        raise WebActionError(
            "privileged helper returned an invalid response"
        ) from error

    if not isinstance(
        response,
        dict,
    ):
        raise WebActionError(
            "privileged helper returned an invalid response"
        )

    return response


def apply_vpn_via_helper(
    vpn: VpnConfig,
) -> WebVpnApplyResult:
    """Submit validated VPN config through the privileged Unix socket."""

    response = _exchange(
        {
            "action": "apply-vpn",
            "vpn": vpn.model_dump(
                mode="json"
            ),
        }
    )

    error = response.get(
        "error"
    )

    if error == "busy":
        raise WebActionBusyError(
            "another configuration action is running"
        )

    if response.get("ok") is not True:
        raise WebActionError(
            "privileged VPN action failed"
        )

    data = response.get(
        "result"
    )

    if not isinstance(
        data,
        dict,
    ):
        raise WebActionError(
            "privileged helper result is missing"
        )

    try:
        return WebVpnApplyResult(
            applied_tunnels=int(
                data["applied_tunnels"]
            ),
            removed_tunnels=int(
                data["removed_tunnels"]
            ),
            active_name=data.get(
                "active_name"
            ),
            active_interface=data.get(
                "active_interface"
            ),
        )

    except (
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise WebActionError(
            "privileged helper result is invalid"
        ) from error


def get_vpn_via_helper() -> VpnConfig:
    """Read current VPN configuration through the privileged socket."""

    response = _exchange(
        {
            "action": "get-vpn",
        }
    )

    if response.get("ok") is not True:
        raise WebActionError(
            "privileged VPN configuration read failed"
        )

    result = response.get(
        "result"
    )

    if not isinstance(
        result,
        dict,
    ):
        raise WebActionError(
            "privileged helper result is missing"
        )

    raw_vpn = result.get(
        "vpn"
    )

    try:
        return VpnConfig.model_validate(
            raw_vpn
        )

    except Exception as error:
        raise WebActionError(
            "privileged helper returned invalid VPN configuration"
        ) from error


@dataclass(frozen=True)
class WebNetworkDhcpApplyResult:
    interfaces: int
    dhcp_scopes: int
    enabled_dhcp_scopes: int


def get_network_dhcp_via_helper(
) -> tuple[NetworkConfig, list[DhcpServerConfig]]:
    response = _exchange(
        {
            "action": "get-network-dhcp",
        }
    )

    if response.get("ok") is not True:
        raise WebActionError(
            "privileged Network/DHCP read failed"
        )

    data = response.get("result")

    if not isinstance(data, dict):
        raise WebActionError(
            "privileged helper returned invalid Network/DHCP data"
        )

    raw_network = data.get("network")
    raw_dhcp = data.get("dhcp")

    if not isinstance(raw_dhcp, list):
        raise WebActionError(
            "privileged helper returned invalid DHCP data"
        )

    try:
        network = NetworkConfig.model_validate(
            raw_network
        )

        dhcp = [
            DhcpServerConfig.model_validate(item)
            for item in raw_dhcp
        ]

    except Exception as error:
        raise WebActionError(
            "privileged helper returned invalid Network/DHCP configuration"
        ) from error

    return network, dhcp


def apply_network_dhcp_via_helper(
    network: NetworkConfig,
    dhcp: list[DhcpServerConfig],
) -> WebNetworkDhcpApplyResult:
    response = _exchange(
        {
            "action": "apply-network-dhcp",
            "network": network.model_dump(
                mode="json"
            ),
            "dhcp": [
                scope.model_dump(
                    mode="json"
                )
                for scope in dhcp
            ],
        }
    )

    error = response.get("error")

    if error == "busy":
        raise WebActionBusyError(
            "another configuration action is running"
        )

    if response.get("ok") is not True:
        detail = response.get("detail")

        if (
            isinstance(detail, str)
            and detail.strip()
        ):
            raise WebActionError(
                detail.strip()
            )

        raise WebActionError(
            "privileged Network/DHCP action failed"
        )

    data = response.get("result")

    if not isinstance(data, dict):
        raise WebActionError(
            "privileged helper returned invalid Network/DHCP result"
        )

    try:
        return WebNetworkDhcpApplyResult(
            interfaces=int(
                data["interfaces"]
            ),
            dhcp_scopes=int(
                data["dhcp_scopes"]
            ),
            enabled_dhcp_scopes=int(
                data["enabled_dhcp_scopes"]
            ),
        )
    except (
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise WebActionError(
            "privileged helper returned invalid Network/DHCP result"
        ) from error

@dataclass(frozen=True)
class WebDashboardContext:
    config: SecBoxConfig
    l2_handshakes: dict[str, dict[str, object]]
    doh_feed: dict[str, object]


def get_dashboard_context_via_helper() -> WebDashboardContext:
    """Read sanitized Dashboard context through the privileged worker."""

    response = _exchange(
        {
            "action": "get-dashboard-context",
        }
    )

    if response.get("ok") is not True:
        raise WebActionError(
            "privileged Dashboard context read failed"
        )

    result = response.get("result")

    if not isinstance(result, dict):
        raise WebActionError(
            "privileged Dashboard context is invalid"
        )

    raw_config = result.get("config")
    raw_l2 = result.get("l2_handshakes")
    raw_doh = result.get("doh_feed")

    if not isinstance(raw_l2, dict):
        raise WebActionError(
            "privileged L2 VPN health data is invalid"
        )

    if not isinstance(raw_doh, dict):
        raise WebActionError(
            "privileged DoH health data is invalid"
        )

    try:
        config = SecBoxConfig.model_validate(
            raw_config
        )
    except Exception as error:
        raise WebActionError(
            "privileged Dashboard configuration is invalid"
        ) from error

    l2_handshakes: dict[str, dict[str, object]] = {}

    for interface, value in raw_l2.items():
        if not isinstance(interface, str):
            raise WebActionError(
                "privileged L2 VPN health data is invalid"
            )

        if not isinstance(value, dict):
            raise WebActionError(
                "privileged L2 VPN health data is invalid"
            )

        l2_handshakes[interface] = value

    return WebDashboardContext(
        config=config,
        l2_handshakes=l2_handshakes,
        doh_feed=raw_doh,
    )



@dataclass(frozen=True)
class WebContentFilterApplyResult:
    enabled: bool
    default_action: str
    blocked_domains: int
    allowed_domains: int
    doh_enabled: bool
    managed_feed_enabled: bool


def get_content_filter_via_helper() -> ContentFilterConfig:
    response = _exchange(
        {
            "action": "get-content-filter",
        }
    )

    if response.get("ok") is not True:
        raise WebActionError(
            "privileged Content Filter read failed"
        )

    result = response.get("result")

    if not isinstance(result, dict):
        raise WebActionError(
            "privileged Content Filter result is invalid"
        )

    raw = result.get("content_filter")

    if raw is None:
        raise WebActionError(
            "Content Filter configuration is missing"
        )

    try:
        return ContentFilterConfig.model_validate(raw)

    except Exception as error:
        raise WebActionError(
            "privileged Content Filter configuration is invalid"
        ) from error


def apply_content_filter_via_helper(
    content_filter: ContentFilterConfig,
) -> WebContentFilterApplyResult:
    response = _exchange(
        {
            "action": "apply-content-filter",
            "content_filter": content_filter.model_dump(
                mode="json"
            ),
        }
    )

    error = response.get("error")

    if error == "busy":
        raise WebActionBusyError(
            "another configuration action is running"
        )

    if response.get("ok") is not True:
        detail = response.get("detail")

        if isinstance(detail, str) and detail.strip():
            raise WebActionError(detail.strip())

        raise WebActionError(
            "privileged Content Filter apply failed"
        )

    result = response.get("result")

    if not isinstance(result, dict):
        raise WebActionError(
            "privileged Content Filter result is invalid"
        )

    try:
        return WebContentFilterApplyResult(
            enabled=bool(result["enabled"]),
            default_action=str(
                result["default_action"]
            ),
            blocked_domains=int(
                result["blocked_domains"]
            ),
            allowed_domains=int(
                result["allowed_domains"]
            ),
            doh_enabled=bool(
                result["doh_enabled"]
            ),
            managed_feed_enabled=bool(
                result["managed_feed_enabled"]
            ),
        )

    except (
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise WebActionError(
            "privileged Content Filter result is invalid"
        ) from error


@dataclass(frozen=True)
class WebFirewallApplyResult:
    enabled: bool
    wan_interface: str
    lan_interface: str
    management_interface: str
    nat_enabled: bool
    dynamic_blacklist_enabled: bool


def get_firewall_via_helper() -> FirewallConfig:
    response = _exchange(
        {
            "action": "get-firewall",
        }
    )

    if response.get("ok") is not True:
        raise WebActionError(
            "privileged Firewall read failed"
        )

    result = response.get("result")

    if not isinstance(result, dict):
        raise WebActionError(
            "privileged Firewall result is invalid"
        )

    raw = result.get("firewall")

    if raw is None:
        raise WebActionError(
            "Firewall configuration is missing"
        )

    try:
        return FirewallConfig.model_validate(raw)

    except Exception as error:
        raise WebActionError(
            "privileged Firewall configuration is invalid"
        ) from error


def apply_firewall_via_helper(
    firewall: FirewallConfig,
) -> WebFirewallApplyResult:
    response = _exchange(
        {
            "action": "apply-firewall",
            "firewall": firewall.model_dump(
                mode="json"
            ),
        }
    )

    error = response.get("error")

    if error == "busy":
        raise WebActionBusyError(
            "another configuration action is running"
        )

    if response.get("ok") is not True:
        detail = response.get("detail")

        if isinstance(detail, str) and detail.strip():
            raise WebActionError(detail.strip())

        raise WebActionError(
            "privileged Firewall apply failed"
        )

    result = response.get("result")

    if not isinstance(result, dict):
        raise WebActionError(
            "privileged Firewall result is invalid"
        )

    try:
        return WebFirewallApplyResult(
            enabled=bool(result["enabled"]),
            wan_interface=str(result["wan_interface"]),
            lan_interface=str(result["lan_interface"]),
            management_interface=str(
                result["management_interface"]
            ),
            nat_enabled=bool(result["nat_enabled"]),
            dynamic_blacklist_enabled=bool(
                result["dynamic_blacklist_enabled"]
            ),
        )

    except (
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise WebActionError(
            "privileged Firewall result is invalid"
        ) from error


def get_managed_services_via_helper(
) -> list[dict[str, object]]:
    """Read allowlisted service states through root helper."""

    response = _exchange(
        {
            "action": "get-services",
        }
    )

    if response.get("ok") is not True:
        detail = response.get("detail")

        raise WebActionError(
            str(detail)
            if detail
            else "privileged service status read failed"
        )

    result = response.get("result")

    if not isinstance(result, dict):
        raise WebActionError(
            "privileged service result is invalid"
        )

    services = result.get("services")

    if not isinstance(services, list):
        raise WebActionError(
            "privileged service list is invalid"
        )

    if not all(
        isinstance(item, dict)
        for item in services
    ):
        raise WebActionError(
            "privileged service entries are invalid"
        )

    return services


def service_action_via_helper(
    unit: str,
    operation: str,
) -> dict[str, object]:
    """Execute one allowlisted systemd action."""

    response = _exchange(
        {
            "action": "service-action",
            "unit": unit,
            "operation": operation,
        }
    )

    if response.get("ok") is not True:
        detail = response.get("detail")

        raise WebActionError(
            str(detail)
            if detail
            else "privileged service action failed"
        )

    result = response.get("result")

    if not isinstance(result, dict):
        raise WebActionError(
            "privileged service result is invalid"
        )

    service = result.get("service")

    if not isinstance(service, dict):
        raise WebActionError(
            "privileged service state is invalid"
        )

    return service


def get_managed_services_via_helper(
) -> list[dict[str, object]]:
    """Read allowlisted service states through root helper."""

    response = _exchange(
        {
            "action": "get-services",
        }
    )

    if response.get("ok") is not True:
        detail = response.get("detail")

        raise WebActionError(
            str(detail)
            if detail
            else "privileged service status read failed"
        )

    result = response.get("result")

    if not isinstance(result, dict):
        raise WebActionError(
            "privileged service result is invalid"
        )

    services = result.get("services")

    if not isinstance(services, list):
        raise WebActionError(
            "privileged service list is invalid"
        )

    if not all(
        isinstance(item, dict)
        for item in services
    ):
        raise WebActionError(
            "privileged service entries are invalid"
        )

    return services


def service_action_via_helper(
    unit: str,
    operation: str,
) -> dict[str, object]:
    """Execute one allowlisted systemd action."""

    response = _exchange(
        {
            "action": "service-action",
            "unit": unit,
            "operation": operation,
        }
    )

    if response.get("ok") is not True:
        detail = response.get("detail")

        raise WebActionError(
            str(detail)
            if detail
            else "privileged service action failed"
        )

    result = response.get("result")

    if not isinstance(result, dict):
        raise WebActionError(
            "privileged service result is invalid"
        )

    service = result.get("service")

    if not isinstance(service, dict):
        raise WebActionError(
            "privileged service state is invalid"
        )

    return service


def get_firewall_runtime_via_helper(
) -> dict[str, object]:
    """Read sanitized nftables runtime through privileged helper."""

    response = _exchange(
        {
            "action": "get-firewall-runtime",
        }
    )

    if response.get("ok") is not True:
        detail = response.get("detail")

        raise WebActionError(
            str(detail)
            if detail
            else "privileged Firewall runtime read failed"
        )

    result = response.get("result")

    if not isinstance(result, dict):
        raise WebActionError(
            "privileged Firewall runtime result is invalid"
        )

    runtime = result.get("runtime")

    if not isinstance(runtime, dict):
        raise WebActionError(
            "privileged Firewall runtime payload is invalid"
        )

    return runtime
