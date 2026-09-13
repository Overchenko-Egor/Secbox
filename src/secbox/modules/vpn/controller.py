"""Automatic VPN pool failover controller."""

from dataclasses import dataclass, field, replace
import json
from pathlib import Path

from secbox.modules.vpn.failover import (
    activate_tunnel,
    get_active_interface,
)
from secbox.modules.vpn.health import (
    VpnHealthStatus,
    VpnTunnelHealth,
    get_tunnel_health,
)
from secbox.modules.vpn.models import VpnConfig
from secbox.modules.vpn.selector import select_best_tunnel


DEFAULT_STATE_PATH = Path(
    "/var/lib/secbox/vpn-failover-state.json"
)


@dataclass
class TunnelCounters:
    failures: int = 0
    successes: int = 0


@dataclass
class ControllerState:
    active_interface: str | None = None
    counters: dict[str, TunnelCounters] = field(
        default_factory=dict
    )


@dataclass(frozen=True)
class ControllerResult:
    active_before: str | None
    active_after: str | None
    switched: bool
    reason: str
    health: dict[str, VpnTunnelHealth]


def load_state(path: Path = DEFAULT_STATE_PATH) -> ControllerState:
    if not path.exists():
        return ControllerState()

    data = json.loads(path.read_text())

    counters = {
        interface: TunnelCounters(**values)
        for interface, values in data.get("counters", {}).items()
    }

    return ControllerState(
        active_interface=data.get("active_interface"),
        counters=counters,
    )


def save_state(
    state: ControllerState,
    path: Path = DEFAULT_STATE_PATH,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "active_interface": state.active_interface,
        "counters": {
            interface: {
                "failures": value.failures,
                "successes": value.successes,
            }
            for interface, value in state.counters.items()
        },
    }

    path.write_text(json.dumps(data, indent=2) + "\n")


def _update_counters(
    state: ControllerState,
    health: dict[str, VpnTunnelHealth],
) -> None:
    for interface, snapshot in health.items():
        counters = state.counters.setdefault(
            interface,
            TunnelCounters(),
        )

        if snapshot.status == VpnHealthStatus.HEALTHY:
            counters.successes += 1
            counters.failures = 0
        else:
            counters.failures += 1
            counters.successes = 0


def evaluate_once(
    vpn: VpnConfig,
    *,
    state_path: Path = DEFAULT_STATE_PATH,
    failure_threshold: int = 3,
    recovery_threshold: int = 3,
) -> ControllerResult:
    enabled = [
        tunnel
        for tunnel in vpn.tunnels
        if tunnel.enabled
    ]

    health = {
        tunnel.interface: get_tunnel_health(tunnel)
        for tunnel in enabled
    }

    state = load_state(state_path)
    _update_counters(state, health)

    active_before = get_active_interface()
    active_after = active_before
    switched = False
    reason = "Active VPN tunnel remains unchanged"

    current = next(
        (
            tunnel
            for tunnel in enabled
            if tunnel.interface == active_before
        ),
        None,
    )

    if current is None:
        selection = select_best_tunnel(enabled, health)

        if selection.tunnel is not None:
            activate_tunnel(selection.tunnel)
            active_after = selection.tunnel.interface
            switched = active_after != active_before
            reason = selection.reason

    else:
        current_health = health[current.interface]
        counters = state.counters[current.interface]

        if (
            current_health.status != VpnHealthStatus.HEALTHY
            and counters.failures >= failure_threshold
        ):
            candidate_health = dict(health)

            candidate_health[current.interface] = replace(
                current_health,
                status=VpnHealthStatus.DOWN,
            )

            selection = select_best_tunnel(
                enabled,
                candidate_health,
            )

            if selection.tunnel is not None:
                activate_tunnel(selection.tunnel)
                active_after = selection.tunnel.interface
                switched = active_after != active_before
                reason = (
                    f"{current.name} failed "
                    f"{counters.failures} consecutive checks; "
                    f"{selection.reason}"
                )
            else:
                reason = "No usable backup VPN tunnel is available"

        elif current_health.status == VpnHealthStatus.HEALTHY:
            preferred = [
                tunnel
                for tunnel in enabled
                if tunnel.priority < current.priority
                and health[tunnel.interface].status
                == VpnHealthStatus.HEALTHY
                and state.counters[
                    tunnel.interface
                ].successes >= recovery_threshold
            ]

            if preferred:
                selected = min(
                    preferred,
                    key=lambda tunnel: tunnel.priority,
                )

                activate_tunnel(selected)
                active_after = selected.interface
                switched = active_after != active_before
                reason = (
                    f"Preferred tunnel {selected.name} "
                    "has recovered"
                )

    state.active_interface = active_after
    save_state(state, state_path)

    return ControllerResult(
        active_before=active_before,
        active_after=active_after,
        switched=switched,
        reason=reason,
        health=health,
    )
