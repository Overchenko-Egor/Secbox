"""Command-line interface for SecBox."""

from pathlib import Path
from typing import NoReturn, Any

import typer
import yaml
from secbox.modules.content_filter.doh_feed.resolver import (
    resolve_effective_doh_addresses,
)
from secbox.modules.content_filter.doh_feed.store import (
    DohFeedStore,
    DohFeedStoreError,
)
from secbox.modules.content_filter.doh_feed.service import (
    DohFeedServiceError,
    reconcile_managed_resolvers,
    refresh_managed_resolvers,
)
from secbox.modules.network.models import NetworkConfig
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from secbox.core.config_store import (
    ConfigBackupNotFoundError,
    ConfigNotFoundError,
    ConfigStore,
    ConfigStoreError,
)
from secbox.core.models import SystemConfig
from secbox.core.paths import get_config_path
from secbox.core.version import __version__
from secbox.web.cli import app as web_app
from secbox.modules.network.discovery import (
    NetworkDiscoveryError,
    discover_manageable_interfaces,
)

from secbox.modules.network.validator import (
    NetworkPreflightError,
    validate_management_interface,
    validate_network_preflight,
)
from secbox.modules.network.renderer import (
    NetworkRenderError,
    render_networkd,
)
from secbox.modules.network.executor import (
    NetworkApplyError,
    apply_networkd_config,
)
from secbox.modules.network.runtime import (
    NetworkRuntimeError,
    NetworkRuntimeStore,
    metadata_from_config,
)
from secbox.modules.dhcp.renderer import (
    DhcpRenderError,
    render_dnsmasq_config,
)
from secbox.modules.content_filter.validator import (
    ContentFilterValidationError,
    validate_content_filter_config,
)

from secbox.modules.dhcp.validator import (
    DhcpPreflightError,
    validate_dhcp_preflight,
)
from secbox.modules.dhcp.executor import (
    DhcpApplyError,
    apply_dnsmasq_config,
)
from secbox.modules.firewall.renderer import (
    FirewallRenderError,
    render_nftables_config,
)
from secbox.modules.firewall.validator import (
    FirewallPreflightError,
    validate_firewall_preflight,
)
from secbox.modules.firewall.executor import (
    FirewallApplyError,
    apply_firewall_config,
)
from secbox.modules.firewall.sysctl import (
    ForwardingError,
    set_ipv4_forwarding,
)

from secbox.modules.vpn.renderer import (
    VpnRenderError,
    render_wireguard_config,
)
from secbox.modules.vpn.routing import (
    VpnRoutingError,
    configure_pool_policy,
)
from secbox.modules.vpn.failover import (
    VpnFailoverError,
    activate_tunnel,
)
from secbox.modules.vpn.validator import (
    VpnValidationError,
    validate_vpn_config,
    validate_vpn_key_paths,
)
from secbox.modules.vpn.executor import (
    VpnApplyError,
    apply_wireguard_tunnel,
)
from secbox.modules.vpn.health import get_tunnel_health
from secbox.modules.vpn.controller import evaluate_once
from secbox.modules.vpn.daemon import (
    VpnDaemon,
    VpnDaemonError,
    install_signal_handlers as install_vpn_signal_handlers,
)
from secbox.modules.vpn.state import (
    VpnStateError,
    get_wireguard_status,
)
from secbox.modules.vpn.firewall import (
    get_vpn_firewall_interfaces,
)
from secbox.modules.vpn.service import (
    VpnServiceError,
    apply_vpn_config,
)

from secbox.modules.blacklist.service import (
    BlacklistError,
    add_blacklist_entry,
    delete_blacklist_entry,
    list_blacklist_entries,
    list_blacklist_state,
    reconcile_blacklist,
)

from secbox.modules.ids.processor import (
    IdsProcessorError,
    process_eve_file,
)

from secbox.modules.network.discovery import (
    discover_interfaces,
)

import logging
from threading import Event

from secbox.modules.ids.daemon import (
    IdsDaemon,
    IdsDaemonError,
    install_signal_handlers,
    log_policy_decision,
)
from secbox.modules.ids.runtime import (
    build_ids_response_handler,
    refresh_ids_runtime_state,
)
from secbox.modules.ids.reader import EveTailReader
from secbox.modules.ids.worker import (
    IdsWorkerError,
    StreamingIdsWorker,
)
from secbox.modules.ids.policy import (
    PolicyDecision,
)

from secbox.modules.ids.response import (
    IdsResponseError,
)



def _load_doh_managed_state(config):
    """Load managed DoH state when the feed is enabled."""

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


app = typer.Typer(
    name="secboxctl",
    help="SecBox management utility.",
    no_args_is_help=True,
)

config_app = typer.Typer(
    name="config",
    help="Manage the SecBox configuration.",
    no_args_is_help=True,
)

network_app = typer.Typer(
    name="network",
    help="Manage SecBox network configuration.",
    no_args_is_help=True,
)

dhcp_app = typer.Typer(
    name="dhcp",
    help="Manage SecBox DHCP configuration.",
    no_args_is_help=True,
)

firewall_app = typer.Typer(
    name="firewall",
    help="Manage SecBox firewall configuration.",
    no_args_is_help=True,
)

blacklist_app = typer.Typer(
    name="blacklist",
    help="Manage SecBox dynamic blacklist.",
    no_args_is_help=True,
)

ids_app = typer.Typer(
    help="Suricata IDS analysis commands."
)

content_filter_app = typer.Typer(
    help="Manage SecBox content filtering.",
    no_args_is_help=True,
)

doh_feed_app = typer.Typer(
    help="Manage the managed DoH resolver feed.",
    no_args_is_help=True,
)

vpn_app = typer.Typer(
    help="Manage SecBox VPN tunnels.",
    no_args_is_help=True,
)

app.add_typer(firewall_app, name="firewall")
app.add_typer(network_app, name="network")
app.add_typer(config_app, name="config")
app.add_typer(dhcp_app, name="dhcp")
app.add_typer(blacklist_app, name="blacklist",)
app.add_typer(ids_app, name="ids",)
app.add_typer(web_app, name="web")
app.add_typer(vpn_app, name="vpn")

content_filter_app.add_typer(
    doh_feed_app,
    name="doh-feed",
)
app.add_typer(
    content_filter_app,
    name="content-filter",
)


console = Console()
error_console = Console(stderr=True)


def _store() -> ConfigStore:
    return ConfigStore(get_config_path())


def _fail(message: str, exit_code: int = 1) -> NoReturn:
    error_console.print(f"[bold red]Error:[/bold red] {message}")
    raise typer.Exit(code=exit_code)


@app.command()
def version() -> None:
    """Display the SecBox version."""
    console.print(__version__)


@config_app.command("path")
def config_path() -> None:
    """Display the active configuration path."""
    console.print(get_config_path())


@config_app.command("init")
def config_init(
    force: bool = typer.Option(
        False,
        "--force",
        help="Replace an existing configuration with the defaults.",
    ),
) -> None:
    """Create the default SecBox configuration."""
    store = _store()

    if store.config_path.exists() and not force:
        _fail(
            f"configuration already exists: {store.config_path}. "
            "Use --force to replace it."
        )

    config = store.create_default()

    console.print(
        f"[green]Created configuration:[/green] {store.config_path}"
    )
    console.print(
        yaml.safe_dump(
            config.model_dump(mode="json"),
            sort_keys=False,
            allow_unicode=True,
        ).rstrip()
    )


@config_app.command("show")
def config_show() -> None:
    """Display the current validated configuration."""
    store = _store()

    try:
        config = store.load()
    except ConfigStoreError as error:
        _fail(str(error))

    console.print(
        yaml.safe_dump(
            config.model_dump(mode="json"),
            sort_keys=False,
            allow_unicode=True,
        ).rstrip()
    )


@config_app.command("validate")
def config_validate(
    path: Path | None = typer.Argument(
        None,
        exists=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
        help="Optional YAML file to validate instead of the active configuration.",
    ),
) -> None:
    """Validate a SecBox YAML configuration."""
    store = ConfigStore(path) if path is not None else _store()

    try:
        store.load()
    except ConfigStoreError as error:
        _fail(str(error))

    console.print(f"[green]Configuration is valid:[/green] {store.config_path}")


@config_app.command("set-hostname")
def config_set_hostname(
    hostname: str = typer.Argument(
        ...,
        help="New hostname using letters, digits and hyphens.",
    ),
) -> None:
    """Set the configured SecBox hostname."""
    store = _store()

    try:
        current_config = store.load()
        updated_system = SystemConfig(hostname=hostname)
        updated_config = current_config.model_copy(
            update={"system": updated_system}
        )
        store.save(updated_config)

    except ConfigNotFoundError:
        _fail("configuration is not initialized; run 'secboxctl config init'")

    except (ConfigStoreError, ValidationError) as error:
        _fail(str(error))

    console.print(
        f"[green]Hostname updated:[/green] {updated_config.system.hostname}"
    )


@config_app.command("rollback")
def config_rollback() -> None:
    """Restore the most recent configuration backup."""
    store = _store()

    try:
        restored = store.rollback()
    except ConfigBackupNotFoundError:
        _fail("no configuration backup is available")
    except ConfigStoreError as error:
        _fail(str(error))

    console.print("[green]Configuration restored from backup.[/green]")
    console.print(
        yaml.safe_dump(
            restored.model_dump(mode="json"),
            sort_keys=False,
            allow_unicode=True,
        ).rstrip()
    )

@network_app.command("show")
def network_show() -> None:
    """Display the validated network configuration."""
    store = _store()

    try:
        config = store.load()
    except ConfigStoreError as error:
        _fail(str(error))

    console.print(
        yaml.safe_dump(
            config.network.model_dump(mode="json"),
            sort_keys=False,
            allow_unicode=True,
        ).rstrip()
    )


@network_app.command("load")
def network_load(
    path: Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
        help="YAML file containing a network section or network model.",
    ),
) -> None:
    """Validate and import a network configuration from YAML."""
    store = _store()

    try:
        raw_data: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        _fail(f"failed to read network configuration: {error}")

    if not isinstance(raw_data, dict):
        _fail("network configuration root must be a YAML mapping")

    network_data = raw_data.get("network", raw_data)

    if not isinstance(network_data, dict):
        _fail("network section must be a YAML mapping")

    try:
        network_config = NetworkConfig.model_validate(network_data)
        current_config = store.load()
        updated_config = current_config.model_copy(
            update={"network": network_config}
        )
        store.save(updated_config)
    except ConfigNotFoundError:
        _fail("configuration is not initialized; run 'secboxctl config init'")
    except (ConfigStoreError, ValidationError) as error:
        _fail(str(error))

    console.print(
        f"[green]Network configuration imported:[/green] {path}"
    )

@network_app.command("interfaces")
def network_interfaces() -> None:
    """Display detected network interfaces."""

    try:
        interfaces = discover_manageable_interfaces()
    except NetworkDiscoveryError as error:
        _fail(str(error))

    if not interfaces:
        console.print("No manageable network interfaces found.")
        return

    for interface in interfaces:
        console.print(f"[bold]{interface.name}[/bold]")
        console.print(f"  MAC:       {interface.mac or '-'}")
        console.print(f"  State:     {interface.operstate}")
        console.print(f"  MTU:       {interface.mtu}")

        if interface.addresses:
            console.print("  Addresses:")

            for address in interface.addresses:
                console.print(
                    f"    {address.family}: "
                    f"{address.address}/{address.prefixlen}"
                )
        else:
            console.print("  Addresses: -")

@network_app.command("check")
def network_check() -> None:
    """Validate network configuration against the current system."""

    store = _store()

    try:
        config = store.load()
        runtime_interfaces = discover_manageable_interfaces()

        validate_network_preflight(
            config.network,
            runtime_interfaces,
        )

        validate_management_interface(
            config.network,
            runtime_interfaces,
        )

    except (
        ConfigStoreError,
        NetworkDiscoveryError,
        NetworkPreflightError,
    ) as error:
        _fail(str(error))

    console.print(
        "[green]Network configuration passed preflight checks.[/green]"
    )

@network_app.command("render")
def network_render(
    output_dir: Path = typer.Option(
        Path("/tmp/secbox-render"),
        "--output-dir",
        "-o",
        help="Directory where rendered networkd files will be written.",
    ),
) -> None:
    """Render network configuration without applying it."""

    store = _store()

    try:
        config = store.load()
        runtime_interfaces = discover_manageable_interfaces()

        validate_network_preflight(
            config.network,
            runtime_interfaces,
        )

        validate_management_interface(
            config.network,
            runtime_interfaces,
        )

        files = render_networkd(
            config.network,
            output_dir,
        )

    except (
        ConfigStoreError,
        NetworkDiscoveryError,
        NetworkPreflightError,
        NetworkRenderError,
        OSError,
    ) as error:
        _fail(str(error))

    console.print(
        f"[green]Rendered network configuration:[/green] {output_dir}"
    )

    for file_path in files:
        console.print(f"  {file_path}")


@network_app.command("apply")
def network_apply() -> None:
    """Apply the validated network configuration."""

    store = _store()

    try:
        config = store.load()
        runtime_interfaces = discover_manageable_interfaces()

        validate_network_preflight(
            config.network,
            runtime_interfaces,
        )

        validate_management_interface(
            config.network,
            runtime_interfaces,
        )

        apply_networkd_config(
            config=config.network,
            staging_dir=Path("/run/secbox/network-stage"),
            target_dir=Path("/etc/systemd/network"),
            backup_dir=Path("/var/lib/secbox/network-backup"),
        )

        NetworkRuntimeStore().save(
            metadata_from_config(config.network)
        )

    except (
        ConfigStoreError,
        NetworkDiscoveryError,
        NetworkPreflightError,
        NetworkApplyError,
        NetworkRuntimeError,
        OSError,
    ) as error:
        _fail(str(error))

    console.print(
        "[green]Network configuration applied successfully.[/green]"
    )


@dhcp_app.command("render")
def dhcp_render(
    output_path: Path = typer.Option(
        Path("/tmp/secbox-dhcp.conf"),
        "--output",
        "-o",
    ),
) -> None:
    """Render dnsmasq DHCP configuration without applying it."""

    store = _store()

    try:
        config = store.load()

        validate_dhcp_preflight(
            config.dhcp,
            config.network,
        )

        validate_content_filter_config(config)

        rendered = render_dnsmasq_config(
            config.dhcp,
            output_path,
            content_filter=config.content_filter,
        )

    except (
        ConfigStoreError,
        DhcpPreflightError,
        ContentFilterValidationError,
        DhcpRenderError,
        OSError,
    ) as error:
        _fail(str(error))

    console.print(
        f"[green]Rendered DHCP configuration:[/green] {rendered}"
    )

@dhcp_app.command("apply")
def dhcp_apply() -> None:
    """Render and apply SecBox DHCP configuration."""

    store = _store()

    rendered_file = Path("/run/secbox/secbox-dhcp.conf")

    try:
        config = store.load()

        validate_dhcp_preflight(
            config.dhcp,
            config.network,
        )

        validate_content_filter_config(config)

        render_dnsmasq_config(
            config.dhcp,
            rendered_file,
            content_filter=config.content_filter,
        )

        apply_dnsmasq_config(
            rendered_file=rendered_file,
            target_file=Path("/etc/dnsmasq.d/secbox-dhcp.conf"),
            backup_file=Path("/var/lib/secbox/dhcp/secbox-dhcp.conf.bak"),
        )

    except (
        ConfigStoreError,
        DhcpPreflightError,
        ContentFilterValidationError,
        DhcpRenderError,
        DhcpApplyError,
        OSError,
    ) as error:
        _fail(str(error))

    console.print(
        "[green]DHCP configuration applied successfully.[/green]"
    )


@vpn_app.command("check")
def vpn_check() -> None:
    """Validate SecBox VPN configuration."""

    try:
        config = _store().load()

        if config.vpn is None:
            _fail("VPN configuration is not defined")

        validate_vpn_config(config)

    except (
        ConfigStoreError,
        VpnValidationError,
    ) as error:
        _fail(str(error))

    console.print(
        "[green]VPN configuration is valid.[/green]"
    )


@vpn_app.command("render")
def vpn_render(
    output_dir: Path = typer.Option(
        Path("/tmp/secbox-vpn"),
        "--output-dir",
        "-o",
    ),
) -> None:
    """Render enabled VPN tunnels without applying them."""

    try:
        config = _store().load()

        if config.vpn is None:
            _fail("VPN configuration is not defined")

        validate_vpn_config(config)

        if not config.vpn.enabled:
            _fail("VPN is disabled")

        rendered_count = 0

        for tunnel in config.vpn.tunnels:
            if not tunnel.enabled:
                continue

            output = output_dir / f"{tunnel.interface}.conf"

            render_wireguard_config(
                tunnel,
                output,
            )

            console.print(
                f"[green]Rendered:[/green] {output}"
            )

            rendered_count += 1

        console.print(
            f"[green]Rendered VPN tunnels:[/green] {rendered_count}"
        )

    except (
        ConfigStoreError,
        VpnValidationError,
        VpnRenderError,
        OSError,
    ) as error:
        _fail(str(error))


@vpn_app.command("apply")
def vpn_apply() -> None:
    """Apply enabled SecBox VPN tunnels."""

    try:
        config = _store().load()
        result = apply_vpn_config(config)

    except (
        ConfigStoreError,
        VpnValidationError,
        VpnApplyError,
        VpnRoutingError,
        VpnFailoverError,
        VpnServiceError,
        OSError,
    ) as error:
        _fail(str(error))

    console.print(
        f"[green]Active VPN tunnel:[/green] "
        f"{result.active_name} ({result.active_interface})"
    )

    console.print(
        f"[green]Applied VPN tunnels:[/green] "
        f"{result.applied_tunnels}"
    )



@vpn_app.command("run")
def vpn_run(
    interval: float = typer.Option(
        3.0,
        "--interval",
        min=0.5,
        help="Seconds between VPN health evaluations.",
    ),
) -> None:
    """Run continuous automatic VPN failover."""

    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s "
            "%(levelname)s "
            "%(name)s: "
            "%(message)s"
        ),
    )

    try:
        config = _store().load()

        if config.vpn is None or not config.vpn.enabled:
            _fail("VPN is not enabled")

        validate_vpn_config(config)

        daemon = VpnDaemon(
            config.vpn,
            state_path=Path(
                "/var/lib/secbox/vpn-failover-state.json"
            ),
            interval=interval,
        )

        stop_event = Event()

        install_vpn_signal_handlers(
            stop_event
        )

        console.print(
            "[green]SecBox VPN daemon started[/green] "
            f"(interval={interval}s)"
        )

        daemon.run(
            stop_event
        )

        stats = daemon.stats()

        console.print(
            "[yellow]SecBox VPN daemon stopped[/yellow] "
            f"iterations={stats.iterations}, "
            f"switches={stats.switches}"
        )

    except (
        ConfigStoreError,
        VpnValidationError,
        VpnDaemonError,
        OSError,
    ) as error:
        _fail(str(error))


@vpn_app.command("evaluate")
def vpn_evaluate() -> None:
    """Run one automatic VPN failover evaluation."""

    try:
        config = _store().load()

        if config.vpn is None or not config.vpn.enabled:
            _fail("VPN is not enabled")

        result = evaluate_once(config.vpn)

        console.print(
            f"Active: {result.active_before} -> "
            f"{result.active_after}"
        )
        console.print(f"Switched: {result.switched}")
        console.print(f"Reason: {result.reason}")

    except (ConfigStoreError, OSError) as error:
        _fail(str(error))


@vpn_app.command("status")
def vpn_status() -> None:
    """Show WireGuard runtime state."""

    try:
        config = _store().load()

        if config.vpn is None:
            _fail("VPN configuration is not defined")

        for tunnel in config.vpn.tunnels:
            console.print(
                f"[bold]{tunnel.name} "
                f"({tunnel.interface})[/bold]"
            )

            try:
                status = get_wireguard_status(
                    tunnel.interface
                )
            except VpnStateError:
                console.print(
                    "[yellow]not active[/yellow]"
                )
                continue

            console.print(status or "active")

    except ConfigStoreError as error:
        _fail(str(error))



@vpn_app.command("health")
def vpn_health() -> None:
    """Show evaluated VPN tunnel health."""

    try:
        config = _store().load()

        if config.vpn is None:
            _fail("VPN configuration is not defined")

        for tunnel in config.vpn.tunnels:
            result = get_tunnel_health(tunnel)

            console.print(
                f"[bold]{result.name} "
                f"({result.interface})[/bold]"
            )
            console.print(
                f"Status: {result.status.value.upper()}"
            )
            console.print(
                f"Peer: "
                f"{'present' if result.peer_present else 'missing'}"
            )

            handshake = (
                f"{result.handshake_age_seconds}s ago"
                if result.handshake_age_seconds is not None
                else "never"
            )
            console.print(f"Handshake: {handshake}")

            probe = (
                "OK"
                if result.probe_ok is True
                else "FAILED"
                if result.probe_ok is False
                else "disabled"
            )
            console.print(f"Probe: {probe}")

            if result.latency_ms is not None:
                console.print(
                    f"Latency: {result.latency_ms:.1f} ms"
                )

            console.print(
                f"RX/TX: {result.rx_bytes} / "
                f"{result.tx_bytes} bytes"
            )
            console.print(f"Reason: {result.reason}")
            console.print()

    except ConfigStoreError as error:
        _fail(str(error))


@firewall_app.command("render")
def firewall_render(
    output_path: Path = typer.Option(
        Path("/tmp/secbox-firewall.nft"),
        "--output",
        "-o",
    ),
) -> None:
    """Render nftables ruleset without applying it."""

    store = _store()

    try:
        config = store.load()

        if config.firewall is None:
            _fail("firewall configuration is not defined")

        validate_firewall_preflight(
            config.firewall,
            config.network,
        )

        validate_content_filter_config(config)

        dns_enforcement = (
            config.content_filter is not None
            and config.content_filter.enabled
            and config.content_filter.dns.enabled
        )

        block_dot = (
            config.content_filter is not None
            and config.content_filter.enabled
            and config.content_filter.encrypted_dns.block_dot
        )

        block_doq = (
            config.content_filter is not None
            and config.content_filter.enabled
            and config.content_filter.encrypted_dns.block_doq
        )

        doh_managed_state = (
            _load_doh_managed_state(config)
        )

        doh_resolver_addresses = (
            resolve_effective_doh_addresses(
                config.content_filter,
                doh_managed_state,
            )
        )

        enable_doh_set = (
            config.content_filter is not None
            and config.content_filter.enabled
            and config.content_filter.encrypted_dns.doh.enabled
        )

        rendered = render_nftables_config(
            config.firewall,
            output_path,
            enforce_lan_dns=dns_enforcement,
            block_dot=block_dot,
            block_doq=block_doq,
            enable_doh_set=enable_doh_set,
            doh_resolver_addresses=doh_resolver_addresses,
            vpn_interfaces=get_vpn_firewall_interfaces(config.vpn),
        )

    except (
        ConfigStoreError,
        FirewallPreflightError,
        ContentFilterValidationError,
        FirewallRenderError,
        OSError,
    ) as error:
        _fail(str(error))

    console.print(
        f"[green]Rendered firewall configuration:[/green] {rendered}"
    )

@firewall_app.command("apply")
def firewall_apply() -> None:
    """Render and apply SecBox firewall configuration."""

    store = _store()

    rendered_file = Path("/run/secbox/secbox-firewall.nft")

    try:
        config = store.load()

        if config.firewall is None:
            _fail("firewall configuration is not defined")

        validate_firewall_preflight(
            config.firewall,
            config.network,
        )

        validate_content_filter_config(config)

        dns_enforcement = (
            config.content_filter is not None
            and config.content_filter.enabled
            and config.content_filter.dns.enabled
        )

        block_dot = (
            config.content_filter is not None
            and config.content_filter.enabled
            and config.content_filter.encrypted_dns.block_dot
        )

        block_doq = (
            config.content_filter is not None
            and config.content_filter.enabled
            and config.content_filter.encrypted_dns.block_doq
        )

        doh_managed_state = (
            _load_doh_managed_state(config)
        )

        doh_resolver_addresses = (
            resolve_effective_doh_addresses(
                config.content_filter,
                doh_managed_state,
            )
        )

        enable_doh_set = (
            config.content_filter is not None
            and config.content_filter.enabled
            and config.content_filter.encrypted_dns.doh.enabled
        )

        render_nftables_config(
            config.firewall,
            rendered_file,
            enforce_lan_dns=dns_enforcement,
            block_dot=block_dot,
            block_doq=block_doq,
            enable_doh_set=enable_doh_set,
            doh_resolver_addresses=doh_resolver_addresses,
            vpn_interfaces=get_vpn_firewall_interfaces(config.vpn),
        )

        apply_firewall_config(
            rendered_file=rendered_file,
            target_file=Path("/etc/secbox/nftables.conf"),
            backup_file=Path("/var/lib/secbox/firewall/nftables.conf.bak"),
        )
        set_ipv4_forwarding(
            config.firewall.enable_ipv4_forwarding
        )

        try:
            restored_count, expired_count = reconcile_blacklist()
        except BlacklistError as error:
            console.print(
                "[yellow]Firewall applied, but blacklist reconciliation failed: "
                f"{error}[/yellow]"
            )
        else:
            console.print(
                "[green]Blacklist reconciled.[/green] "
                f"Restored: {restored_count}, "
                f"expired removed: {expired_count}"
            )

    except (
        ConfigStoreError,
        FirewallPreflightError,
        ContentFilterValidationError,
        FirewallRenderError,
        FirewallApplyError,
        OSError,
        ForwardingError,
    ) as error:
        _fail(str(error))

    console.print(
        "[green]Firewall configuration applied successfully.[/green]"
    )




@doh_feed_app.command("update")
def doh_feed_update() -> None:
    """Download and apply the managed DoH resolver feed."""

    try:
        config = _store().load()
    except ConfigStoreError as error:
        _fail(str(error))

    content_filter = config.content_filter

    if content_filter is None:
        _fail("content filter configuration is not present")

    try:
        state = refresh_managed_resolvers(
            content_filter=content_filter,
        )
    except DohFeedServiceError as error:
        _fail(str(error))

    console.print(
        "[green]Managed DoH feed updated.[/green]"
    )
    console.print(
        f"Managed addresses: {len(state.addresses)}"
    )

    if state.updated_at is not None:
        console.print(
            f"Updated at: {state.updated_at.isoformat()}"
        )



@doh_feed_app.command("reconcile")
def doh_feed_reconcile() -> None:
    """Restore the effective DoH resolver nftables set."""

    try:
        config = _store().load()
    except ConfigStoreError as error:
        _fail(str(error))

    content_filter = config.content_filter

    if content_filter is None:
        _fail("content filter configuration is not present")

    try:
        state = reconcile_managed_resolvers(
            content_filter=content_filter,
        )
    except DohFeedServiceError as error:
        _fail(str(error))

    effective_addresses = (
        resolve_effective_doh_addresses(
            content_filter,
            state,
        )
    )

    console.print(
        "[green]Managed DoH state reconciled.[/green]"
    )
    console.print(
        f"Managed addresses: {len(state.addresses)}"
    )
    console.print(
        f"Effective addresses: "
        f"{len(effective_addresses)}"
    )


@doh_feed_app.command("status")
def doh_feed_status() -> None:
    """Display managed DoH feed status."""

    try:
        config = _store().load()
    except ConfigStoreError as error:
        _fail(str(error))

    content_filter = config.content_filter

    if content_filter is None:
        _fail("content filter configuration is not present")

    doh = content_filter.encrypted_dns.doh

    try:
        managed_state = DohFeedStore().load()
    except DohFeedStoreError as error:
        _fail(
            f"failed to load managed DoH state: {error}"
        )

    effective_addresses = resolve_effective_doh_addresses(
        content_filter,
        (
            managed_state
            if doh.managed_feed_enabled
            else None
        ),
    )

    table = Table(
        title="Managed DoH Feed Status"
    )

    table.add_column("Property")
    table.add_column("Value")

    table.add_row(
        "Content filter",
        "enabled" if content_filter.enabled else "disabled",
    )
    table.add_row(
        "DoH filtering",
        "enabled" if doh.enabled else "disabled",
    )
    table.add_row(
        "Managed feed",
        "enabled" if doh.managed_feed_enabled else "disabled",
    )
    table.add_row(
        "Feed URL",
        doh.managed_feed_url or "-",
    )
    table.add_row(
        "Last update",
        (
            managed_state.updated_at.isoformat()
            if managed_state.updated_at is not None
            else "-"
        ),
    )
    table.add_row(
        "Manual addresses",
        (
            ", ".join(
                str(address)
                for address in doh.resolver_addresses
            )
            or "-"
        ),
    )
    table.add_row(
        "Managed addresses",
        (
            ", ".join(
                str(address)
                for address in managed_state.addresses
            )
            or "-"
        ),
    )
    table.add_row(
        "Effective addresses",
        (
            ", ".join(
                str(address)
                for address in effective_addresses
            )
            or "-"
        ),
    )

    console.print(table)


@blacklist_app.command("add")
def blacklist_add(
    address: str = typer.Argument(
        ...,
        help="IPv4 address to block.",
    ),
    timeout: str = typer.Option(
        "1h",
        "--timeout",
        "-t",
        help="Blacklist timeout, for example 10m, 1h or 1d.",
    ),
    reason: str = typer.Option(
        "manual",
        "--reason",
        "-r",
        help="Reason for blocking the address.",
    ),
) -> None:
    """Add an IPv4 address to the dynamic blacklist."""

    try:
        config = _store().load()

        protected_networks: list[str] = []

        if config.firewall is not None:
            protected_networks = (
                config.firewall.dynamic_blacklist_protected_networks
            )

        add_blacklist_entry(
            address=address,
            timeout=timeout,
            reason=reason,
            source="cli",
            protected_networks=protected_networks,
        )

    except (
        ConfigStoreError,
        BlacklistError,
    ) as error:
        _fail(str(error))

    console.print(
        f"[green]Blacklisted:[/green] {address} "
        f"(timeout: {timeout}, reason: {reason})"
    )


@blacklist_app.command("del")
def blacklist_delete(
    address: str = typer.Argument(
        ...,
        help="IPv4 address to remove.",
    ),
) -> None:
    """Remove an IPv4 address from the dynamic blacklist."""

    try:
        delete_blacklist_entry(address)
    except BlacklistError as error:
        _fail(str(error))

    console.print(
        f"[green]Removed from blacklist:[/green] {address}"
    )

@blacklist_app.command("list")
def blacklist_list() -> None:
    """Display current dynamic blacklist entries."""

    try:
        nft_entries = set(
            list_blacklist_entries()
        )

        state_entries = list_blacklist_state()

    except BlacklistError as error:
        _fail(str(error))

    if not nft_entries:
        console.print(
            "[yellow]Blacklist is empty.[/yellow]"
        )
        return

    for entry in state_entries:
        if entry.address not in nft_entries:
            continue

        console.print(
            f"{entry.address} "
            f"reason={entry.reason} "
            f"source={entry.source} "
            f"expires={entry.expires_at.isoformat()}"
        )


@blacklist_app.command("reconcile")
def blacklist_reconcile() -> None:
    """Synchronize persistent blacklist state with nftables."""

    try:
        restored_count, expired_count = reconcile_blacklist()
    except BlacklistError as error:
        _fail(str(error))

    console.print(
        "[green]Blacklist reconciled.[/green] "
        f"Restored: {restored_count}, "
        f"expired removed: {expired_count}"
    )


@ids_app.command("analyze")
def ids_analyze() -> None:
    """Analyze the current Suricata EVE log."""

    store = _store()

    try:
        config = store.load()
    except Exception as error:
        console.print(
            "[red]Failed to load SecBox configuration:[/red] "
            f"{error}"
        )
        raise typer.Exit(code=1) from error

    if not config.ids.enabled:
        console.print(
            "[yellow]IDS is disabled in configuration.[/yellow]"
        )
        raise typer.Exit(code=0)

    try:
        runtime_interfaces = (
            discover_interfaces()
        )

        result = process_eve_file(
            config,
            runtime_interfaces,
        )

    except IdsProcessorError as error:
        console.print(
            "[red]IDS analysis failed:[/red] "
            f"{error}"
        )
        raise typer.Exit(code=1) from error

    console.print()
    console.print(
        "[bold]SecBox IDS Analysis[/bold]"
    )
    console.print()

    console.print(
        f"Observations: "
        f"{result.observation_count}"
    )

    console.print(
        f"Logical alerts: "
        f"{result.logical_alert_count}"
    )

    console.print(
        f"Detections: "
        f"{result.detection_count}"
    )

    console.print(
        f"Decisions: "
        f"{result.decision_count}"
    )

    console.print(
        f"Parse errors: "
        f"{result.parse_error_count}"
    )

    console.print(
        f"Classification errors: "
        f"{result.classification_error_count}"
    )

    console.print()

    if not result.decisions:
        console.print(
            "[green]No IDS detections found.[/green]"
        )
        return

    table = Table(
        title="IDS Policy Decisions"
    )

    table.add_column(
        "Action"
    )

    table.add_column(
        "Source"
    )

    table.add_column(
        "Destination"
    )

    table.add_column(
        "SID"
    )

    table.add_column(
        "Severity"
    )

    table.add_column(
        "Count"
    )

    table.add_column(
        "Signature"
    )

    table.add_column(
        "Reason"
    )

    for decision in result.decisions:
        detection = decision.detection

        table.add_row(
            decision.action.value.upper(),
            detection.source_ip,
            detection.destination_ip,
            str(detection.signature_id),
            str(detection.severity),
            str(detection.count),
            detection.signature,
            decision.reason,
        )

    console.print(
        table
    )


@ids_app.command("run")
def ids_run() -> None:
    """Run the continuous Suricata IDS processing daemon."""

    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s "
            "%(levelname)s "
            "%(name)s: "
            "%(message)s"
        ),
    )

    try:
        config = _store().load()

        if not config.ids.enabled:
            console.print(
                "IDS is disabled in configuration."
            )
            raise typer.Exit(
                code=0
            )

        runtime_interfaces = (
            discover_interfaces()
        )

        worker = StreamingIdsWorker(
            config,
            runtime_interfaces,
        )

        response_handler = (
            build_ids_response_handler(
                config,
                runtime_interfaces,
            )
        )

        reader = EveTailReader(
            config.ids.eve_path,
            poll_interval=0.05,
            start_at_end=True,
        )


        def handle_decision(
            decision: PolicyDecision,
        ) -> None:
            log_policy_decision(
                decision
            )

            try:
                response_handler.handle(
                    decision
                )

            except IdsResponseError as error:
                logging.getLogger(
                    __name__
                ).error(
                    (
                        "IDS response failed; "
                        "continuing event processing: %s"
                    ),
                    error,
                )


        def refresh_runtime() -> None:
            try:
                refreshed_interfaces = (
                    discover_interfaces()
                )

                refresh_ids_runtime_state(
                    config,
                    refreshed_interfaces,
                    worker,
                    response_handler,
                )

            except Exception as error:
                logging.getLogger(
                    __name__
                ).warning(
                    (
                        "IDS runtime network "
                        "refresh failed; "
                        "keeping previous state: %s"
                    ),
                    error,
                )

        daemon = IdsDaemon(
            reader,
            worker,
            decision_handler=handle_decision,
            runtime_refresh_handler=(
                refresh_runtime
            ),
            runtime_refresh_interval=5.0,
        )

        stop_event = Event()

        install_signal_handlers(
            stop_event
        )

        console.print(
            "SecBox IDS daemon started."
        )

        console.print(
            f"EVE log: "
            f"{config.ids.eve_path}"
        )

        daemon.run(
            stop_event
        )

        daemon_stats = (
            daemon.stats()
        )

        worker_stats = (
            worker.stats()
        )

        console.print(
            "SecBox IDS daemon stopped."
        )

        console.print(
            (
                "Runtime: "
                f"lines={daemon_stats.lines_read}, "
                f"decisions="
                f"{daemon_stats.decisions_emitted}, "
                f"reader_resets="
                f"{daemon_stats.reader_resets}"
            )
        )

        console.print(
            (
                "Worker: "
                f"alerts="
                f"{worker_stats.parsed_alerts}, "
                f"logical_alerts="
                f"{worker_stats.logical_alerts}, "
                f"detections="
                f"{worker_stats.detections}, "
                f"parse_errors="
                f"{worker_stats.parse_errors}, "
                f"classification_errors="
                f"{worker_stats.classification_errors}"
            )
        )

    except (
        IdsDaemonError,
        IdsWorkerError,
        IdsResponseError,
    ) as error:
        console.print(
            f"[red]IDS daemon failed:[/red] "
            f"{error}"
        )

        raise typer.Exit(
            code=1
        ) from error
