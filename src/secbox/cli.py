"""Command-line interface for SecBox."""

from pathlib import Path
from typing import NoReturn, Any

import typer
import yaml
from secbox.modules.network.models import NetworkConfig
from pydantic import ValidationError
from rich.console import Console

from secbox.core.config_store import (
    ConfigBackupNotFoundError,
    ConfigNotFoundError,
    ConfigStore,
    ConfigStoreError,
)
from secbox.core.models import SystemConfig
from secbox.core.paths import get_config_path
from secbox.core.version import __version__
from secbox.modules.network.discovery import (
    NetworkDiscoveryError,
    discover_manageable_interfaces,
)

from secbox.modules.network.validator import (
    NetworkPreflightError,
    validate_management_interface,
    validate_network_preflight,
)




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

app.add_typer(network_app, name="network")
app.add_typer(config_app, name="config")

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
