"""Launch the optional web interface without affecting CLI-only installs."""

from typing import Annotated

import typer

from secbox.web.settings import WebSettings

app = typer.Typer(help="Run the SecBox web interface.", no_args_is_help=True)


@app.command()
def serve(port: Annotated[int, typer.Option(min=1, max=65535)] = 8000) -> None:
    """Serve on 127.0.0.1; use an SSH tunnel for remote access."""
    try:
        settings = WebSettings.from_environment()
    except (OSError, ValueError) as error:
        typer.echo(f"Web settings error: {error}", err=True)
        raise typer.Exit(1) from error
    try:
        import uvicorn

        from secbox.web.app import create_app
    except ImportError as error:
        typer.echo('Install the web dependencies: pip install -e ".[web]"', err=True)
        raise typer.Exit(1) from error
    uvicorn.run(create_app(settings), host="127.0.0.1", port=port, proxy_headers=False)
