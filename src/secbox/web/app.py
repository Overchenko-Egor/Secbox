"""Authenticated observations and configuration previews."""

import logging
import secrets
from pathlib import Path
from typing import Annotated, Any

import yaml
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from starlette.middleware.base import RequestResponseEndpoint
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from secbox.core.config_store import ConfigNotFoundError, ConfigStore, ConfigStoreError, ConfigValidationError
from secbox.core.models import SecBoxConfig
from secbox.core.version import __version__
from secbox.modules.dhcp.renderer import DhcpRenderError
from secbox.modules.dhcp.validator import DhcpPreflightError
from secbox.modules.firewall.renderer import FirewallRenderError
from secbox.modules.firewall.validator import FirewallPreflightError
from secbox.modules.network.discovery import NetworkDiscoveryError, discover_interfaces
from secbox.modules.network.renderer import NetworkRenderError
from secbox.modules.network.routes import NetworkRoute, RouteDiscoveryError, discover_ipv4_routes
from secbox.modules.network.state import NetworkInterfaceState
from secbox.modules.network.validator import NetworkPreflightError
from secbox.modules.vpn.runtime import (
    VpnEventStore,
    VpnRuntimeError,
    VpnRuntimeState,
    VpnRuntimeStore,
    VpnSwitchEvent,
)
from secbox.web.monitoring import ServiceStatus, SystemStatus, service_statuses, system_status
from secbox.web.preview import ConfigPreview, preview_config
from secbox.web.settings import WebSettings

logger = logging.getLogger(__name__)
MAX_BODY_BYTES = 1024 * 1024
STATIC_ROOT = Path(__file__).parent / "static"


class BodyLimitMiddleware:
    """Bound request bodies even without a Content-Length header."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > MAX_BODY_BYTES:
                await JSONResponse({"detail": "Request body exceeds 1 MiB"}, status_code=413)(scope, receive, send)
                return
            if not message.get("more_body", False):
                break
        delivered = False

        async def replay() -> Message:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


def create_app(settings: WebSettings | None = None) -> FastAPI:
    settings = settings or WebSettings.from_environment()
    store = ConfigStore(settings.config_path)
    vpn_runtime_store = VpnRuntimeStore()
    vpn_event_store = VpnEventStore()
    security = HTTPBasic(realm="SecBox")
    app = FastAPI(
        title="SecBox Management API", version=__version__,
        description="Read-only observations and configuration previews. No live configuration changes.",
        docs_url=None, redoc_url=None, openapi_url=None,
    )
    app.add_middleware(BodyLimitMiddleware)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])

    @app.middleware("http")
    async def response_headers(request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        )
        return response

    def require_auth(credentials: Annotated[HTTPBasicCredentials, Depends(security)]) -> None:
        username_ok = secrets.compare_digest(credentials.username.encode(), settings.username.encode())
        password_ok = secrets.compare_digest(credentials.password.encode(), settings.password.encode())
        if not (username_ok and password_ok):
            raise HTTPException(401, "Invalid credentials", headers={"WWW-Authenticate": 'Basic realm="SecBox"'})

    router = APIRouter(dependencies=[Depends(require_auth)])

    def load_config() -> SecBoxConfig:
        try:
            return store.load()
        except ConfigNotFoundError as error:
            raise HTTPException(404, "Configuration does not exist; initialize it using secboxctl config init") from error
        except ConfigValidationError as error:
            raise HTTPException(409, "Stored configuration is invalid; validate it using secboxctl config validate") from error
        except ConfigStoreError as error:
            logger.warning("Configuration read failed: %s", error)
            raise HTTPException(503, "Configuration is not readable by the web service") from error

    @app.get("/healthz", tags=["health"])
    def health() -> dict[str, str]:
        """Process liveness only, not firewall or IDS readiness."""
        return {"status": "ok"}

    @router.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(STATIC_ROOT / "index.html")

    @router.get("/assets/app.js", include_in_schema=False)
    def javascript() -> FileResponse:
        return FileResponse(STATIC_ROOT / "app.js", media_type="text/javascript")

    @router.get("/assets/style.css", include_in_schema=False)
    def stylesheet() -> FileResponse:
        return FileResponse(STATIC_ROOT / "style.css", media_type="text/css")

    @router.get("/api/v1/system", tags=["monitoring"])
    def system() -> SystemStatus:
        return system_status()

    @router.get("/api/v1/services", tags=["monitoring"])
    def services() -> list[ServiceStatus]:
        """Report systemd states, not whether a ruleset protects traffic."""
        return service_statuses()

    @router.get("/api/v1/vpn/status", tags=["vpn"])
    def vpn_status() -> VpnRuntimeState:
        """Return the latest VPN pool runtime snapshot."""
        try:
            state = vpn_runtime_store.load()
        except VpnRuntimeError as error:
            logger.warning(
                "VPN runtime state read failed: %s",
                error,
            )
            raise HTTPException(
                503,
                "VPN runtime state is not readable",
            ) from error

        if state is None:
            raise HTTPException(
                404,
                "VPN runtime state is not available yet",
            )

        return state

    @router.get("/api/v1/vpn/events", tags=["vpn"])
    def vpn_events(
        limit: Annotated[
            int,
            Query(ge=1, le=500),
        ] = 50,
    ) -> list[VpnSwitchEvent]:
        """Return recent VPN switch events, newest first."""
        try:
            return vpn_event_store.load_recent(
                limit=limit
            )
        except VpnRuntimeError as error:
            logger.warning(
                "VPN event history read failed: %s",
                error,
            )
            raise HTTPException(
                503,
                "VPN event history is not readable",
            ) from error

    @router.get("/api/v1/network/interfaces", tags=["network"])
    def interfaces() -> list[NetworkInterfaceState]:
        try:
            return discover_interfaces()
        except NetworkDiscoveryError as error:
            logger.warning("Interface discovery failed: %s", error)
            raise HTTPException(503, "Network interfaces could not be read") from error

    @router.get("/api/v1/network/routes", tags=["network"])
    def routes() -> list[NetworkRoute]:
        try:
            return discover_ipv4_routes()
        except RouteDiscoveryError as error:
            logger.warning("Route discovery failed: %s", error)
            raise HTTPException(503, "IPv4 routes could not be read") from error

    @router.get("/api/v1/config", tags=["configuration"])
    def configuration() -> SecBoxConfig:
        return load_config()

    @router.get("/api/v1/config/export", tags=["configuration"], response_class=Response)
    def export_configuration() -> Response:
        return Response(
            yaml.safe_dump(load_config().model_dump(mode="json"), sort_keys=False, allow_unicode=True),
            media_type="application/yaml",
            headers={"Content-Disposition": 'attachment; filename="secbox.yml"'},
        )

    @router.post("/api/v1/config/preview", tags=["configuration"])
    def preview(candidate: SecBoxConfig) -> ConfigPreview:
        """Check schema, live interfaces and cross-module constraints, then render in a temporary directory."""
        try:
            return preview_config(candidate, discover_interfaces())
        except NetworkDiscoveryError as error:
            raise HTTPException(503, "Cannot validate interface existence: network discovery unavailable") from error
        except (
            NetworkPreflightError, DhcpPreflightError, FirewallPreflightError,
            NetworkRenderError, DhcpRenderError, FirewallRenderError,
        ) as error:
            raise HTTPException(422, str(error)) from error
        except OSError as error:
            logger.warning("Preview generation failed: %s", error)
            raise HTTPException(503, "Could not generate configuration preview") from error

    @router.get("/api/v1/openapi.json", include_in_schema=False)
    def api_schema() -> dict[str, Any]:
        return app.openapi()

    app.include_router(router)
    return app
