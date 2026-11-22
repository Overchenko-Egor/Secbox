"""Authenticated observations and configuration previews."""

import logging
from pathlib import Path
from typing import Annotated, Any

import yaml
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
from pydantic import BaseModel
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from starlette.middleware.base import RequestResponseEndpoint
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from secbox.modules.network.validator import validate_management_interface
from secbox.modules.network.validator import validate_network_preflight
from secbox.modules.dhcp.validator import validate_dhcp_preflight
from secbox.modules.content_filter.validator import validate_content_filter_config
from secbox.modules.content_filter.models import ContentFilterConfig
from secbox.modules.vpn.validator import validate_l2_access_ports
from secbox.core.config_store import ConfigNotFoundError, ConfigStore, ConfigStoreError, ConfigValidationError
from secbox.core.models import SecBoxConfig
from secbox.core.version import __version__
from secbox.modules.dhcp.renderer import DhcpRenderError
from secbox.modules.dhcp.validator import DhcpPreflightError
from secbox.modules.firewall.renderer import FirewallRenderError
from secbox.modules.firewall.models import FirewallConfig
from secbox.modules.firewall.validator import (
    FirewallPreflightError,
    validate_firewall_preflight,
)
from secbox.modules.network.discovery import NetworkDiscoveryError, discover_interfaces
from secbox.modules.network.renderer import NetworkRenderError
from secbox.modules.network.routes import NetworkRoute, RouteDiscoveryError, discover_ipv4_routes
from secbox.modules.network.state import NetworkInterfaceState
from secbox.modules.network.runtime import (
    NetworkRuntimeError,
    NetworkRuntimeStore,
    NetworkStatus,
    build_network_status,
)
from secbox.modules.network.validator import NetworkPreflightError
from secbox.modules.vpn.runtime import (
    VpnEventStore,
    VpnRuntimeError,
    VpnRuntimeState,
    VpnRuntimeStore,
    VpnSwitchEvent,
)
from secbox.web.dashboard import DashboardResponse, build_dashboard
from secbox.web.monitoring import ServiceStatus, SystemStatus, service_statuses, system_status
from secbox.web.preview import ConfigPreview, preview_config
from secbox.web.actions import (
    WebActionBusyError,
    WebActionError,
    WebActionTimeoutError,
    apply_vpn_via_helper,
    get_vpn_via_helper,
    apply_network_dhcp_via_helper,
    get_network_dhcp_via_helper,
    get_dashboard_context_via_helper,
    get_content_filter_via_helper,
    apply_content_filter_via_helper,
    get_firewall_via_helper,
    apply_firewall_via_helper,
    get_firewall_runtime_via_helper,
)
from secbox.web.vpn_config import (
    VpnConfigPreviewRequest,
    VpnConfigPreviewResponse,
    VpnConfigApplyResponse,
    VpnConfigReadResponse,
    VpnValidationError,
    validate_vpn_candidate,
)
from secbox.web.network_dhcp_config import (
    NetworkDhcpApplyResponse,
    NetworkDhcpConfigPayload,
    NetworkDhcpConfigReadResponse,
    NetworkDhcpValidationResponse,
)
from secbox.web.settings import WebSettings
from secbox.web.auth import (
    SESSION_COOKIE,
    SESSION_TTL_SECONDS,
    AuthError,
    SessionSigner,
    UserConflictError,
    UserDeleteError,
    UserNotFoundError,
    UserStore,
    UserValidationError,
)

logger = logging.getLogger(__name__)
MAX_BODY_BYTES = 1024 * 1024
STATIC_ROOT = Path(__file__).parent / "static"


class LoginRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    password: str


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


from secbox.modules.ids.config import IdsConfig
from secbox.web.ids_actions import (
    IdsWebActionBusyError,
    IdsWebActionError,
    IdsWebActionTimeoutError,
    apply_ids_via_helper,
    get_ids_runtime_via_helper,
    get_ids_via_helper,
    validate_ids_via_helper,
)


from secbox.web.blackhole_api import (
    router as blackhole_api_router,
)


from secbox.web.system_api import (
    router as system_api_router,
)


from secbox.web.deception_api import (
    router as deception_api_router,
)




def create_app(settings: WebSettings | None = None) -> FastAPI:
    settings = settings or WebSettings.from_environment()
    store = ConfigStore(settings.config_path)
    vpn_runtime_store = VpnRuntimeStore()
    vpn_event_store = VpnEventStore()
    network_runtime_store = NetworkRuntimeStore()

    user_store = UserStore(
        settings.users_path
    )

    user_store.ensure_bootstrap(
        username=settings.username,
        password=settings.password,
    )

    session_signer = SessionSigner(
        settings.session_key_path
    )

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

    def current_user(
        request: Request,
    ):
        token = request.cookies.get(
            SESSION_COOKIE
        )

        if not token:
            return None

        parsed = session_signer.parse(
            token
        )

        if parsed is None:
            return None

        username, version = parsed

        return user_store.get_session_user(
            username,
            version,
        )

    def require_auth(
        request: Request,
    ):
        user = current_user(request)

        if user is not None:
            return user

        if request.url.path.startswith(
            "/api/"
        ):
            raise HTTPException(
                401,
                "Authentication required",
            )

        next_path = request.url.path

        if request.url.query:
            next_path += (
                "?"
                + request.url.query
            )

        from urllib.parse import quote

        raise HTTPException(
            303,
            "Authentication required",
            headers={
                "Location":
                    "/login?next="
                    + quote(
                        next_path,
                        safe="",
                    )
            },
        )

    router = APIRouter(
        dependencies=[
            Depends(require_auth)
        ]
    )

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

    @app.get(
        "/login",
        include_in_schema=False,
    )
    def login_page(
        request: Request,
    ):
        if current_user(request) is not None:
            return RedirectResponse(
                "/",
                status_code=303,
            )

        return FileResponse(
            STATIC_ROOT / "login.html"
        )

    @app.get(
        "/assets/login.css",
        include_in_schema=False,
    )
    def login_stylesheet():
        return FileResponse(
            STATIC_ROOT / "login.css",
            media_type="text/css",
        )

    @app.get(
        "/assets/login.js",
        include_in_schema=False,
    )
    def login_javascript():
        return FileResponse(
            STATIC_ROOT / "login.js",
            media_type="text/javascript",
        )

    @app.post(
        "/api/v1/auth/login",
        include_in_schema=False,
    )
    def login(
        payload: LoginRequest,
    ):
        authenticated = (
            user_store.authenticate(
                payload.username.strip(),
                payload.password,
            )
        )

        if authenticated is None:
            raise HTTPException(
                401,
                "Неверное имя пользователя или пароль.",
            )

        user, version = authenticated

        response = JSONResponse(
            {
                "ok": True,
                "username":
                    user.username,
                "role":
                    user.role,
            }
        )

        response.set_cookie(
            key=SESSION_COOKIE,
            value=session_signer.create(
                username=user.username,
                session_version=version,
            ),
            max_age=SESSION_TTL_SECONDS,
            httponly=True,
            secure=True,
            samesite="strict",
            path="/",
        )

        return response

    @app.post(
        "/api/v1/auth/logout",
        include_in_schema=False,
    )
    def logout():
        response = JSONResponse(
            {"ok": True}
        )

        response.delete_cookie(
            key=SESSION_COOKIE,
            path="/",
            secure=True,
            httponly=True,
            samesite="strict",
        )

        return response

    @app.get(
        "/api/v1/auth/me",
        include_in_schema=False,
    )
    def auth_me(
        request: Request,
    ):
        user = require_auth(
            request
        )

        return {
            "username":
                user.username,
            "role":
                user.role,
        }

    @router.get("/monitoring/network", include_in_schema=False)
    @router.get("/monitoring/vpn", include_in_schema=False)
    @router.get("/monitoring/firewall", include_in_schema=False)
    @router.get("/monitoring/ids", include_in_schema=False)
    @router.get("/monitoring/blackhole", include_in_schema=False)
    @router.get("/monitoring/deception", include_in_schema=False)
    @router.get("/monitoring/content-filter", include_in_schema=False)
    @router.get("/monitoring/services", include_in_schema=False)
    @router.get("/monitoring/system", include_in_schema=False)
    @router.get("/manage/network/interfaces", include_in_schema=False)
    @router.get("/manage/network/dhcp", include_in_schema=False)
    @router.get("/manage/vpn/l3", include_in_schema=False)
    @router.get("/manage/vpn/l2", include_in_schema=False)
    @router.get("/manage/firewall", include_in_schema=False)
    @router.get("/manage/ids", include_in_schema=False)
    @router.get("/manage/blackhole", include_in_schema=False)
    @router.get("/manage/content-filter", include_in_schema=False)
    @router.get("/manage/services", include_in_schema=False)
    @router.get("/manage/system", include_in_schema=False)
    @router.get("/", include_in_schema=False)
    @router.get("/network", include_in_schema=False)
    @router.get("/dhcp", include_in_schema=False)
    @router.get("/vpn", include_in_schema=False)
    @router.get("/firewall", include_in_schema=False)
    @router.get("/ids", include_in_schema=False)
    @router.get("/blackhole", include_in_schema=False)
    @router.get("/content-filter", include_in_schema=False)
    @router.get("/system", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(STATIC_ROOT / "index.html")

    @router.get("/assets/app.js", include_in_schema=False)
    def javascript() -> FileResponse:
        return FileResponse(STATIC_ROOT / "app.js", media_type="text/javascript")

    @router.get("/assets/deception.js", include_in_schema=False)
    def deception_javascript() -> FileResponse:
        return FileResponse(
            STATIC_ROOT / "deception.js",
            media_type="text/javascript",
        )

    @router.get("/assets/style.css", include_in_schema=False)
    def stylesheet() -> FileResponse:
        return FileResponse(STATIC_ROOT / "style.css", media_type="text/css")

    @router.get(
        "/manage/users",
        include_in_schema=False,
    )
    def users_page() -> FileResponse:
        return FileResponse(
            STATIC_ROOT / "users.html"
        )

    @router.get(
        "/assets/users.js",
        include_in_schema=False,
    )
    def users_javascript() -> FileResponse:
        return FileResponse(
            STATIC_ROOT / "users.js",
            media_type="text/javascript",
        )

    @router.get(
        "/api/v1/users",
        include_in_schema=False,
    )
    def users_list():
        return {
            "users":
                user_store.list_users()
        }

    @router.post(
        "/api/v1/users",
        include_in_schema=False,
    )
    def users_create(
        payload: CreateUserRequest,
    ):
        try:
            user = (
                user_store.create_user(
                    username=
                        payload.username,
                    password=
                        payload.password,
                )
            )

        except UserConflictError as error:
            raise HTTPException(
                409,
                str(error),
            ) from error

        except UserValidationError as error:
            raise HTTPException(
                422,
                str(error),
            ) from error

        return {
            "ok": True,
            "user": user,
        }

    @router.put(
        "/api/v1/users/{username}/password",
        include_in_schema=False,
    )
    def users_change_password(
        username: str,
        payload: ChangePasswordRequest,
    ):
        try:
            user_store.change_password(
                username=username,
                password=payload.password,
            )

        except UserNotFoundError as error:
            raise HTTPException(
                404,
                str(error),
            ) from error

        except UserValidationError as error:
            raise HTTPException(
                422,
                str(error),
            ) from error

        return {
            "ok": True,
        }

    @router.delete(
        "/api/v1/users/{username}",
        include_in_schema=False,
    )
    def users_delete(
        username: str,
        request: Request,
    ):
        user = require_auth(
            request
        )

        try:
            user_store.delete_user(
                username=username,
                current_username=
                    user.username,
            )

        except UserNotFoundError as error:
            raise HTTPException(
                404,
                str(error),
            ) from error

        except UserDeleteError as error:
            raise HTTPException(
                409,
                str(error),
            ) from error

        return {
            "ok": True,
        }


    @router.get(
        "/api/v1/dashboard",
        tags=["monitoring"],
        response_model=DashboardResponse,
    )
    def dashboard_status() -> DashboardResponse:
        """Return aggregated read-only operational status."""

        try:
            context = get_dashboard_context_via_helper()
        except WebActionError as error:
            logger.warning(
                "Dashboard privileged context unavailable: %s",
                error,
            )
            return build_dashboard()

        return build_dashboard(
            config=context.config,
            l2_handshakes=context.l2_handshakes,
            doh_feed=context.doh_feed,
        )

    @router.get(
        "/api/v1/content-filter/config",
        tags=["content-filter"],
    )
    def get_content_filter_config() -> dict[str, object]:
        try:
            config = get_content_filter_via_helper()
        except WebActionError as error:
            raise HTTPException(
                503,
                str(error),
            ) from error

        return {
            "content_filter": config.model_dump(
                mode="json"
            )
        }


    @router.post(
        "/api/v1/content-filter/config/validate",
        tags=["content-filter"],
    )
    def validate_content_filter_web(
        content_filter: ContentFilterConfig,
    ) -> dict[str, object]:
        try:
            context = get_dashboard_context_via_helper()

            candidate = context.config.model_copy(
                update={
                    "content_filter": content_filter,
                }
            )

            candidate = SecBoxConfig.model_validate(
                candidate.model_dump(
                    mode="json"
                )
            )

            validate_content_filter_config(
                candidate
            )

        except WebActionError as error:
            raise HTTPException(
                503,
                str(error),
            ) from error

        except Exception as error:
            raise HTTPException(
                422,
                str(error),
            ) from error

        return {
            "valid": True,
        }


    @router.post(
        "/api/v1/content-filter/config/apply",
        tags=["content-filter"],
    )
    def apply_content_filter_web(
        content_filter: ContentFilterConfig,
    ) -> dict[str, object]:
        try:
            result = apply_content_filter_via_helper(
                content_filter
            )

        except WebActionBusyError as error:
            raise HTTPException(
                409,
                str(error),
            ) from error

        except WebActionTimeoutError as error:
            raise HTTPException(
                504,
                str(error),
            ) from error

        except WebActionError as error:
            raise HTTPException(
                422,
                str(error),
            ) from error

        return {
            "enabled": result.enabled,
            "default_action": (
                result.default_action
            ),
            "blocked_domains": (
                result.blocked_domains
            ),
            "allowed_domains": (
                result.allowed_domains
            ),
            "doh_enabled": result.doh_enabled,
            "managed_feed_enabled": (
                result.managed_feed_enabled
            ),
        }


    @router.get(
        "/api/v1/ids/config",
        tags=["ids"],
    )
    def get_ids_web_config(
    ) -> dict[str, object]:
        try:
            ids = get_ids_via_helper()

        except IdsWebActionTimeoutError as error:
            raise HTTPException(
                504,
                "IDS configuration read timed out",
            ) from error

        except IdsWebActionError as error:
            raise HTTPException(
                503,
                str(error),
            ) from error

        return {
            "ids": ids.model_dump(
                mode="json"
            )
        }


    @router.get(
        "/api/v1/ids/runtime",
        tags=["ids"],
    )
    def get_ids_web_runtime(
    ) -> dict[str, object]:
        try:
            runtime = (
                get_ids_runtime_via_helper()
            )

        except IdsWebActionTimeoutError as error:
            raise HTTPException(
                504,
                "IDS runtime read timed out",
            ) from error

        except IdsWebActionError as error:
            raise HTTPException(
                503,
                str(error),
            ) from error

        return {
            "runtime": runtime,
        }


    @router.post(
        "/api/v1/ids/config/validate",
        tags=["ids"],
    )
    def validate_ids_web_config(
        ids: IdsConfig,
    ) -> dict[str, bool]:
        try:
            validate_ids_via_helper(
                ids
            )

        except IdsWebActionTimeoutError as error:
            raise HTTPException(
                504,
                str(error),
            ) from error

        except IdsWebActionError as error:
            raise HTTPException(
                422,
                str(error),
            ) from error

        return {
            "valid": True,
        }


    @router.post(
        "/api/v1/ids/config/apply",
        tags=["ids"],
    )
    def apply_ids_web_config(
        ids: IdsConfig,
    ) -> dict[str, object]:
        try:
            result = apply_ids_via_helper(
                ids
            )

        except IdsWebActionBusyError as error:
            raise HTTPException(
                409,
                str(error),
            ) from error

        except IdsWebActionTimeoutError as error:
            raise HTTPException(
                504,
                str(error),
            ) from error

        except IdsWebActionError as error:
            raise HTTPException(
                422,
                str(error),
            ) from error

        return {
            "enabled":
                result.enabled,
            "automatic_blackhole_enabled":
                result.automatic_blackhole_enabled,
            "automatic_blackhole_timeout":
                result.automatic_blackhole_timeout,
        }


    def _validate_firewall_candidate(
        firewall: FirewallConfig,
    ) -> None:
        if not firewall.enabled:
            raise HTTPException(
                422,
                "Disabling Firewall through Web UI is not supported",
            )

        if 8443 not in firewall.management_tcp_ports:
            raise HTTPException(
                422,
                "Management TCP port 8443 must remain allowed",
            )

        try:
            context = (
                get_dashboard_context_via_helper()
            )

            candidate = context.config.model_copy(
                update={
                    "firewall": firewall,
                }
            )

            candidate = SecBoxConfig.model_validate(
                candidate.model_dump(
                    mode="json"
                )
            )

            validate_firewall_preflight(
                candidate.firewall,
                candidate.network,
            )

            validate_content_filter_config(
                candidate
            )

        except HTTPException:
            raise

        except WebActionError as error:
            raise HTTPException(
                503,
                str(error),
            ) from error

        except Exception as error:
            raise HTTPException(
                422,
                str(error),
            ) from error


    @router.get(
        "/api/v1/firewall/config",
        tags=["firewall"],
    )
    def get_firewall_web_config(
    ) -> dict[str, object]:
        try:
            firewall = (
                get_firewall_via_helper()
            )

            context = (
                get_dashboard_context_via_helper()
            )

        except WebActionTimeoutError as error:
            raise HTTPException(
                504,
                "Firewall configuration read timed out",
            ) from error

        except WebActionError as error:
            raise HTTPException(
                503,
                str(error),
            ) from error

        interfaces = [
            {
                "name": interface.name,
                "role": interface.role,
                "enabled": (
                    interface.ipv4_method != "disabled"
                ),
            }
            for interface
            in context.config.network.interfaces
            if interface.role
            in {"wan", "lan", "mgmt"}
        ]

        return {
            "firewall": firewall.model_dump(
                mode="json"
            ),
            "interfaces": interfaces,
        }


    @router.get(
        "/api/v1/firewall/runtime",
        tags=["firewall"],
    )
    def get_firewall_web_runtime(
    ) -> dict[str, object]:
        try:
            runtime = (
                get_firewall_runtime_via_helper()
            )

        except WebActionTimeoutError as error:
            raise HTTPException(
                504,
                "Firewall runtime read timed out",
            ) from error

        except WebActionError as error:
            raise HTTPException(
                503,
                str(error),
            ) from error

        return {
            "runtime": runtime,
        }


    @router.post(
        "/api/v1/firewall/config/validate",
        tags=["firewall"],
    )
    def validate_firewall_web_config(
        firewall: FirewallConfig,
    ) -> dict[str, bool]:
        _validate_firewall_candidate(
            firewall
        )

        return {
            "valid": True,
        }


    @router.post(
        "/api/v1/firewall/config/apply",
        tags=["firewall"],
    )
    def apply_firewall_web_config(
        firewall: FirewallConfig,
    ) -> dict[str, object]:
        _validate_firewall_candidate(
            firewall
        )

        try:
            result = (
                apply_firewall_via_helper(
                    firewall
                )
            )

        except WebActionBusyError as error:
            raise HTTPException(
                409,
                str(error),
            ) from error

        except WebActionTimeoutError as error:
            raise HTTPException(
                504,
                str(error),
            ) from error

        except WebActionError as error:
            raise HTTPException(
                422,
                str(error),
            ) from error

        return {
            "enabled": result.enabled,
            "wan_interface": (
                result.wan_interface
            ),
            "lan_interface": (
                result.lan_interface
            ),
            "management_interface": (
                result.management_interface
            ),
            "nat_enabled": (
                result.nat_enabled
            ),
            "dynamic_blacklist_enabled": (
                result.dynamic_blacklist_enabled
            ),
        }


    @router.get("/api/v1/system", tags=["monitoring"])
    def system() -> SystemStatus:
        return system_status()

    @router.get("/api/v1/services", tags=["monitoring"])
    def services() -> list[ServiceStatus]:
        """Report systemd states, not whether a ruleset protects traffic."""
        return service_statuses()

    @router.post(
        "/api/v1/vpn/config/validate",
        tags=["vpn"],
    )
    def validate_vpn_web_config(
        request: VpnConfigPreviewRequest,
    ) -> VpnConfigPreviewResponse:
        """Validate VPN configuration without changing persistent state."""

        try:
            metadata = network_runtime_store.load()
        except NetworkRuntimeError as error:
            logger.warning(
                "Network runtime metadata read failed during VPN validation: %s",
                error,
            )
            raise HTTPException(
                503,
                "Network runtime metadata is not readable",
            ) from error

        if metadata is None:
            raise HTTPException(
                409,
                "Network configuration must be applied before VPN validation",
            )

        physical_interfaces = {
            interface.name
            for interface in metadata.interfaces
        }

        try:
            return validate_vpn_candidate(
                request.vpn,
                physical_interfaces,
            )
        except VpnValidationError as error:
            raise HTTPException(
                422,
                str(error),
            ) from error

    @router.get(
        "/api/v1/vpn/config",
        tags=["vpn"],
    )
    def get_vpn_web_config() -> VpnConfigReadResponse:
        """Return editable VPN configuration without secret key contents."""

        try:
            vpn = get_vpn_via_helper()

        except WebActionTimeoutError as error:
            raise HTTPException(
                504,
                "VPN configuration read timed out",
            ) from error

        except WebActionError as error:
            logger.error(
                "Privileged VPN configuration read failed"
            )
            raise HTTPException(
                503,
                "VPN configuration is temporarily unavailable",
            ) from error

        return VpnConfigReadResponse(
            vpn=vpn
        )


    @router.put(
        "/api/v1/vpn/config",
        tags=["vpn"],
    )
    def apply_vpn_web_config(
        request: VpnConfigPreviewRequest,
    ) -> VpnConfigApplyResponse:
        """Validate and transactionally apply VPN configuration."""

        try:
            metadata = network_runtime_store.load()
        except NetworkRuntimeError as error:
            logger.warning(
                "Network runtime metadata read failed during VPN apply: %s",
                error,
            )
            raise HTTPException(
                503,
                "Network runtime metadata is not readable",
            ) from error

        if metadata is None:
            raise HTTPException(
                409,
                "Network configuration must be applied before VPN changes",
            )

        physical_interfaces = {
            interface.name
            for interface in metadata.interfaces
        }

        try:
            validate_vpn_candidate(
                request.vpn,
                physical_interfaces,
            )

        except VpnValidationError as error:
            raise HTTPException(
                422,
                str(error),
            ) from error

        try:
            result = apply_vpn_via_helper(
                request.vpn
            )

        except WebActionBusyError as error:
            raise HTTPException(
                409,
                "Another configuration change is already running",
            ) from error

        except WebActionTimeoutError as error:
            logger.error(
                "Privileged VPN action timed out"
            )
            raise HTTPException(
                504,
                "VPN configuration action timed out",
            ) from error

        except WebActionError as error:
            logger.error(
                "Privileged VPN action failed"
            )
            raise HTTPException(
                500,
                "VPN configuration could not be applied",
            ) from error

        return VpnConfigApplyResponse(
            applied=True,
            applied_tunnels=result.applied_tunnels,
            removed_tunnels=result.removed_tunnels,
            active_name=result.active_name,
            active_interface=result.active_interface,
        )

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


    @router.get(
        "/api/v1/services/managed",
        tags=["services"],
    )
    def managed_services_get() -> dict[str, object]:
        """Return strict allowlist of manageable services."""

        from secbox.web.actions import (
            WebActionError,
            WebActionTimeoutError,
            get_managed_services_via_helper,
        )

        try:
            services = (
                get_managed_services_via_helper()
            )

        except WebActionTimeoutError as error:
            raise HTTPException(
                504,
                "Service status helper timed out",
            ) from error

        except WebActionError as error:
            raise HTTPException(
                503,
                str(error),
            ) from error

        return {
            "services": services,
        }


    @router.post(
        "/api/v1/services/action",
        tags=["services"],
    )
    def managed_service_action(
        payload: dict[str, str],
    ) -> dict[str, object]:
        """Perform one strictly allowlisted service operation."""

        from secbox.web.actions import (
            WebActionError,
            WebActionTimeoutError,
            service_action_via_helper,
        )

        if set(payload) != {
            "unit",
            "operation",
        }:
            raise HTTPException(
                422,
                "Expected unit and operation",
            )

        unit = payload.get(
            "unit",
            "",
        ).strip()

        operation = payload.get(
            "operation",
            "",
        ).strip()

        if not unit or not operation:
            raise HTTPException(
                422,
                "unit and operation are required",
            )

        try:
            service = service_action_via_helper(
                unit,
                operation,
            )

        except WebActionTimeoutError as error:
            raise HTTPException(
                504,
                "Service action timed out",
            ) from error

        except WebActionError as error:
            raise HTTPException(
                422,
                str(error),
            ) from error

        return {
            "ok": True,
            "service": service,
        }


    @router.get(
        "/api/v1/network/config",
        response_model=NetworkDhcpConfigReadResponse,
        tags=["network"],
    )
    def network_config_get() -> NetworkDhcpConfigReadResponse:
        """Return editable Network and DHCP desired state."""

        try:
            network, dhcp = get_network_dhcp_via_helper()

        except WebActionTimeoutError as error:
            raise HTTPException(
                504,
                "Network/DHCP configuration read timed out",
            ) from error

        except WebActionError as error:
            raise HTTPException(
                503,
                "Network/DHCP configuration could not be read",
            ) from error

        return NetworkDhcpConfigReadResponse(
            network=network,
            dhcp=dhcp,
        )


    @router.post(
        "/api/v1/network/config/validate",
        response_model=NetworkDhcpValidationResponse,
        tags=["network"],
    )
    def network_config_validate(
        payload: NetworkDhcpConfigPayload,
    ) -> NetworkDhcpValidationResponse:
        """Validate Network/DHCP without changing runtime state."""

        try:
            # The Web service deliberately cannot read
            # /etc/secbox/config.yml directly.
            #
            # Read the current Network/DHCP state through the
            # privileged helper instead.
            current_network, current_dhcp = (
                get_network_dhcp_via_helper()
            )

            # The submitted payload has already passed the
            # strict Pydantic Network/DHCP models.
            #
            # Runtime/cross-module validation that requires the
            # complete SecBox configuration is performed again
            # by the privileged action during Apply.
            runtime_interfaces = discover_interfaces()

            validate_network_preflight(
                payload.network,
                runtime_interfaces,
            )

            validate_management_interface(
                payload.network,
                runtime_interfaces,
            )

            # Make sure the helper result itself remains
            # parseable and available. It is intentionally
            # fetched above rather than reading config.yml.
            _ = current_network, current_dhcp

        except WebActionTimeoutError as error:
            raise HTTPException(
                504,
                "Network/DHCP validation helper timed out",
            ) from error

        except WebActionError as error:
            raise HTTPException(
                503,
                "Network/DHCP configuration could not be read",
            ) from error

        except (
            NetworkDiscoveryError,
            NetworkPreflightError,
            ValueError,
        ) as error:
            raise HTTPException(
                422,
                str(error),
            ) from error

        return NetworkDhcpValidationResponse(
            valid=True
        )


    @router.put(
        "/api/v1/network/config",
        response_model=NetworkDhcpApplyResponse,
        tags=["network"],
    )
    def network_config_apply(
        payload: NetworkDhcpConfigPayload,
    ) -> NetworkDhcpApplyResponse:
        """Validate and transactionally apply Network + DHCP."""

        # Always run the same unprivileged validation first.
        network_config_validate(payload)

        try:
            result = apply_network_dhcp_via_helper(
                payload.network,
                payload.dhcp,
            )

        except WebActionBusyError as error:
            raise HTTPException(
                409,
                "Another configuration action is running",
            ) from error

        except WebActionTimeoutError as error:
            raise HTTPException(
                504,
                "Network/DHCP configuration action timed out",
            ) from error

        except WebActionError as error:
            raise HTTPException(
                500,
                "Network/DHCP configuration action failed",
            ) from error

        return NetworkDhcpApplyResponse(
            ok=True,
            interfaces=result.interfaces,
            dhcp_scopes=result.dhcp_scopes,
            enabled_dhcp_scopes=result.enabled_dhcp_scopes,
        )


    @router.get("/api/v1/network/status", tags=["network"])
    def network_status() -> NetworkStatus:
        """Return live status of SecBox-managed network interfaces."""
        try:
            metadata = network_runtime_store.load()
        except NetworkRuntimeError as error:
            logger.warning(
                "Network runtime metadata read failed: %s",
                error,
            )
            raise HTTPException(
                503,
                "Network runtime metadata is not readable",
            ) from error

        if metadata is None:
            raise HTTPException(
                404,
                "Network runtime metadata is not available yet",
            )

        try:
            runtime_interfaces = discover_interfaces()
        except NetworkDiscoveryError as error:
            logger.warning(
                "Interface discovery failed: %s",
                error,
            )
            raise HTTPException(
                503,
                "Network interfaces could not be read",
            ) from error

        return build_network_status(
            metadata,
            runtime_interfaces,
        )

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

    router.include_router(
        blackhole_api_router
    )

    router.include_router(
        system_api_router
    )


    router.include_router(
        deception_api_router
    )

    app.include_router(router)
    return app
