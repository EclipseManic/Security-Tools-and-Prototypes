"""FastAPI application factory, middleware, and SPA hosting."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from api.auth import CSRF_HEADER, CSRF_VALUE
from api.errors import ApiError, envelope
from api.routes import health, router
from config import APP_NAME, APP_VERSION, BASE_DIR
from core.run_service import RunServiceError
from core.session_db import DB_PATH, SessionDB

API_PREFIX = "/api/v1"


def _status_code_for(exc: StarletteHTTPException) -> str:
    return {
        400: "bad_request",
        401: "unauthenticated",
        403: "forbidden",
        404: "not_found",
        405: "method_not_allowed",
        409: "conflict",
        422: "validation_error",
        429: "rate_limited",
        500: "internal_error",
        503: "unavailable",
    }.get(exc.status_code, "http_error")


def create_app(db_path: str | None = None) -> FastAPI:
    resolved_db = db_path or os.getenv("SOC_TRAINER_DB") or DB_PATH

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # Opening once migrates legacy databases and sets PRAGMA user_version;
        # later per-request connections skip the migration work.
        db = SessionDB(app.state.db_path)
        app.state.db_available = db.available
        db.close()
        yield

    app = FastAPI(
        title=APP_NAME,
        version=APP_VERSION,
        description="Local SOC incident-response trainer API.",
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    app.state.db_path = resolved_db
    app.state.db_available = False

    # ------------------------------------------------------------------ #
    # Errors — one envelope: {code, message, detail}
    # ------------------------------------------------------------------ #
    @app.exception_handler(ApiError)
    async def _api_error(_request: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=envelope(exc.code, exc.message, exc.detail),
        )

    @app.exception_handler(RunServiceError)
    async def _run_error(_request: Request, exc: RunServiceError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=envelope(exc.code, exc.message, exc.detail),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content=envelope(
                "validation_error",
                "Request validation failed.",
                exc.errors(),
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(
        _request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        message = exc.detail if isinstance(exc.detail, str) else "HTTP error"
        return JSONResponse(
            status_code=exc.status_code,
            content=envelope(_status_code_for(exc), message, exc.detail),
        )

    # ------------------------------------------------------------------ #
    # Middleware
    # ------------------------------------------------------------------ #
    if os.getenv("SOC_DEV_CORS", "0") == "1":
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[
                "http://localhost:5173",
                "http://127.0.0.1:5173",
            ],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        response = await call_next(request)
        path = request.url.path
        if path.startswith(("/api/docs", "/api/redoc")):
            # FastAPI's generated docs load Swagger UI from a CDN and bootstrap
            # it with an inline script, so this one page needs a relaxed policy.
            csp = (
                "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "img-src 'self' data: https://fastapi.tiangolo.com https://cdn.jsdelivr.net; "
                "font-src 'self' data:; connect-src 'self'; "
                "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
            )
        else:
            csp = (
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; "
                "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
            )
        response.headers.setdefault("Content-Security-Policy", csp)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    @app.middleware("http")
    async def _csrf_guard(request: Request, call_next):
        if (
            request.method in ("POST", "PUT", "PATCH", "DELETE")
            and request.url.path.startswith(API_PREFIX)
            and request.headers.get(CSRF_HEADER) != CSRF_VALUE
        ):
            return JSONResponse(
                status_code=403,
                content=envelope(
                    "csrf_required",
                    f"Mutating API requests require the {CSRF_HEADER} header.",
                ),
            )
        return await call_next(request)

    # ------------------------------------------------------------------ #
    # Routes
    # ------------------------------------------------------------------ #
    app.include_router(router, prefix=API_PREFIX)
    app.add_api_route("/health", health, methods=["GET"], include_in_schema=False)

    for path in ("/api", "/api/v1"):
        app.add_api_route(
            path,
            lambda: {
                "app": APP_NAME,
                "version": APP_VERSION,
                "docs": "/api/docs",
                "health": "/health",
            },
            methods=["GET"],
            include_in_schema=False,
        )

    # ------------------------------------------------------------------ #
    # SPA (production build). In dev, Vite proxies /api to this app.
    # ------------------------------------------------------------------ #
    dist = Path(
        os.getenv("SOC_WEB_DIST") or str(BASE_DIR / "web" / "dist")
    ).resolve()
    if dist.is_dir():
        assets = dist / "assets"
        if assets.is_dir():
            app.mount("/assets", StaticFiles(directory=str(assets)), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        async def _spa(path: str) -> FileResponse:
            if path.startswith(("api/", "health")):
                return JSONResponse(
                    status_code=404,
                    content=envelope("not_found", "Not found."),
                )
            target = (dist / path).resolve()
            if path and target.is_file() and dist in target.parents:
                return FileResponse(target)
            return FileResponse(dist / "index.html")
    else:

        @app.get("/", include_in_schema=False)
        async def _root() -> dict:
            return {
                "app": APP_NAME,
                "version": APP_VERSION,
                "api": API_PREFIX,
                "docs": "/api/docs",
                "ui": "not built — run `npm --prefix web install && npm --prefix web run build`",
            }

    return app


app = create_app()
