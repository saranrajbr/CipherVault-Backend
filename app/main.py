"""CipherForge FastAPI application.

Layering, outermost first:

    HTTP routes (app.api) -> validation (app.schemas) -> services
    (app.encoding, app.crypto, app.hashing) -> `cryptography` and `bcrypt`

This module wires the application together and installs the exception handlers
that turn service errors into structured JSON. It contains no cryptographic
logic, and it never logs request bodies, keys or passwords.
"""

from __future__ import annotations

import logging
import os

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__
from .api import algorithms as algorithms_router
from .api import encode as encode_router
from .api import encryption as encryption_router
from .api import hash as hash_router
from .errors import CipherForgeError
from .schemas.crypto import ErrorResponse, HealthResponse

logger = logging.getLogger("cipherforge")

_DEFAULT_ORIGINS = (
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
)

DESCRIPTION = """
CipherForge is an educational cryptography toolkit.

**Encode** Base64 and hexadecimal transport encodings.
**Encryption** AES-256-GCM, ChaCha20-Poly1305, RSA-2048 OAEP, Caesar and DES (disabled).
**Hash** MD5, SHA-256, SHA-512 and bcrypt.

All primitives come from `cryptography` and `bcrypt`. CipherForge implements no
cryptography of its own, uses `secrets` for every key, nonce and token, and
never logs keys or passwords.
"""


def _cors_origins() -> list[str]:
    """Return the allowed browser origins.

    The Vite dev server origin is allowed by default. ``CORS_ORIGINS`` overrides
    the list for deployments, comma separated.

    Returns:
        List of allowed origins.
    """
    configured = os.getenv("CORS_ORIGINS")
    if not configured:
        return list(_DEFAULT_ORIGINS)
    return [origin.strip() for origin in configured.split(",") if origin.strip()]


def _error_response(status_code: int, code: str, message: str) -> JSONResponse:
    """Build the standard error envelope.

    Args:
        status_code: HTTP status to send.
        code: Stable machine readable error code.
        message: User-safe message. Never contains stack traces or paths.

    Returns:
        A JSONResponse carrying the structured error body.
    """
    return JSONResponse(
        status_code=status_code,
        content=ErrorResponse(error={"code": code, "message": message}).model_dump(),
    )


def _summarise_validation_errors(exc: RequestValidationError) -> str:
    """Turn Pydantic error objects into one readable sentence.

    Args:
        exc: The validation error raised by FastAPI.

    Returns:
        A short message naming the offending fields. No payload values are
        echoed back, so passwords and key material cannot leak through an
        error message.
    """
    parts: list[str] = []
    for error in exc.errors():
        location = ".".join(str(item) for item in error.get("loc", ()) if item != "body")
        message = error.get("msg", "invalid value")
        parts.append(f"{location or 'request body'}: {message}")
    if not parts:
        return "The request body failed validation."
    return "Request validation failed. " + "; ".join(parts)


def create_app() -> FastAPI:
    """Build and configure the FastAPI application.

    Returns:
        The configured application instance.
    """
    application = FastAPI(
        title="CipherForge API",
        description=DESCRIPTION,
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

    @application.exception_handler(CipherForgeError)
    async def handle_cipherforge_error(_: Request, exc: CipherForgeError) -> JSONResponse:
        """Convert a service error into structured JSON.

        Only the code and the curated message are returned. The traceback is
        logged at debug level and never serialised to the client.
        """
        logger.debug("CipherForge service error: %s", exc.code)
        return _error_response(exc.status_code, exc.code, exc.message)

    @application.exception_handler(RequestValidationError)
    async def handle_validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        """Return HTTP 400 with a readable summary for schema violations."""
        return _error_response(
            status.HTTP_400_BAD_REQUEST,
            "INVALID_INPUT",
            _summarise_validation_errors(exc),
        )

    @application.exception_handler(StarletteHTTPException)
    async def handle_http_exception(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        """Return the same envelope for 404 and other HTTP level failures."""
        detail = exc.detail if isinstance(exc.detail, str) else "Request could not be processed."
        return _error_response(exc.status_code, "HTTP_ERROR", detail)

    @application.exception_handler(Exception)
    async def handle_unexpected_error(_: Request, exc: Exception) -> JSONResponse:
        """Return an opaque 500 so internals are never exposed."""
        logger.error("Unhandled error while processing a request: %s", type(exc).__name__)
        return _error_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "An unexpected internal error occurred. Please try again.",
        )

    @application.get(
        "/api/health",
        response_model=HealthResponse,
        status_code=status.HTTP_200_OK,
        summary="Service health check",
        tags=["system"],
    )
    def health() -> HealthResponse:
        """Report service status and version."""
        return HealthResponse(version=__version__)

    application.include_router(encode_router.router, prefix="/api")
    application.include_router(encryption_router.router, prefix="/api")
    application.include_router(hash_router.router, prefix="/api")
    application.include_router(algorithms_router.router, prefix="/api")

    return application


app = create_app()