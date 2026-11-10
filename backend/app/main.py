import os
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from threading import Lock

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.admin_routes import router as admin_router
from app.api.routes import router
from app.core.config import settings
from app.core.security import hash_password
from app.db.session import SessionLocal
from app.ml.predictor import MessagePredictor
from app.models.entities import User
from app.ocr import MAX_IMAGE_BYTES, MAX_MULTIPART_OVERHEAD


def bootstrap_admin() -> None:
    """Create or promote the configured first administrator."""
    email = os.getenv("BOOTSTRAP_ADMIN_EMAIL", "").strip().lower()
    password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "")

    if not email and not password:
        return

    if not email or not password:
        raise RuntimeError(
            "Both BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD are required."
        )

    if not 12 <= len(password) <= 128:
        raise RuntimeError(
            "Bootstrap administrator password must be 12–128 characters."
        )

    with SessionLocal() as db:
        existing_admin = db.scalar(
            select(User.id).where(User.role == "admin").limit(1)
        )

        if existing_admin:
            return

        user = db.scalar(
            select(User).where(User.email == email)
        )

        if user is None:
            user = User(email=email)

        user.password_hash = hash_password(password)
        user.role = "admin"

        db.add(user)
        db.commit()


class RequestGuardMiddleware(BaseHTTPMiddleware):
    """Apply per-process request limits and content-length checks."""

    def __init__(self, app):
        super().__init__(app)
        self.events = defaultdict(deque)
        self.lock = Lock()

    async def dispatch(self, request: Request, call_next):
        try:
            size = int(request.headers.get("content-length", "0"))
        except ValueError:
            return JSONResponse(
                {"detail": "Invalid content length"},
                status_code=400,
            )

        max_size = (
            MAX_IMAGE_BYTES + MAX_MULTIPART_OVERHEAD
            if request.url.path == "/api/investigations/image"
            else 100_000
        )

        if size > max_size:
            return JSONResponse(
                {"detail": "Request body too large"},
                status_code=413,
            )

        client = request.client.host if request.client else "unknown"
        key = f"{client}:{request.url.path}"
        now = time.monotonic()

        limit = (
            8
            if request.url.path.endswith(
                ("/auth/login", "/auth/register")
            )
            else 60
        )

        with self.lock:
            bucket = self.events[key]

            while bucket and now - bucket[0] > 60:
                bucket.popleft()

            if len(bucket) >= limit:
                return JSONResponse(
                    {"detail": "Rate limit exceeded"},
                    status_code=429,
                )

            bucket.append(now)

        return await call_next(request)


class ImageUploadBodyLimitMiddleware:
    """Limit multipart image upload size, including chunked requests."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if (
            scope.get("type") != "http"
            or scope.get("path") != "/api/investigations/image"
            or scope.get("method") != "POST"
        ):
            await self.app(scope, receive, send)
            return

        body = bytearray()

        while True:
            message = await receive()

            if message["type"] == "http.disconnect":
                return

            if message["type"] != "http.request":
                continue

            body.extend(message.get("body", b""))

            if len(body) > MAX_IMAGE_BYTES + MAX_MULTIPART_OVERHEAD:
                response = JSONResponse(
                    {"detail": "Image request exceeds the upload limit"},
                    status_code=413,
                )
                await response(scope, receive, send)
                return

            if not message.get("more_body", False):
                break

        sent = False

        async def replay_receive():
            nonlocal sent

            if not sent:
                sent = True
                return {
                    "type": "http.request",
                    "body": bytes(body),
                    "more_body": False,
                }

            return {"type": "http.disconnect"}

        await self.app(scope, replay_receive, send)


@asynccontextmanager
async def lifespan(application: FastAPI):
    bootstrap_admin()

    application.state.message_predictor = MessagePredictor.load(
        settings.ml_model_path,
        expected_version=settings.ml_model_version,
        enabled=settings.ml_model_enabled,
    )

    yield


app = FastAPI(
    title="ScamGuard Investigation API",
    version="0.1.0",
    description="Advisory scam investigation reports with explicit evidence provenance.",
    lifespan=lifespan,
)

app.add_middleware(RequestGuardMiddleware)
app.add_middleware(ImageUploadBodyLimitMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
)

app.include_router(router)
app.include_router(admin_router)


@app.exception_handler(OperationalError)
async def database_unavailable_handler(
    _request: Request,
    _exc: OperationalError,
) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"detail": "Database unavailable"},
    )


@app.get("/health")
def health() -> dict:
    return {
        "status": "available",
        "service": "api",
    }