from collections import defaultdict, deque
from threading import Lock
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.exc import OperationalError

from app.api.routes import router
from app.core.config import settings
from app.ocr import MAX_IMAGE_BYTES, MAX_MULTIPART_OVERHEAD


class RequestGuardMiddleware(BaseHTTPMiddleware):
    """Simple per-process request limit and content-length guard; production needs edge limits too."""
    def __init__(self, app):
        super().__init__(app)
        self.events = defaultdict(deque)
        self.lock = Lock()

    async def dispatch(self, request: Request, call_next):
        try:
            size = int(request.headers.get("content-length", "0"))
        except ValueError:
            return JSONResponse({"detail":"Invalid content length"}, status_code=400)
        max_size = MAX_IMAGE_BYTES + MAX_MULTIPART_OVERHEAD if request.url.path == "/api/investigations/image" else 100_000
        if size > max_size:
            return JSONResponse({"detail":"Request body too large"}, status_code=413)
        client = request.client.host if request.client else "unknown"
        key = f"{client}:{request.url.path}"
        now = time.monotonic()
        limit = 8 if request.url.path.endswith(("/auth/login", "/auth/register")) else 60
        with self.lock:
            bucket = self.events[key]
            while bucket and now - bucket[0] > 60:
                bucket.popleft()
            if len(bucket) >= limit:
                return JSONResponse({"detail":"Rate limit exceeded"}, status_code=429)
            bucket.append(now)
        return await call_next(request)


class ImageUploadBodyLimitMiddleware:
    """Bound even chunked multipart uploads before Starlette spools them."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or scope.get("path") != "/api/investigations/image" or scope.get("method") != "POST":
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
                response = JSONResponse({"detail": "Image request exceeds the upload limit"}, status_code=413)
                await response(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        sent = False
        async def replay_receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, replay_receive, send)


app = FastAPI(title="ScamGuard Investigation API", version="0.1.0", description="Advisory scam investigation reports with explicit evidence provenance.")
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


@app.exception_handler(OperationalError)
async def database_unavailable_handler(_request: Request, _exc: OperationalError) -> JSONResponse:
    """Return a safe, actionable response when the database cannot be reached."""
    return JSONResponse(status_code=503, content={"detail": "Database unavailable"})


@app.get("/health")
def health() -> dict:
    return {"status":"available", "service":"api"}
