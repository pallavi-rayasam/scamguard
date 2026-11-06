from collections import defaultdict, deque
from threading import Lock
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.routes import router
from app.core.config import settings


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
        if size > 100_000:
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


app = FastAPI(title="ScamGuard Investigation API", version="0.1.0", description="Advisory scam investigation reports with explicit evidence provenance.")
app.add_middleware(RequestGuardMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
)
app.include_router(router)


@app.get("/health")
def health() -> dict:
    return {"status":"available", "service":"api"}
