from __future__ import annotations

import logging
import time
import uuid
from typing import Dict, Tuple

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

# ------------------------------------------------------------
# Logging (simple + review-friendly)
# ------------------------------------------------------------
logger = logging.getLogger("app")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )


# ------------------------------------------------------------
# Simple in-memory rate limiter (demo purpose)
# key = (client_ip, route) -> (window_start, count)
# ------------------------------------------------------------
WINDOW_SECONDS = 60
MAX_REQUESTS_PER_WINDOW = 60
_rate_state: Dict[Tuple[str, str], Tuple[float, int]] = {}


def _client_ip(request: Request) -> str:
    # If behind proxy/CDN, you may rely on X-Forwarded-For.
    # For demo we fallback to request.client.host
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def rate_limit(request: Request) -> None:
    ip = _client_ip(request)
    route = request.url.path
    key = (ip, route)

    now = time.time()
    window_start, count = _rate_state.get(key, (now, 0))

    # reset window
    if now - window_start >= WINDOW_SECONDS:
        window_start, count = now, 0

    count += 1
    _rate_state[key] = (window_start, count)

    if count > MAX_REQUESTS_PER_WINDOW:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please slow down.",
        )


# ------------------------------------------------------------
# Auth (demo token)
# ------------------------------------------------------------
bearer = HTTPBearer(auto_error=False)

DEMO_TOKEN = "demo-token-123"  # demo only


def require_auth(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
):
    if not creds or creds.scheme.lower() != "bearer" or creds.credentials != DEMO_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"user_id": "u_1001", "role": "viewer"}


# ------------------------------------------------------------
# Schemas (input validation)
# ------------------------------------------------------------
class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=6, max_length=128)


class EchoRequest(BaseModel):
    message: str = Field(min_length=1, max_length=500)


# ------------------------------------------------------------
# App
# ------------------------------------------------------------
app = FastAPI(
    title="Security Engineering Lab (AppSec)",
    version="0.2.0",
    docs_url="/docs",
    redoc_url="/redoc",
)


@app.middleware("http")
async def request_context_and_security_headers(request: Request, call_next):
    request_id = str(uuid.uuid4())
    start = time.time()

    # Attach request id for traceability
    request.state.request_id = request_id

    response = await call_next(request)

    # Basic security headers (demo)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Request-Id"] = request_id

    # Log request summary
    duration_ms = int((time.time() - start) * 1000)
    logger.info(
        "request_id=%s method=%s path=%s status=%s duration_ms=%s",
        request_id,
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    return response


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/auth/login")
def login(payload: LoginRequest, request: Request):
    # Rate limit per route
    rate_limit(request)

    # Demo only: accept a fixed user/pass pattern
    if payload.username != "demo" or payload.password != "password123":
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {
        "access_token": DEMO_TOKEN,
        "token_type": "bearer",
    }


@app.get("/me")
def me(request: Request, user=Depends(require_auth)):
    rate_limit(request)
    return {"user": user}


@app.post("/echo")
def echo(payload: EchoRequest, request: Request, user=Depends(require_auth)):
    rate_limit(request)
    # Safe response (no stack traces, no internal details)
    return {"echo": payload.message, "by": user["user_id"]}


# Helpful for local run (if you run it later on your PC)
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
