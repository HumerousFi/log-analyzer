from dotenv import load_dotenv

load_dotenv()

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException as StarletteHTTPException

import account
import auth
import billing
from auth import APP_BASE_URL, COOKIE_SECURE, SECRET_KEY, get_current_user, require_active_subscription
from db import User, get_db, init_db
from models import LogAnalysisResponse
from parser import analyze_log_content

app = FastAPI(title="Security Log Analyzer")

# The analyzer is CPU-bound and reads the whole upload into memory - cap it so
# one large file can't tie up a worker thread indefinitely or exhaust memory.
MAX_UPLOAD_BYTES = 20 * 1024 * 1024  # 20 MB

# Locked down site-wide - no inline/external scripts, no framing, no cross-
# origin fetches. style-src needs 'unsafe-inline' for the few inline
# style="" attributes in templates (e.g. the landing hero mockup); that's a
# much narrower risk than allowing inline/unsafe scripts, which stay
# disallowed everywhere.
CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)

# /billing/checkout is the one page that has to embed Razorpay's Checkout.js
# widget, and live-testing showed it needs real relaxation, not just source
# allowlisting: script-src additionally needs 'unsafe-eval' and
# 'unsafe-inline' - without them, Checkout.js loads and its iframe/DOM get
# built, but the modal silently stays display:none forever (no console
# error, no exception - it just never shows), which strongly suggests it
# uses eval()/new Function() or inline event handlers internally. It also
# needs the full *.razorpay.com wildcard on script/connect/img/frame-src
# (a risk-detection bundle loads from cdn.razorpay.com, telemetry posts to
# lumberjack.razorpay.com). Everything NOT confirmed necessary - clickjacking
# protection (frame-ancestors, X-Frame-Options) and Permissions-Policy -
# stays on, even on this page: those were only removed transiently while
# bisecting the actual cause and neither one turned out to matter, so don't
# assume they need to go too if this policy ever needs adjusting again.
CHECKOUT_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-eval' 'unsafe-inline' https://*.razorpay.com; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src https://fonts.gstatic.com; "
    "img-src 'self' data: https://*.razorpay.com; "
    "connect-src 'self' https://*.razorpay.com; "
    "frame-src https://*.razorpay.com; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    is_checkout = request.url.path == "/billing/checkout"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = CHECKOUT_CSP if is_checkout else CSP
    # HSTS only makes sense once we're actually serving over https - sending
    # it over plain http (local dev) does nothing but risks confusing a
    # future switch back to http during testing.
    if COOKIE_SECURE:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

app.include_router(auth.router)
app.include_router(billing.router)
app.include_router(account.router)


@app.on_event("startup")
def on_startup() -> None:
    # The default SECRET_KEY is fine for local dev but signs every session
    # cookie in the app - refuse to boot with it once APP_BASE_URL points
    # somewhere real, rather than silently running an unauthenticated-looking
    # session system in production.
    if SECRET_KEY == "dev-insecure-secret-change-me" and not APP_BASE_URL.startswith(
        "http://localhost"
    ):
        raise RuntimeError(
            "SECRET_KEY is still the default dev value but APP_BASE_URL "
            f"({APP_BASE_URL!r}) doesn't look like localhost. Set a real "
            "SECRET_KEY before deploying."
        )
    init_db()


@app.exception_handler(StarletteHTTPException)
async def redirect_on_auth_errors(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 303 and "Location" in (exc.headers or {}):
        return RedirectResponse(url=exc.headers["Location"], status_code=303)
    return await http_exception_handler(request, exc)


@app.get("/")
def landing(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    return templates.TemplateResponse(request, "landing.html", {"user": user})


@app.get("/pricing")
def pricing(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    subscribed = bool(user and user.subscription and user.subscription.is_active)
    return templates.TemplateResponse(
        request, "pricing.html", {"user": user, "subscribed": subscribed}
    )


@app.get("/dashboard")
def dashboard(request: Request, user: User = Depends(require_active_subscription)):
    return templates.TemplateResponse(request, "dashboard.html", {"user": user})


@app.post("/analyze", response_model=LogAnalysisResponse)
async def analyze_log(
    file: UploadFile = File(...), user: User = Depends(require_active_subscription)
):
    if not (file.filename.endswith(".log") or file.filename.endswith(".txt")):
        raise HTTPException(status_code=400, detail="Only .log or .txt files supported")

    chunks = []
    total = 0
    while chunk := await file.read(1024 * 1024):
        total += len(chunk)
        if total > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"File too large (max {MAX_UPLOAD_BYTES // (1024 * 1024)} MB).",
            )
        chunks.append(chunk)
    text = b"".join(chunks).decode("utf-8", errors="ignore")

    # analyze_log_content is CPU-bound (regex over every line) and can take
    # seconds on a large file - run it off the event loop so it doesn't stall
    # every other concurrent request on this single-process server.
    return await run_in_threadpool(analyze_log_content, text)
