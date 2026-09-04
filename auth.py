import os
import re
import time
from collections import defaultdict

import bcrypt
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy.orm import Session

from db import Subscription, User, get_db

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-insecure-secret-change-me")
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:8000")
SESSION_COOKIE = "session"
SESSION_MAX_AGE = 60 * 60 * 24 * 30  # 30 days
# Only mark the cookie Secure when we're actually served over https - a local
# http:// dev server would otherwise have the browser silently drop it.
COOKIE_SECURE = APP_BASE_URL.startswith("https://")

_serializer = URLSafeTimedSerializer(SECRET_KEY, salt="session")

# A reasonably strict-but-normal email shape: this is deliberately narrower
# than RFC 5322 (which technically allows quoted strings, etc.) because a
# permissive local-part let structurally dangerous characters (<, >, ", ')
# through as a "valid email" - harmless today only because every template
# that renders it happens to autoescape, which is incidental, not designed,
# protection. Don't loosen this without checking every place email is
# rendered (including inside <script> blocks, e.g. checkout.html).
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

templates = Jinja2Templates(directory="templates")

router = APIRouter()

# --- Login rate limiting (in-memory - fine for this single-process app) ---
LOGIN_WINDOW_SECONDS = 15 * 60
MAX_FAILURES_PER_IP = 15  # across all target emails - catches enumeration/spray
MAX_FAILURES_PER_EMAIL = 5  # against one account - catches targeted brute force

_failures_by_ip: dict[str, list[float]] = defaultdict(list)
_failures_by_email: dict[str, list[float]] = defaultdict(list)

# A fixed dummy hash checked when the submitted email doesn't exist, so a
# nonexistent-account login takes the same time as a wrong-password one
# (bcrypt.checkpw's cost dominates the response time either way). Without
# this, a login attempt against a real email measurably takes ~100x longer
# than one against a fake email - a live-verified timing side channel that
# lets an attacker enumerate registered accounts before ever brute-forcing
# a password.
_DUMMY_PASSWORD_HASH = bcrypt.hashpw(b"not-a-real-password", bcrypt.gensalt()).decode("utf-8")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def _prune(timestamps: list[float], now: float) -> list[float]:
    return [t for t in timestamps if now - t < LOGIN_WINDOW_SECONDS]


def _is_login_rate_limited(ip: str, email: str) -> bool:
    now = time.time()
    ip_hits = _prune(_failures_by_ip[ip], now)
    email_hits = _prune(_failures_by_email[email], now)
    _failures_by_ip[ip] = ip_hits
    _failures_by_email[email] = email_hits
    return len(ip_hits) >= MAX_FAILURES_PER_IP or len(email_hits) >= MAX_FAILURES_PER_EMAIL


def _record_login_failure(ip: str, email: str) -> None:
    now = time.time()
    _failures_by_ip[ip].append(now)
    _failures_by_email[email].append(now)


def _clear_login_failures(ip: str, email: str) -> None:
    _failures_by_ip.pop(ip, None)
    _failures_by_email.pop(email, None)


def create_session_cookie(user_id: int) -> str:
    return _serializer.dumps({"user_id": user_id})


def read_session_cookie(token: str) -> int | None:
    try:
        data = _serializer.loads(token, max_age=SESSION_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None
    return data.get("user_id")


def set_session_cookie(response, user_id: int) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        create_session_cookie(user_id),
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=COOKIE_SECURE,
    )


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    user_id = read_session_cookie(token)
    if user_id is None:
        return None
    return db.get(User, user_id)


def require_user(request: Request, db: Session = Depends(get_db)) -> User:
    user = get_current_user(request, db)
    if user is None:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return user


def require_active_subscription(
    request: Request, db: Session = Depends(get_db)
) -> User:
    user = require_user(request, db)
    sub = user.subscription
    if sub is None or not sub.is_active:
        raise HTTPException(status_code=303, headers={"Location": "/pricing"})
    return user


@router.get("/signup")
def signup_page(request: Request):
    return templates.TemplateResponse(request, "signup.html", {"error": None})


@router.post("/signup")
def signup_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    email = email.strip().lower()

    if not EMAIL_RE.match(email):
        return templates.TemplateResponse(
            request,
            "signup.html",
            {"error": "Enter a valid email address."},
            status_code=400,
        )

    if len(password) < 8:
        return templates.TemplateResponse(
            request,
            "signup.html",
            {"error": "Password must be at least 8 characters."},
            status_code=400,
        )

    if db.query(User).filter(User.email == email).first():
        # Deliberately vaguer than "an account with that email already
        # exists" - this app has no email-verification flow to fully close
        # the account-enumeration gap (that would require confirming
        # signups by email), so this is a partial mitigation: it stops
        # short of directly confirming the email is registered.
        return templates.TemplateResponse(
            request,
            "signup.html",
            {"error": "Couldn't create an account with those details. If you already have one, try logging in."},
            status_code=400,
        )

    user = User(email=email, password_hash=hash_password(password))
    db.add(user)
    db.flush()

    db.add(Subscription(user_id=user.id, status="none"))
    db.commit()
    db.refresh(user)

    response = RedirectResponse(url="/pricing", status_code=303)
    set_session_cookie(response, user.id)
    return response


@router.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})


@router.post("/login")
def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    email = email.strip().lower()
    ip = request.client.host if request.client else "unknown"

    if _is_login_rate_limited(ip, email):
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Too many attempts. Try again in a few minutes."},
            status_code=429,
        )

    user = db.query(User).filter(User.email == email).first()

    # Always run a bcrypt check, even for a nonexistent user, against a
    # fixed dummy hash - so this branch takes the same time either way and
    # doesn't leak which emails are registered via response timing.
    if user is None:
        verify_password(password, _DUMMY_PASSWORD_HASH)
        password_ok = False
    else:
        password_ok = verify_password(password, user.password_hash)

    if not password_ok:
        _record_login_failure(ip, email)
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Incorrect email or password."},
            status_code=400,
        )

    _clear_login_failures(ip, email)
    response = RedirectResponse(url="/dashboard", status_code=303)
    set_session_cookie(response, user.id)
    return response


@router.get("/logout")
def logout():
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response
