import os
import re

import bcrypt
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy.orm import Session

from db import Subscription, User, get_db

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-insecure-secret-change-me")
SESSION_COOKIE = "session"
SESSION_MAX_AGE = 60 * 60 * 24 * 30  # 30 days

_serializer = URLSafeTimedSerializer(SECRET_KEY, salt="session")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

templates = Jinja2Templates(directory="templates")

router = APIRouter()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


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
        return templates.TemplateResponse(
            request,
            "signup.html",
            {"error": "An account with that email already exists."},
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
    user = db.query(User).filter(User.email == email).first()

    if user is None or not verify_password(password, user.password_hash):
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Incorrect email or password."},
            status_code=400,
        )

    response = RedirectResponse(url="/dashboard", status_code=303)
    set_session_cookie(response, user.id)
    return response


@router.get("/logout")
def logout():
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response
