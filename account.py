from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from auth import require_user
from db import BackupCode, User, get_db
from security import verify_password
from twofactor import (
    consume_backup_code,
    generate_backup_codes,
    generate_totp_secret,
    provisioning_uri,
    qr_code_svg,
    verify_totp_code,
)

templates = Jinja2Templates(directory="templates")

router = APIRouter(prefix="/account")


@router.get("")
def account_page(
    request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)
):
    unused_backup_codes = (
        db.query(BackupCode)
        .filter(BackupCode.user_id == user.id, BackupCode.used.is_(False))
        .count()
    )
    return templates.TemplateResponse(
        request,
        "account.html",
        {
            "user": user,
            "unused_backup_codes": unused_backup_codes,
            "error": request.query_params.get("error"),
        },
    )


@router.get("/2fa/setup")
def twofactor_setup_page(
    request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)
):
    if user.totp_enabled:
        return RedirectResponse(url="/account", status_code=303)

    # A fresh secret each time this page loads (not yet saved as the user's
    # real secret until they confirm a code from it) - avoids ever enabling
    # 2FA with a secret the user never actually scanned successfully.
    secret = generate_totp_secret()
    user.totp_secret = secret
    db.commit()

    uri = provisioning_uri(user.email, secret)
    return templates.TemplateResponse(
        request,
        "twofactor_setup.html",
        {"user": user, "secret": secret, "qr_svg": qr_code_svg(uri), "error": None},
    )


@router.post("/2fa/setup")
def twofactor_setup_confirm(
    request: Request,
    code: str = Form(...),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    if user.totp_enabled or not user.totp_secret:
        return RedirectResponse(url="/account", status_code=303)

    if not verify_totp_code(user.totp_secret, code):
        uri = provisioning_uri(user.email, user.totp_secret)
        return templates.TemplateResponse(
            request,
            "twofactor_setup.html",
            {
                "user": user,
                "secret": user.totp_secret,
                "qr_svg": qr_code_svg(uri),
                "error": "That code didn't match. Try the current code from your app.",
            },
            status_code=400,
        )

    user.totp_enabled = True
    db.commit()
    backup_codes = generate_backup_codes(db, user)
    return templates.TemplateResponse(
        request, "twofactor_backup_codes.html", {"user": user, "backup_codes": backup_codes}
    )


@router.post("/2fa/disable")
def twofactor_disable(
    request: Request,
    password: str = Form(...),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    if not verify_password(password, user.password_hash):
        unused_backup_codes = (
            db.query(BackupCode)
            .filter(BackupCode.user_id == user.id, BackupCode.used.is_(False))
            .count()
        )
        return templates.TemplateResponse(
            request,
            "account.html",
            {
                "user": user,
                "unused_backup_codes": unused_backup_codes,
                "error": "Incorrect password.",
            },
            status_code=400,
        )

    user.totp_enabled = False
    user.totp_secret = None
    db.query(BackupCode).filter(BackupCode.user_id == user.id).delete()
    db.commit()
    return RedirectResponse(url="/account", status_code=303)


@router.post("/2fa/regenerate-backup-codes")
def twofactor_regenerate_backup_codes(
    request: Request,
    code: str = Form(...),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    if not user.totp_enabled or not user.totp_secret:
        return RedirectResponse(url="/account", status_code=303)
    if not (verify_totp_code(user.totp_secret, code) or consume_backup_code(db, user, code)):
        return RedirectResponse(url="/account?error=code", status_code=303)

    backup_codes = generate_backup_codes(db, user)
    return templates.TemplateResponse(
        request, "twofactor_backup_codes.html", {"user": user, "backup_codes": backup_codes}
    )
