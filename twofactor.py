import io
import secrets

import pyotp
import qrcode
import qrcode.image.svg

from db import BackupCode, User
from security import hash_password, verify_password

ISSUER = "Sentinel"
BACKUP_CODE_COUNT = 8


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(email: str, secret: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=ISSUER)


def qr_code_svg(uri: str) -> str:
    # SvgPathImage (a single <path>, with a real viewBox) - not the plain
    # SvgImage factory, whose output has no viewBox and hundreds of
    # unfilled <rect> elements, and renders blank once CSS gives it a pixel
    # size different from its native mm-based one (verified: it does).
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode("utf-8")


def verify_totp_code(secret: str, code: str) -> bool:
    code = code.strip().replace(" ", "")
    if not code.isdigit():
        return False
    # valid_window=1 tolerates the code from the previous/next 30s step, for
    # clock drift between the server and the user's authenticator app.
    return pyotp.totp.TOTP(secret).verify(code, valid_window=1)


def generate_backup_codes(db, user: User) -> list[str]:
    """Replace any existing backup codes with a fresh batch. Returns the
    plaintext codes once - only the bcrypt hash is persisted."""
    db.query(BackupCode).filter(BackupCode.user_id == user.id).delete()

    plaintext_codes = []
    for _ in range(BACKUP_CODE_COUNT):
        code = "-".join(secrets.token_hex(2) for _ in range(2))  # e.g. "a1b2-c3d4"
        plaintext_codes.append(code)
        db.add(BackupCode(user_id=user.id, code_hash=hash_password(code)))
    db.commit()
    return plaintext_codes


def consume_backup_code(db, user: User, code: str) -> bool:
    code = code.strip().lower()
    for backup_code in db.query(BackupCode).filter(
        BackupCode.user_id == user.id, BackupCode.used.is_(False)
    ):
        if verify_password(code, backup_code.code_hash):
            backup_code.used = True
            db.commit()
            return True
    return False
