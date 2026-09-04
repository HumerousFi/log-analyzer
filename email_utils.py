import logging
import os
import smtplib
from email.message import EmailMessage

logger = logging.getLogger("sentinel.email")

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "Sentinel <no-reply@sentinel.local>")


def send_email(to: str, subject: str, body: str) -> None:
    """Send a plain-text email, or log it to the console if SMTP isn't
    configured - so email-dependent flows (verification, password reset)
    are still testable in local dev without a real mail provider."""
    if not SMTP_HOST:
        logger.warning(
            "SMTP not configured - email not sent. To: %s | Subject: %s\n%s",
            to,
            subject,
            body,
        )
        return

    message = EmailMessage()
    message["From"] = SMTP_FROM
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
        smtp.starttls()
        if SMTP_USER:
            smtp.login(SMTP_USER, SMTP_PASSWORD)
        smtp.send_message(message)


def send_verification_email(to: str, verify_url: str) -> None:
    send_email(
        to,
        "Verify your Sentinel email",
        f"Confirm your email address to finish setting up Sentinel:\n\n{verify_url}\n\n"
        "This link expires in 24 hours. If you didn't sign up for Sentinel, ignore this email.",
    )


def send_password_reset_email(to: str, reset_url: str) -> None:
    send_email(
        to,
        "Reset your Sentinel password",
        f"Someone requested a password reset for this account. If that was you:\n\n"
        f"{reset_url}\n\n"
        "This link expires in 1 hour and works only once. If you didn't request this, "
        "you can ignore this email - your password hasn't been changed.",
    )
