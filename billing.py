import datetime
import hashlib
import hmac
import os

import razorpay
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from auth import require_user
from db import Subscription, User, get_db

RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID", "")
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET", "")
RAZORPAY_WEBHOOK_SECRET = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:8000")

# Stopgap billing model: Razorpay Subscriptions requires the account's
# Subscriptions product to be enabled, which is gated behind KYC/business
# approval. Until that clears, access is sold as a flat prepaid charge via
# the Orders API (works in test mode today) that grants a fixed number of
# days of access. Swap this for real Razorpay Subscriptions once KYC clears.
PLAN_AMOUNT_PAISE = 490000  # ₹4,900
PLAN_PERIOD_DAYS = 30

router = APIRouter(prefix="/billing")
templates = Jinja2Templates(directory="templates")

_client: razorpay.Client | None = None


def get_client() -> razorpay.Client:
    global _client
    if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
        raise HTTPException(
            status_code=500,
            detail="Razorpay is not configured (RAZORPAY_KEY_ID/RAZORPAY_KEY_SECRET missing).",
        )
    if _client is None:
        _client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
    return _client


def _get_or_create_subscription_row(db: Session, user: User) -> Subscription:
    if user.subscription is None:
        sub = Subscription(user_id=user.id, status="none")
        db.add(sub)
        db.commit()
        db.refresh(user)
    return user.subscription


def _grant_access(sub_row: Subscription) -> None:
    now = datetime.datetime.utcnow()
    base = sub_row.current_period_end if sub_row.current_period_end and sub_row.current_period_end > now else now
    sub_row.current_period_end = base + datetime.timedelta(days=PLAN_PERIOD_DAYS)
    sub_row.status = "active"


@router.post("/checkout")
def start_checkout(
    request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)
):
    client = get_client()
    sub_row = _get_or_create_subscription_row(db, user)

    order = client.order.create(
        {
            "amount": PLAN_AMOUNT_PAISE,
            "currency": "INR",
            "payment_capture": 1,
            "notes": {"user_id": str(user.id)},
        }
    )

    sub_row.razorpay_order_id = order["id"]
    db.commit()

    return templates.TemplateResponse(
        request,
        "checkout.html",
        {
            "key_id": RAZORPAY_KEY_ID,
            "order_id": order["id"],
            "amount": PLAN_AMOUNT_PAISE,
            "user_email": user.email,
        },
    )


@router.post("/verify")
def verify_checkout(
    razorpay_payment_id: str = Form(...),
    razorpay_order_id: str = Form(...),
    razorpay_signature: str = Form(...),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    if not RAZORPAY_KEY_SECRET:
        raise HTTPException(status_code=500, detail="Razorpay is not configured.")

    sub_row = user.subscription
    if sub_row is None or sub_row.razorpay_order_id != razorpay_order_id:
        raise HTTPException(status_code=400, detail="Order mismatch.")

    payload = f"{razorpay_order_id}|{razorpay_payment_id}"
    expected_signature = hmac.new(
        RAZORPAY_KEY_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected_signature, razorpay_signature):
        raise HTTPException(status_code=400, detail="Invalid payment signature.")

    if sub_row.credited_order_id != razorpay_order_id:
        _grant_access(sub_row)
        sub_row.credited_order_id = razorpay_order_id
        db.commit()

    return RedirectResponse(url="/dashboard?checkout=success", status_code=303)


@router.post("/webhook")
async def razorpay_webhook(request: Request, db: Session = Depends(get_db)):
    if not RAZORPAY_WEBHOOK_SECRET:
        raise HTTPException(
            status_code=500, detail="Razorpay is not configured (RAZORPAY_WEBHOOK_SECRET missing)."
        )

    payload = await request.body()
    sig_header = request.headers.get("x-razorpay-signature", "")

    client = get_client()
    try:
        client.utility.verify_webhook_signature(
            payload.decode("utf-8"), sig_header, RAZORPAY_WEBHOOK_SECRET
        )
    except razorpay.errors.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid webhook signature.")

    event = await request.json()
    if event.get("event") == "payment.captured":
        payment_entity = event.get("payload", {}).get("payment", {}).get("entity", {})
        order_id = payment_entity.get("order_id")

        sub_row = (
            db.query(Subscription).filter(Subscription.razorpay_order_id == order_id).first()
        )
        if sub_row is not None and sub_row.credited_order_id != order_id:
            _grant_access(sub_row)
            sub_row.credited_order_id = order_id
            db.commit()

    return {"received": True}
