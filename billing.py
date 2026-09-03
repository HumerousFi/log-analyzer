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

PLAN_AMOUNT_PAISE = 490000  # ₹4,900
PLAN_CURRENCY = "INR"
PLAN_PERIOD = "monthly"
PLAN_INTERVAL = 1
PLAN_NAME = "Sentinel Monthly"
# Razorpay subscriptions require a total_count of billing cycles; there's no
# "until cancelled" option, so use a number large enough to be effectively
# unlimited (100 years of monthly billing).
PLAN_TOTAL_COUNT = 1200

router = APIRouter(prefix="/billing")
templates = Jinja2Templates(directory="templates")

_client: razorpay.Client | None = None
_plan_id: str | None = None


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


def _get_or_create_plan(client: razorpay.Client) -> str:
    global _plan_id
    if _plan_id:
        return _plan_id

    existing = client.plan.all({"count": 100})
    for plan in existing.get("items", []):
        item = plan.get("item", {})
        if (
            plan.get("period") == PLAN_PERIOD
            and plan.get("interval") == PLAN_INTERVAL
            and item.get("amount") == PLAN_AMOUNT_PAISE
            and item.get("currency") == PLAN_CURRENCY
        ):
            _plan_id = plan["id"]
            return _plan_id

    plan = client.plan.create(
        {
            "period": PLAN_PERIOD,
            "interval": PLAN_INTERVAL,
            "item": {
                "name": PLAN_NAME,
                "amount": PLAN_AMOUNT_PAISE,
                "currency": PLAN_CURRENCY,
            },
        }
    )
    _plan_id = plan["id"]
    return _plan_id


def _get_or_create_subscription_row(db: Session, user: User) -> Subscription:
    if user.subscription is None:
        sub = Subscription(user_id=user.id, status="none")
        db.add(sub)
        db.commit()
        db.refresh(user)
    return user.subscription


def _apply_subscription_state(sub_row: Subscription, subscription_entity: dict) -> None:
    sub_row.status = subscription_entity.get("status", sub_row.status)
    current_end = subscription_entity.get("current_end")
    if current_end:
        sub_row.current_period_end = datetime.datetime.utcfromtimestamp(current_end)


@router.post("/checkout")
def start_checkout(
    request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)
):
    client = get_client()
    sub_row = _get_or_create_subscription_row(db, user)
    plan_id = _get_or_create_plan(client)

    subscription = client.subscription.create(
        {
            "plan_id": plan_id,
            "customer_notify": 1,
            "total_count": PLAN_TOTAL_COUNT,
            "notes": {"user_id": str(user.id)},
        }
    )

    sub_row.razorpay_subscription_id = subscription["id"]
    sub_row.status = subscription.get("status", "created")
    sub_row.cancel_at_period_end = False
    db.commit()

    return templates.TemplateResponse(
        request,
        "checkout.html",
        {
            "key_id": RAZORPAY_KEY_ID,
            "subscription_id": subscription["id"],
            "user_email": user.email,
        },
    )


@router.post("/verify")
def verify_checkout(
    razorpay_payment_id: str = Form(...),
    razorpay_subscription_id: str = Form(...),
    razorpay_signature: str = Form(...),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    if not RAZORPAY_KEY_SECRET:
        raise HTTPException(status_code=500, detail="Razorpay is not configured.")

    sub_row = user.subscription
    if sub_row is None or sub_row.razorpay_subscription_id != razorpay_subscription_id:
        raise HTTPException(status_code=400, detail="Subscription mismatch.")

    payload = f"{razorpay_payment_id}|{razorpay_subscription_id}"
    expected_signature = hmac.new(
        RAZORPAY_KEY_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected_signature, razorpay_signature):
        raise HTTPException(status_code=400, detail="Invalid payment signature.")

    if sub_row.credited_payment_id != razorpay_payment_id:
        # The signature is already cryptographic proof the charge succeeded
        # (only someone holding RAZORPAY_KEY_SECRET could produce it), so a
        # network hiccup talking to Razorpay here shouldn't block granting
        # access. Fetch for the exact period end on a best-effort basis; fall
        # back to a provisional 1-month grant and let the webhook true it up.
        try:
            subscription = get_client().subscription.fetch(razorpay_subscription_id)
            _apply_subscription_state(sub_row, subscription)
        except Exception:
            sub_row.status = "active"
            now = datetime.datetime.utcnow()
            base = sub_row.current_period_end if sub_row.current_period_end and sub_row.current_period_end > now else now
            sub_row.current_period_end = base + datetime.timedelta(days=30)

        sub_row.credited_payment_id = razorpay_payment_id
        db.commit()

    return RedirectResponse(url="/dashboard?checkout=success", status_code=303)


@router.post("/cancel")
def cancel_subscription(user: User = Depends(require_user), db: Session = Depends(get_db)):
    sub_row = user.subscription
    if sub_row is None or not sub_row.razorpay_subscription_id:
        raise HTTPException(status_code=400, detail="No subscription to cancel.")

    client = get_client()
    client.subscription.cancel(sub_row.razorpay_subscription_id, {"cancel_at_cycle_end": 1})
    sub_row.cancel_at_period_end = True
    db.commit()

    return RedirectResponse(url="/pricing?cancel=success", status_code=303)


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
    event_name = event.get("event", "")

    if event_name.startswith("subscription."):
        sub_entity = event.get("payload", {}).get("subscription", {}).get("entity", {})
        subscription_id = sub_entity.get("id")

        sub_row = (
            db.query(Subscription)
            .filter(Subscription.razorpay_subscription_id == subscription_id)
            .first()
            if subscription_id
            else None
        )

        if sub_row is not None:
            if event_name == "subscription.charged":
                payment_entity = event.get("payload", {}).get("payment", {}).get("entity", {})
                payment_id = payment_entity.get("id")
                if sub_row.credited_payment_id != payment_id:
                    _apply_subscription_state(sub_row, sub_entity)
                    sub_row.credited_payment_id = payment_id
                    db.commit()
            else:
                _apply_subscription_state(sub_row, sub_entity)
                db.commit()

    return {"received": True}
