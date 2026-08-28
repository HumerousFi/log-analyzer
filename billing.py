import os

import stripe
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from stripe import StripeClient

from auth import require_user
from db import ACTIVE_STATUSES, Subscription, User, get_db

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_PRICE_ID = os.environ.get("STRIPE_PRICE_ID", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:8000")

router = APIRouter(prefix="/billing")

_client: StripeClient | None = None


def get_client() -> StripeClient:
    global _client
    if not STRIPE_SECRET_KEY:
        raise HTTPException(
            status_code=500,
            detail="Stripe is not configured (STRIPE_SECRET_KEY missing).",
        )
    if _client is None:
        _client = StripeClient(api_key=STRIPE_SECRET_KEY)
    return _client


def _get_or_create_subscription_row(db: Session, user: User) -> Subscription:
    if user.subscription is None:
        sub = Subscription(user_id=user.id, status="none", is_active=False)
        db.add(sub)
        db.commit()
        db.refresh(user)
    return user.subscription


@router.post("/checkout")
def create_checkout_session(
    user: User = Depends(require_user), db: Session = Depends(get_db)
):
    if not STRIPE_PRICE_ID:
        raise HTTPException(
            status_code=500, detail="Stripe is not configured (STRIPE_PRICE_ID missing)."
        )

    client = get_client()
    sub_row = _get_or_create_subscription_row(db, user)

    session_params = {
        "mode": "subscription",
        "line_items": [{"price": STRIPE_PRICE_ID, "quantity": 1}],
        "success_url": f"{APP_BASE_URL}/dashboard?checkout=success",
        "cancel_url": f"{APP_BASE_URL}/pricing?checkout=cancel",
        "client_reference_id": str(user.id),
    }

    if sub_row.stripe_customer_id:
        session_params["customer"] = sub_row.stripe_customer_id
    else:
        session_params["customer_email"] = user.email

    session = client.checkout.sessions.create(session_params)
    return RedirectResponse(url=session.url, status_code=303)


@router.get("/portal")
def create_portal_session(
    user: User = Depends(require_user), db: Session = Depends(get_db)
):
    sub_row = user.subscription
    if sub_row is None or not sub_row.stripe_customer_id:
        raise HTTPException(status_code=400, detail="No billing account on file yet.")

    client = get_client()
    portal_session = client.billing_portal.sessions.create(
        {"customer": sub_row.stripe_customer_id, "return_url": f"{APP_BASE_URL}/dashboard"}
    )
    return RedirectResponse(url=portal_session.url, status_code=303)


def _apply_subscription_state(db: Session, customer_id: str, stripe_subscription: dict) -> None:
    sub_row = (
        db.query(Subscription)
        .filter(Subscription.stripe_customer_id == customer_id)
        .first()
    )
    if sub_row is None:
        return

    status = stripe_subscription.get("status", "none")
    sub_row.stripe_subscription_id = stripe_subscription.get("id")
    sub_row.status = status
    sub_row.is_active = status in ACTIVE_STATUSES
    db.commit()


@router.post("/webhook")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(
            status_code=500, detail="Stripe is not configured (STRIPE_WEBHOOK_SECRET missing)."
        )

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except (ValueError, stripe.SignatureVerificationError):
        raise HTTPException(status_code=400, detail="Invalid webhook signature.")

    event_type = event["type"]
    data = event["data"]["object"]

    if event_type == "checkout.session.completed":
        if data.get("payment_status") == "unpaid":
            return {"received": True}

        user_id = data.get("client_reference_id")
        customer_id = data.get("customer")
        subscription_id = data.get("subscription")

        if user_id and customer_id:
            sub_row = (
                db.query(Subscription)
                .filter(Subscription.user_id == int(user_id))
                .first()
            )
            if sub_row is not None:
                sub_row.stripe_customer_id = customer_id
                sub_row.stripe_subscription_id = subscription_id
                sub_row.status = "active"
                sub_row.is_active = True
                db.commit()

    elif event_type in (
        "customer.subscription.updated",
        "customer.subscription.deleted",
    ):
        customer_id = data.get("customer")
        if customer_id:
            _apply_subscription_state(db, customer_id, data)

    return {"received": True}
