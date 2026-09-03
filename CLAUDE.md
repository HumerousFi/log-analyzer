# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Sentinel is a security log analyzer SaaS **shell**: landing page, signup/login,
Razorpay billing, and a gated dashboard, wrapped around an early analysis
engine that is not yet wired up to the UI. The dashboard currently shows a
"coming soon" placeholder instead of calling `/analyze`.

## Commands

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env       # fill in SECRET_KEY and RAZORPAY_* (see README)
uvicorn main:app --reload  # http://localhost:8000
```

There is no test suite, linter, or CI config in this repo yet. There is no
CLI entrypoint for the analyzer — it's only reachable via `POST /analyze`
(multipart file upload, `.log` files only) or by importing
`parser.analyze_log_content` directly (e.g. in a `python -c` one-liner) when
iterating on it standalone.

Docker: `docker build -t sentinel . && docker run -p 8000:8000 --env-file .env sentinel`.

## Architecture

Single-process FastAPI app, SQLite by default (`DATABASE_URL` swaps to
Postgres later), server-rendered Jinja2 templates — no frontend build step,
no JS framework.

- **`main.py`** — app wiring only: mounts `auth.router` and `billing.router`,
  defines `/`, `/pricing`, `/dashboard`, and `/analyze`. A global
  `StarletteHTTPException` handler turns any `HTTPException(status_code=303,
  headers={"Location": ...})` into an actual redirect — this is the
  mechanism `auth.require_user` / `require_active_subscription` use to bounce
  unauthenticated or unpaid users to `/login` or `/pricing`, so raise that
  pattern rather than `RedirectResponse` inside a dependency.
- **`auth.py`** — signup/login/logout, bcrypt password hashing, and
  itsdangerous-signed session cookies (`SESSION_COOKIE`, 30-day max age, no
  server-side session store). Exposes the two auth dependencies every
  protected route should use: `require_user` (logged in) and
  `require_active_subscription` (logged in + `subscription.is_active`).
- **`db.py`** — SQLAlchemy 2.0 models, `User` 1:1 `Subscription`. Notable:
  `Subscription.is_active` is a computed `@property` derived from
  `current_period_end`, not a stored column — don't try to set it or filter
  on it in a SQL query, and don't reintroduce it as a mapped column.
- **`billing.py`** — Razorpay **Subscriptions** integration (real recurring
  billing, not a one-time charge). `_get_or_create_plan` lazily creates/finds
  the Plan by matching amount/currency/period rather than hardcoding a Plan
  ID. `/billing/verify` treats a valid payment signature as sufficient proof
  of a successful charge and grants access on it directly — it also attempts
  a live `client.subscription.fetch` for the exact renewal date, but that
  call is best-effort (wrapped in a broad `except Exception`) precisely
  because gating access on it once caused a real outage: a transient
  connection reset to Razorpay's API right after a verified payment left a
  paying user unprovisioned. Don't reintroduce a hard dependency on that
  fetch succeeding. `/billing/webhook` (`subscription.*` events) reconciles
  renewals/cancellations/period-end drift from that fallback; both paths are
  idempotent via `Subscription.credited_payment_id`. Razorpay's subscription
  entity has no field marking a pending cancellation — `cancel_at_cycle_end`
  leaves `status` as `"active"` until the period actually ends — so
  `Subscription.cancel_at_period_end` tracks that intent locally; don't
  derive cancellation UI state from `status`.
- **`parser.py` / `models.py`** — the actual analysis engine. Regex-based,
  intentionally generic placeholder logic (severity/suspicious-pattern
  matching via `SUSPICIOUS_PATTERNS`, `SEVERITY_MAP`) — being rebuilt
  separately with real brute-force/suspicious-IP/scanning/web-attack
  detection. Not currently linked from the dashboard.
- **`templates/`** — `base.html` layout plus one template per page
  (landing/signup/login/pricing/dashboard/checkout). `checkout.html` embeds
  Razorpay Checkout.js and posts the payment result to `/billing/verify`.

## Working in this repo

- Never commit `.env` (real Razorpay test keys live there); `.env.example`
  is the template to keep in sync when adding new config.
- When touching billing, re-read the "Razorpay setup" section of
  `README.md` first — it has the up-to-date account-gating caveat and the
  webhook/test-card setup steps.
