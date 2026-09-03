# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Sentinel is a security log analyzer SaaS: landing page, signup/login,
Razorpay billing, a gated dashboard, and a log analysis engine wired up to
it. Currently understands Linux `auth.log` (SSH/sudo); more formats are
meant to be added one at a time (see `parser.py` architecture note below).

## Commands

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env       # fill in SECRET_KEY and RAZORPAY_* (see README)
uvicorn main:app --reload  # http://localhost:8000
```

There is no test suite, linter, or CI config in this repo yet. There is no
CLI entrypoint for the analyzer — it's only reachable via `POST /analyze`
(multipart upload, `.log`/`.txt`, requires an active subscription) or by
importing `parser.analyze_log_content` directly (e.g. in a `python -c`
one-liner) when iterating on detection logic standalone, which is much
faster than round-tripping through the dashboard upload form.

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
- **`parser.py` / `models.py`** — the analysis engine. `models.py` defines
  `Finding` (severity/category/description/evidence) and
  `LogAnalysisResponse` — the schema is findings-shaped, not generic
  error/warning counts, because the product is "plain-English security
  findings," not a log grep tool. `parser.py`'s `analyze_log_content` is a
  dispatcher: `detect_log_type` sniffs the format from a signature regex,
  then hands off to a per-format `_analyze_<format>(lines)` function
  (currently only `_analyze_linux_auth`); an unrecognized format returns an
  empty findings list with an explanatory `summary.note` rather than an
  error. Add a new log format by writing another `_analyze_<format>`
  function and a signature check in `detect_log_type` — don't try to
  generalize the regexes across formats prematurely, each format's log
  lines are structurally different enough that a shared parser adds
  complexity without reuse. Detection thresholds (`BRUTE_FORCE_THRESHOLD`,
  etc.) are module-level constants at the top of the file, deliberately not
  configurable per-user yet.
- **`templates/`** — `base.html` layout plus one template per page
  (landing/signup/login/pricing/dashboard/checkout). `checkout.html` embeds
  Razorpay Checkout.js and posts the payment result to `/billing/verify`.
  `dashboard.html` has an upload form that POSTs to `/analyze` via `fetch`
  and renders the JSON response client-side with vanilla JS (no build step,
  consistent with the rest of the app) — the severity-to-color mapping and
  finding-card layout live in `static/style.css` under `.severity-*` /
  `.finding-card`.

## Working in this repo

- Never commit `.env` (real Razorpay test keys live there); `.env.example`
  is the template to keep in sync when adding new config.
- When touching billing, re-read the "Razorpay setup" section of
  `README.md` first — it has the up-to-date account-gating caveat and the
  webhook/test-card setup steps.
