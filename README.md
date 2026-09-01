# Sentinel — Security Log Analyzer (SaaS shell)

A security-analyst-in-a-box for small companies: upload Linux auth logs,
Apache/Nginx logs, firewall logs, or Windows event exports, and get
plain-English findings — brute-force attempts, suspicious IPs, unusual
login times, scanning activity, web attacks, privilege escalation
indicators, anomalies.

## What's in this repo right now

This is the **shell**: landing page, signup/login, Razorpay billing, and a
gated dashboard. The actual analysis engine (`parser.py` / `models.py` / the
`/analyze` endpoint) is an early, generic version and is being rebuilt
separately — the dashboard currently shows a "coming soon" placeholder
instead of wiring up to it.

| Piece | Status |
| --- | --- |
| Landing page | ✅ |
| Signup / login (email + password, session cookie) | ✅ |
| Pricing page + Razorpay Checkout (one-time charge) | ✅ |
| Razorpay webhook (backup activation on payment capture) | ✅ |
| Gated dashboard | ✅ (placeholder content) |
| Log analysis engine wired into the dashboard | ⏳ later |
| Real recurring Razorpay Subscriptions | ⏳ blocked on KYC, see below |

## Local setup

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# fill in SECRET_KEY and the RAZORPAY_* values, see below
```

Run it:

```bash
uvicorn main:app --reload
```

Visit http://localhost:8000

## Razorpay setup (test mode)

Razorpay hands out **test-mode** API keys as soon as you sign up, but the
**Subscriptions product specifically returns 401 until it's enabled** on
the account (in practice this seems tied to KYC/business approval, even in
test mode — general Payments/Orders/Customers endpoints work fine before
that). So for now, billing is a flat one-time charge via the **Orders API**
that grants `PLAN_PERIOD_DAYS` (30) days of access, not a real recurring
Razorpay Subscription. Swap `billing.py` back to the Subscriptions API
(Plans + `subscription.create`) once Subscriptions is enabled on the
account — the Checkout.js/webhook plumbing carries over, only the
order-vs-subscription object changes.

1. Dashboard → **Settings → API keys** → Regenerate Key. Put the pair in
   `.env` as `RAZORPAY_KEY_ID` (`rzp_test_...`) and `RAZORPAY_KEY_SECRET`.
2. Dashboard → **Settings → Webhooks** → add an endpoint. In test mode you'll
   need a public URL for your local server (e.g. `ngrok http 8000`) pointed
   at `/billing/webhook`, subscribed to the `payment.captured` event. Put the
   secret you set there into `.env` as `RAZORPAY_WEBHOOK_SECRET`.
3. Use a [test card](https://razorpay.com/docs/payments/payments/test-card-upi-details/)
   like `4111 1111 1111 1111`, any future expiry, any CVC — or test UPI id
   `success@razorpay`.

Checkout grants access immediately client-side (signature verified in
`/billing/verify`); the webhook is a backup in case the browser closes
before that fires. Both paths are idempotent per Razorpay order id.

In production, generate the equivalent **live** key pair once KYC is
approved, and add a live webhook endpoint in the Dashboard pointing at
`https://<your-domain>/billing/webhook`.

## Deployment

The app is a single Dockerized FastAPI service (SQLite by default — fine to
start, swap `DATABASE_URL` for Postgres when you outgrow it). Any
container host works; two straightforward options:

**Render / Railway / Fly.io** — point them at this repo, they'll build the
`Dockerfile` automatically. Set the env vars from `.env.example` in the
host's dashboard (never commit `.env`). Set `APP_BASE_URL` to your public
URL once you have one, and point the Razorpay webhook endpoint at
`https://<that-url>/billing/webhook`.

```bash
docker build -t sentinel .
docker run -p 8000:8000 --env-file .env sentinel
```

## Project layout

```
main.py       FastAPI app, routes, wiring
auth.py       signup/login/logout, password hashing, session cookies
billing.py    Razorpay subscription checkout, cancellation, webhook handler
db.py         SQLAlchemy models (User, Subscription) + SQLite setup
templates/    Jinja2 pages (landing, signup, login, pricing, dashboard)
static/       stylesheet
models.py     Pydantic response schema for /analyze (existing tool code)
parser.py     log-parsing/analysis logic (existing tool code, to be rebuilt)
```
