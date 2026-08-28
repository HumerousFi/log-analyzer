# Sentinel — Security Log Analyzer (SaaS shell)

A security-analyst-in-a-box for small companies: upload Linux auth logs,
Apache/Nginx logs, firewall logs, or Windows event exports, and get
plain-English findings — brute-force attempts, suspicious IPs, unusual
login times, scanning activity, web attacks, privilege escalation
indicators, anomalies.

## What's in this repo right now

This is the **shell**: landing page, signup/login, Stripe subscription
billing, and a gated dashboard. The actual analysis engine
(`parser.py` / `models.py` / the `/analyze` endpoint) is an early, generic
version and is being rebuilt separately — the dashboard currently shows a
"coming soon" placeholder instead of wiring up to it.

| Piece | Status |
| --- | --- |
| Landing page | ✅ |
| Signup / login (email + password, session cookie) | ✅ |
| Pricing page + Stripe Checkout subscription | ✅ |
| Stripe webhook (activates/deactivates access) | ✅ |
| Billing portal (self-serve cancel/update card) | ✅ |
| Gated dashboard | ✅ (placeholder content) |
| Log analysis engine wired into the dashboard | ⏳ later |

## Local setup

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# fill in SECRET_KEY and the STRIPE_* values, see below
```

Run it:

```bash
uvicorn main:app --reload
```

Visit http://localhost:8000

## Stripe setup (test mode)

1. Install the [Stripe CLI](https://docs.stripe.com/stripe-cli) and run
   `stripe login` (or `stripe sandbox create` if you don't have a Stripe
   account yet — no signup required for a sandbox).
2. Create the product/price once:
   ```bash
   stripe products create --name "Sentinel Monthly"
   stripe prices create --product <prod_id> --unit-amount 4900 \
     --currency usd --recurring[interval]=month
   ```
   Put the resulting `price_...` id in `.env` as `STRIPE_PRICE_ID`.
3. Create a **restricted key** (Dashboard → Developers → API keys → Create
   restricted key) scoped to write access on Checkout Sessions and Billing
   Portal Sessions, and read access on Subscriptions/Customers. Put it in
   `.env` as `STRIPE_SECRET_KEY` (starts with `rk_test_...`). Avoid using a
   full secret key (`sk_...`) if you can avoid it.
4. Forward webhooks to your local server and copy the signing secret it
   prints into `STRIPE_WEBHOOK_SECRET`:
   ```bash
   stripe listen --forward-to localhost:8000/billing/webhook
   ```
5. Use a [test card](https://docs.stripe.com/testing) like
   `4242 4242 4242 4242`, any future expiry, any CVC.

**Before going live:** if you'll be charging customers in the US or EU,
look at [Stripe Tax](https://docs.stripe.com/billing/taxes/collect-taxes.md) —
`automatic_tax` isn't enabled in this shell yet, so no tax is currently being
collected.

In production, create the equivalent live-mode price + restricted key, and
add a webhook endpoint in the Dashboard pointing at
`https://<your-domain>/billing/webhook` instead of using `stripe listen`.

## Deployment

The app is a single Dockerized FastAPI service (SQLite by default — fine to
start, swap `DATABASE_URL` for Postgres when you outgrow it). Any
container host works; two straightforward options:

**Render / Railway / Fly.io** — point them at this repo, they'll build the
`Dockerfile` automatically. Set the env vars from `.env.example` in the
host's dashboard (never commit `.env`). Set `APP_BASE_URL` to your public
URL once you have one, and point the Stripe webhook endpoint at
`https://<that-url>/billing/webhook`.

```bash
docker build -t sentinel .
docker run -p 8000:8000 --env-file .env sentinel
```

## Project layout

```
main.py       FastAPI app, routes, wiring
auth.py       signup/login/logout, password hashing, session cookies
billing.py    Stripe Checkout, billing portal, webhook handler
db.py         SQLAlchemy models (User, Subscription) + SQLite setup
templates/    Jinja2 pages (landing, signup, login, pricing, dashboard)
static/       stylesheet
models.py     Pydantic response schema for /analyze (existing tool code)
parser.py     log-parsing/analysis logic (existing tool code, to be rebuilt)
```
