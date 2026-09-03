# Sentinel — Security Log Analyzer (SaaS shell)

A security-analyst-in-a-box for small companies: upload Linux auth logs,
Apache/Nginx logs, firewall logs, or Windows event exports, and get
plain-English findings — brute-force attempts, suspicious IPs, unusual
login times, scanning activity, web attacks, privilege escalation
indicators, anomalies.

## What's in this repo right now

Landing page, signup/login, Razorpay billing, a gated dashboard, and a real
log analysis engine wired up to it — upload a file, get findings.

| Piece | Status |
| --- | --- |
| Landing page | ✅ |
| Signup / login (email + password, session cookie) | ✅ |
| Pricing page + Razorpay Checkout (recurring subscription) | ✅ |
| Razorpay webhook (reconciles renewals/cancellations) | ✅ |
| Gated dashboard with log upload + findings UI | ✅ |
| Log analysis engine | ✅ Linux `auth.log` (SSH/sudo); more formats ⏳ |

## Log analysis engine

`parser.py` currently understands **Linux `auth.log`** (sshd + sudo/su
lines in classic syslog format) and turns it into a list of findings, not
just error/warning counts:

- **Brute-force SSH attempts** — 5+ failed passwords from one source IP
- **Username enumeration** — 5+ distinct nonexistent usernames from one IP
- **Possible compromise** — a successful login from an IP that was just
  brute-forcing
- **Direct root logins**, **off-hours logins**, **sensitive sudo commands**
  (`passwd`, `useradd`, shells, network tools, encoded payloads), and
  **`su` to root**

Detection is threshold-based (tunable constants at the top of `parser.py`);
an unrecognized log format returns an empty finding list with a note rather
than an error, so the UI degrades gracefully as more formats are added.
`main.py`'s `/analyze` endpoint requires an active subscription — it's the
paid feature, not a public utility.

Adding a new format: write a `_analyze_<format>(lines)` function that
returns a `LogAnalysisResponse`, add a signature check to `detect_log_type`,
and dispatch to it from `analyze_log_content`.

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

Billing is a real recurring Razorpay **Subscription** (₹4,900/month). The
Plan is auto-created/discovered on first checkout (`billing.py`'s
`_get_or_create_plan`) — no manual Plan ID to configure. Note: the
Subscriptions product (`/v1/plans`, `/v1/subscriptions`) returns `401` on a
brand-new Razorpay account until KYC/business approval clears, even though
Payments/Orders/Customers work in test mode from day one.

1. Dashboard → **Settings → API keys** → Regenerate Key. Put the pair in
   `.env` as `RAZORPAY_KEY_ID` (`rzp_test_...`) and `RAZORPAY_KEY_SECRET`.
2. Dashboard → **Settings → Webhooks** → add an endpoint. In test mode you'll
   need a public URL for your local server (e.g. `ngrok http 8000`) pointed
   at `/billing/webhook`, subscribed to `subscription.activated`,
   `subscription.charged`, `subscription.cancelled`, and `subscription.halted`.
   Put the secret you set there into `.env` as `RAZORPAY_WEBHOOK_SECRET`.
3. Test cards: a normal one-time test card (e.g. `4111 1111 1111 1111`) gets
   rejected with "not eligible for recurring payments" — use the
   [recurring-payments test card](https://razorpay.com/docs/payments/payments/test-card-details/)
   `4718 6091 0820 4366` instead (any future expiry, any CVV). Checkout will
   also ask for a mobile number and an OTP: sequential/repeated-digit numbers
   (`9876543210`, `9999999999`) are rejected as fake — use a varied 10-digit
   number instead (e.g. `9845123067`); the OTP screen has a "Skip OTP"
   shortcut in test mode, or accepts any 6 digits on the simulated bank page.

Checkout grants access immediately client-side once the payment signature is
verified in `/billing/verify` (the signature alone is proof of a successful
charge — a live Razorpay `subscription.fetch` call is attempted for the
exact renewal date but is best-effort, since gating access on that live call
means a transient network error to Razorpay could otherwise strand a
paying user). The webhook reconciles renewals, cancellations, and any
period-end drift from that fallback. `Subscription.credited_payment_id`
makes both paths idempotent per Razorpay payment id.

Cancelling (`/billing/cancel`) calls `subscription.cancel` with
`cancel_at_cycle_end: 1` — Razorpay's subscription entity has no field
marking a pending cancellation (its `status` stays `"active"` until the
period actually ends), so `Subscription.cancel_at_period_end` tracks that
intent locally for UI messaging.

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
models.py     Pydantic response schema for /analyze (Finding, LogAnalysisResponse)
parser.py     log parsing/detection logic — see "Log analysis engine" above
```
