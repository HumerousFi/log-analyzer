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
| Log analysis engine | ✅ Linux `auth.log` (SSH/sudo), Apache/Nginx access logs; more formats ⏳ |

## Log analysis engine

`parser.py` currently understands **Linux `auth.log`** — both classic
OpenSSH-style syslog (`sshd[1234]:`) and RHEL/CentOS-style PAM-wrapped
syslog (`sshd(pam_unix)[1234]:`) — and turns it into a list of findings,
not just error/warning counts:

- **Brute-force SSH attempts** — 5+ failed passwords from one source IP
- **Username enumeration** — 5+ distinct nonexistent usernames from one IP
- **Possible compromise** — a *password* login succeeding within 30 minutes
  of 5+ failed password attempts from the same IP (publickey logins and
  older bursts are excluded — see below)
- **Direct root logins**, **off-hours logins**, **sensitive sudo commands**
  (`passwd`, `useradd`, shells, network tools, encoded payloads), and
  **`su` to root**

Detection is threshold-based (tunable constants at the top of `parser.py`);
an unrecognized log format returns an empty finding list with a note rather
than an error, so the UI degrades gracefully as more formats are added.
`main.py`'s `/analyze` endpoint requires an active subscription — it's the
paid feature, not a public utility — reads uploads in bounded chunks up to
20 MB, and runs the analysis in a worker thread so a large file doesn't
stall the app for other users.

**Verified against real-world data.** This was tested against two real
public datasets (loghub's OpenSSH honeypot log and a real RHEL/CentOS
`/var/log/messages` capture), not just hand-written samples, which
surfaced and led to fixing several real gaps:
- `su`-to-root detection now matches the actual `pam_unix` message format
  every modern distro logs (it previously matched formats that don't
  really occur in practice).
- RHEL/CentOS-style PAM-wrapped logs (`sshd(pam_unix)[...]`) are now
  understood at all — this previously reported "unsupported format" with
  zero findings despite real attack traffic being present.
- rsyslog's `message repeated N times: [...]` line-collapsing is now
  unwrapped and weighted correctly, instead of silently undercounting
  attack volume (which it does more of the busier an attack gets).
- "Possible compromise" no longer flags a legitimate login forever just
  because that IP brute-forced once at some point in the file's history,
  and no longer flags publickey logins (which can't be "guessed").

`parser.py` also understands **Apache/Nginx access logs** (Combined and
Common Log Format), covering both classic web-attack reconnaissance and
exploitation attempts:

- **Exploit/injection probing** — 3+ requests from one IP matching known
  SQLi, XSS, path-traversal, or RCE/LFI patterns (URL-decoded before
  matching, since real payloads are almost always percent-encoded)
- **Known scanning tools** — any request whose user-agent identifies a
  tool like sqlmap, nikto, nmap, gobuster, wpscan, acunetix (single hit is
  enough - no legitimate browser sends these)
- **Sensitive path probing** — 3+ requests from one IP to paths like
  `/.env`, `/.git/config`, `/wp-login.php`, `/phpmyadmin`, `/.aws/credentials`
- **Directory/endpoint scanning** — 10+ distinct 404-returning paths from
  one IP (dirb/gobuster-style content discovery)
- **Login-endpoint brute-force** — 8+ POSTs from one IP to a login-like path

Verified against a real 10,000-line production access log (a real public
site's traffic, via Elastic's published example dataset): 100% of lines
parsed correctly, and a real, distributed sensitive-path-probing pattern
(different bot IPs each trying `/wp-login.php` once — ambient internet
background noise, not something worth alerting on individually) is now
surfaced in aggregate via `summary.background_sensitive_path_probes`
rather than being silently invisible. The other four detectors were
verified against a constructed test log built from genuine, publicly
documented attack signatures (real sqlmap UA string, real SQLi/XSS/path-
traversal payloads) since that real dataset didn't happen to contain
active exploitation traffic.

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
`https://` URL once you have one, and point the Razorpay webhook endpoint at
`https://<that-url>/billing/webhook`.

```bash
docker build -t sentinel .
docker run -p 8000:8000 --env-file .env sentinel
```

**Deploy-readiness checklist** (the app enforces some of this itself):

- Set a real, random `SECRET_KEY` in the host's env vars — the app refuses
  to start with the default dev value once `APP_BASE_URL` isn't
  `localhost`, so a forgotten key fails loudly at boot instead of quietly
  signing every session cookie with a public string.
- Set `APP_BASE_URL` to your actual `https://` URL. The session cookie is
  only marked `Secure` when this is `https://`, so setting it correctly
  also protects the cookie in transit.
- SQLite lives at `./app.db` inside the container by default — mount a
  persistent volume at that path (or switch `DATABASE_URL` to a managed
  Postgres instance) or every redeploy wipes user accounts and
  subscriptions.
- `.dockerignore` keeps `.env`, `venv/`, and `.git/` out of the image —
  don't `COPY` around it or a local `.env` (real test-mode keys) ends up
  baked into the image layers.
- Stay on Razorpay **test-mode** keys (`rzp_test_...`) until you're ready
  to take real payments; switching to live keys is a separate, deliberate
  step (new key pair + new live webhook in the Razorpay Dashboard).

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
