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
| Email verification, password reset, 2FA (TOTP + backup codes) | ✅ |
| Pricing page + Razorpay Checkout (recurring subscription) | ✅ |
| Razorpay webhook (reconciles renewals/cancellations) | ✅ |
| Gated dashboard with log upload + findings UI | ✅ |
| Log analysis engine | ✅ Linux `auth.log`, Apache/Nginx, firewall (iptables/ufw), Windows Event Log |

Visual design: **Hanken Grotesk** (display/body) + **IBM Plex Mono** (badges,
pricing, log/evidence lines, summary numbers), a dark-only "security
monitoring" palette with severity colors kept independent of the brand
accent, and a landing hero built around a real mockup of the app's own
finding-card UI rather than generic hero art. See the "Design system" note
in `CLAUDE.md` before changing colors/type.

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

`parser.py` also understands **Linux firewall logs** — iptables/ufw's
`LOG` target output as it appears in `kern.log`/`ufw.log`/syslog
(`SRC=`/`DST=`/`PROTO=`/`SPT=`/`DPT=` key=value fields):

- **Port scanning** — 15+ distinct destination ports probed by one source IP
- **Repeated blocked connections** — 30+ dropped/rejected packets from one
  source IP (persistent attacker or flood traffic)
- **Sensitive port probing** — 3+ attempts from one IP against commonly
  exploited ports (Telnet, RDP, SMB, MySQL, Redis, MongoDB, Docker API,
  etc.), plus the same aggregate-visibility treatment as web sensitive-path
  probing for the (very common) case of many different IPs each trying one
  port once

No public research dataset with real attack traffic in this format was
readily available (unlike the SSH/web-log datasets above), so this was
verified against a constructed log using the genuine, standard netfilter
`LOG` output format with realistic scan/flood/probe patterns rather than
a downloaded real capture.

`parser.py` also understands **Windows Event Log exports** — specifically
`wevtutil qe <LogName> /f:text` output (e.g. `wevtutil qe Security /f:text
> security.txt`), not raw `.evtx` or the XML export. Unlike every other
format here, one event is a multi-line block, not one line:

- **RDP/Windows logon brute-force** — 5+ failed logons (Event ID 4625) from
  one source, labeled specifically as RDP when the logon type is
  RemoteInteractive
- **Possible compromise** — a successful logon (4624) within 30 minutes of
  5+ failed attempts from the same source
- **Account lockouts** (4740), **new accounts created** (4720), **accounts
  added to a privileged group** (4728/4732/4756), **new services installed**
  (7045/4697 - a common persistence mechanism)
- **Audit log cleared** (1102) — flagged critical; legitimate reasons are
  rare and this is a classic anti-forensics step

As with firewall logs, no real anonymized `wevtutil` export was available
to test against, so this was verified against Microsoft's documented
Security-Auditing event schema (field names and block structure are
stable and well-documented) plus a constructed test file built from that
schema, covering every event type above plus legitimate traffic that
correctly produces no findings.

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

## Security

This app has been through a real pentest pass (nmap recon, manual/scripted
auth and payment-logic testing, injection attempts, regex-DoS stress
testing), not just a code read. What that found and fixed:

- **Login is rate-limited** (`auth.py`) — in-memory, per-IP (15 failures /
  15 min, catches enumeration/spray across many emails) and per-email (5 /
  15 min, catches targeted brute force). Resets on process restart, which
  is an accepted tradeoff for a single-process app with no Redis.
- **No timing side-channel on login** — a login attempt against a
  nonexistent email always runs a real bcrypt check (against a fixed dummy
  hash) so it takes the same ~180ms as a real account. Before this fix, a
  nonexistent account resolved in ~2ms versus ~184ms for a real one — a
  measured ~90x gap an attacker could use to enumerate registered emails
  without ever guessing a password.
- **Email validation is intentionally strict**
  (`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`) — a looser pattern
  used to accept `<script>...</script>@x.com` and `x"};alert(1);//@x.com`
  as "valid emails." Both rendered inertly everywhere they're used
  (Jinja2 autoescaping, including inside `checkout.html`'s inline
  `<script>` block), but that was incidental protection from the template
  engine, not something the input validation was actually designed to
  provide.
- **Payment/subscription ownership can't be replayed across accounts** —
  verified by computing a cryptographically valid Razorpay signature for a
  subscription ID a test account didn't own and confirming `/billing/verify`
  still rejects it. Confirmed safe, no fix needed.
- **`/billing/checkout` no longer creates unbounded Razorpay subscriptions**
  — it used to call `client.subscription.create` on every hit with no
  idempotency check, so retries/double-clicks/direct repeated POSTs spun up
  orphaned subscription objects with no limit. It now reuses an existing
  unpaid ("created") subscription and short-circuits to the dashboard if
  the user is already active.
- **SQL injection, session-cookie tampering, path traversal, CSRF, CORS,
  and regex denial-of-service** were all tested directly and found not
  exploitable — SQLAlchemy's ORM parameterizes queries, the signed session
  cookie is correctly rejected when tampered with, `/static/` and direct
  paths don't leak `.env`/`app.db`, `SameSite=Lax` blocks cross-site POST,
  no permissive CORS headers are set, and adversarial payloads (a 50KB
  single line, thousands of unmatched parens) against the parser's regexes
  processed in single-digit milliseconds with no catastrophic backtracking.

Since then, the three gaps above have been closed:

- **Email verification and password reset** (`auth.py`, `email_utils.py`) —
  signup sends a signed, 24-hour verification link (non-blocking: it doesn't
  gate access, just shows a dashboard reminder banner until clicked).
  `/forgot-password` sends a signed, 1-hour, single-use reset link and gives
  an identical response whether or not the account exists — this is what
  actually closes the account-enumeration gap the signup-duplicate message
  couldn't (that message still has to reveal *something* to stay usable
  without an email-confirmation gate; this endpoint has no such constraint).
  The reset token embeds a fingerprint of the current password hash, so
  using it (or changing the password any other way) invalidates it —
  verified by resetting a password then replaying the same link, which
  correctly failed. Without real SMTP configured (`SMTP_HOST` etc. in
  `.env`), emails log to the console instead of failing, so this is testable
  in local dev without a mail provider.
- **2FA** (`twofactor.py`, `account.py`) — TOTP via any standard
  authenticator app, set up from `/account`, plus 8 one-time backup codes
  shown once at enrollment (stored bcrypt-hashed, like passwords). Login
  with 2FA enabled is two-step: a correct password sets a short-lived
  `pending_2fa` cookie and redirects to `/login/2fa`, not a real session —
  verified that hitting `/dashboard` with only that pending cookie still
  redirects to login, i.e. password alone can't skip the second factor.
- **Security response headers** (`main.py`) — CSP, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`,
  and HSTS (once actually served over https) on every response. `/billing/checkout`
  runs a deliberately looser CSP than the rest of the site: live-testing
  showed Razorpay's Checkout.js needs `'unsafe-eval'`/`'unsafe-inline'` in
  `script-src` (without them the payment modal builds its iframe but
  silently stays hidden forever — no console error, no exception) plus the
  full `*.razorpay.com` wildcard, not just `checkout.razorpay.com` (it also
  loads a bundle from `cdn.razorpay.com` and posts telemetry to
  `lumberjack.razorpay.com`). This was caught by actually completing a real
  test-mode payment after adding CSP, not just checking response headers —
  don't trust a "looks fine" without doing that again if this policy changes.

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

**Self-hosted VPS (Docker Compose + Caddy)** — what this repo is actually
set up for via `docker-compose.yml` and `Caddyfile`: one container runs the
app, a second runs Caddy as a reverse proxy that gets you real HTTPS
automatically (via Let's Encrypt) — including with no domain of your own,
using a free [sslip.io](https://sslip.io) hostname that embeds your
server's IP (e.g. `203.0.113.42` → `203-0-113-42.sslip.io`), since that's a
real public DNS name Let's Encrypt can issue a cert for.

```bash
# on the VPS, after installing Docker (curl -fsSL https://get.docker.com | sh)
git clone <this repo> sentinel && cd sentinel
cp .env.example .env
# edit .env: set SECRET_KEY (openssl rand -hex 32), DOMAIN (see above),
# APP_BASE_URL=https://$DOMAIN, DATABASE_URL=sqlite:////app/data/app.db
docker compose up -d --build
```

`DOMAIN` is read by both `Caddyfile` (which host to request a cert for) and
docker compose's own `.env` interpolation — one file covers both. SQLite
persists in the named `app-data` volume (mounted at `/app/data`), so
`docker compose down` / redeploys don't wipe user accounts.

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
main.py         FastAPI app, routes, wiring, security response headers
auth.py         signup/login (incl. 2FA challenge)/logout, email verification,
                password reset, session cookies, login rate limiting
account.py      /account settings page, 2FA setup/disable
twofactor.py    TOTP secret/QR generation, code verification, backup codes
security.py     password hashing (shared by auth.py and twofactor.py)
email_utils.py  SMTP sending, with a console-log fallback for local dev
billing.py      Razorpay subscription checkout, cancellation, webhook handler
db.py           SQLAlchemy models (User, Subscription, BackupCode) + SQLite setup
templates/      Jinja2 pages (landing, signup, login, pricing, dashboard, account, ...)
static/         stylesheet
models.py       Pydantic response schema for /analyze (Finding, LogAnalysisResponse)
parser.py       log parsing/detection logic — see "Log analysis engine" above
```
