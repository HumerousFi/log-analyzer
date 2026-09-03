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
  `/analyze` reads the upload in bounded chunks up to `MAX_UPLOAD_BYTES`
  (20 MB, raising 413 past it) and runs `analyze_log_content` via
  `run_in_threadpool` rather than calling it directly - it's CPU-bound and
  took ~2s on a 300k-line file in testing; calling it inline on this
  single-process server measurably stalled every other concurrent request
  (confirmed: a 1.75s landing-page delay during one large upload) for the
  duration. Don't call `analyze_log_content` (or any future
  `_analyze_<format>`) synchronously from this route again.
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
  of a successful charge and grants a provisional 30-day access window on it
  **unconditionally**, then tries a live `client.subscription.fetch` to
  refine the exact renewal date — but only adopts that fetched state if it
  actually shows `status == "active"` with a `current_end`. Two independent
  outages taught us not to trust that fetch: (1) a transient connection reset
  to Razorpay's API right after a verified payment left a paying user
  unprovisioned when the fetch was in the critical path; (2) even when the
  fetch *succeeds*, Razorpay's subscription record transitions
  `"created"` → `"active"` asynchronously - often a few seconds after the
  browser redirects back here - so an immediate fetch can return a stale,
  non-active subscription with no `current_end`, and blindly applying that
  stale state overwrote a legitimate grant. Don't reintroduce a hard
  dependency on that fetch's result, in either direction - it may fail, or
  it may succeed with data that isn't current yet. `/billing/webhook`
  (`subscription.*` events) reconciles renewals/cancellations/period-end
  drift; both paths are idempotent via `Subscription.credited_payment_id`.
  Razorpay's subscription entity has no field marking a pending
  cancellation — `cancel_at_cycle_end` leaves `status` as `"active"` until
  the period actually ends — so `Subscription.cancel_at_period_end` tracks
  that intent locally; don't derive cancellation UI state from `status`.
- **`parser.py` / `models.py`** — the analysis engine. `models.py` defines
  `Finding` (severity/category/description/evidence) and
  `LogAnalysisResponse` — the schema is findings-shaped, not generic
  error/warning counts, because the product is "plain-English security
  findings," not a log grep tool. `parser.py`'s `analyze_log_content` is a
  dispatcher: `detect_log_type` sniffs the format from a signature regex,
  then hands off to a per-format `_analyze_<format>(lines)` function
  (`_analyze_linux_auth`, `_analyze_web_access`, `_analyze_firewall`,
  `_analyze_windows_events`); an
  unrecognized format returns an empty findings list with an explanatory
  `summary.note` rather than an error. Add a new log format by writing
  another `_analyze_<format>`
  function and a signature check in `detect_log_type` — don't try to
  generalize the regexes across formats prematurely, each format's log
  lines are structurally different enough that a shared parser adds
  complexity without reuse. Detection thresholds (`BRUTE_FORCE_THRESHOLD`,
  etc.) are module-level constants at the top of the file, deliberately not
  configurable per-user yet.
  - **Verified against real-world logs, not just synthetic ones.** Testing
    against loghub's real OpenSSH honeypot and RHEL/CentOS syslog datasets
    surfaced several bugs that a hand-written test log never would have
    (see git history around the commit that fixed them for the full
    writeup). Three patterns worth knowing before touching this file again:
    1. **Program-name prefixes must tolerate a PAM wrapper.** RHEL/CentOS
       (and some Debian configs) tag the syslog facility itself with the
       PAM module name — `sshd(pam_unix)[1234]:` instead of `sshd[1234]:`.
       `SSHD_PREFIX`/`SUDO_PREFIX`/`SU_PREFIX` all account for this
       already — don't hardcode a bare `sshd\[\d+\]:` again in a new
       regex, or that entire OS family silently stops parsing.
    2. **rsyslog collapses repeated identical lines** into
       `message repeated N times: [ <original> ]` — and does so *more*
       under a heavier attack, hiding scale exactly when it matters most.
       `_unwrap_repeated` + the `weight` field on every event dict handle
       this; any new per-line regex needs to run against the
       normalized/unwrapped line (see the top of the loop in
       `_analyze_linux_auth`) and multiply its count by `weight`, not just
       `len(...)` the list.
    3. **The "possible compromise" finding has a deliberate time window**
       (`COMPROMISE_LOOKBACK`) and is restricted to `method == "password"`.
       Without the window, one old brute-force burst permanently flags
       every future login from that IP (IPs get reassigned/shared/NAT'd);
       without the method check, a legitimate publickey login gets called
       "possibly guessed or brute-forced," which doesn't even make sense
       for key-based auth. Don't remove either guard to "simplify" this.
  - **`su` detection matches the real `pam_unix` format** (`session opened
    for user X by Y(uid=N)`, actor blank when root/system did it directly)
    — this is what every modern distro actually logs. The two other
    alternatives in `SU_SUCCESS_RE` are for older/rarer formats; don't
    delete the `pam_unix` branch to "clean up," it's the one that matters.
  - **Memory**: `failed_by_ip` only retains raw line text for the first
    `MAX_RETAINED_LINES_PER_BUCKET` (== `MAX_SAMPLE_LINES`) attempts per IP
    — beyond that, entries still count toward totals/severity but drop
    their `line` text (set to `None`), since nothing beyond the sample
    count is ever rendered. This bounds memory on a multi-million-line
    brute-force flood. If you add a new bucket that can grow unboundedly
    with attack volume, apply the same cap.
  - **`_analyze_web_access`** (Apache/Nginx Combined/Common Log Format)
    keys `events_by_ip` by source IP but deliberately does **not** apply
    the same per-bucket line-retention cap as `failed_by_ip` — each
    detector (exploit-pattern probing, scanner user-agents, sensitive-path
    probing, 404-scanning, login-endpoint brute-force) filters a different
    heterogeneous subset of that IP's full request list, so an early
    truncation could throw away the exact requests a detector needs (e.g.
    an exploit attempt buried in an otherwise-normal browsing session from
    that IP). The request-size cap (`MAX_UPLOAD_BYTES`) and threadpool
    offload in `main.py` are what bound the blast radius here instead.
    Request paths/query strings are URL-decoded once at parse time
    (`unquote_plus`) before matching `EXPLOIT_PATTERN_RE`/
    `SENSITIVE_PATH_RE`, since real attack payloads are almost always
    percent-encoded on the wire.
  - **Sensitive-path probing is usually distributed, not repeated** — real
    testing against an actual public web server's access log showed
    opportunistic bots each hit a sensitive path once from a different IP,
    not one IP repeating it. The per-IP `SENSITIVE_PATH_THRESHOLD` finding
    intentionally doesn't fire on this (alerting on every single-shot bot
    probe would be pure noise — virtually every public server gets this
    constantly), but `summary.background_sensitive_path_probes` /
    `background_sensitive_path_probe_ips` surface it in aggregate so it
    isn't simply invisible. Don't lower the per-IP threshold to "catch"
    this pattern - it'll just create alert fatigue instead.
  - **`_analyze_firewall`** (iptables/ufw `LOG` target via kernel/syslog)
    parses `SRC=`/`DST=`/`PROTO=`/`SPT=`/`DPT=` key=value fields with
    `FIREWALL_FIELDS_RE`. This relies on netfilter's fixed field ordering
    (SRC before DST before PROTO before SPT/DPT) via non-greedy `.*?` —
    it is not a generic key=value parser, so don't reorder the pattern
    groups without checking real log output. Action (`BLOCK`/`ALLOW`/etc.)
    comes from `FIREWALL_ACTION_RE` matching ufw's own `[UFW BLOCK]`-style
    tag or a common `--log-prefix` convention; when no tag is present at
    all, it **defaults to blocked** — a firewall `LOG` rule is set up to
    log drops in the overwhelming majority of real configs, so don't
    change this default to "unknown" without also updating every finding
    that assumes `blocked` means something. Same aggregate-visibility
    pattern as web sensitive-path probing applies to `SENSITIVE_PORTS`
    (Telnet/RDP/SMB/etc.) — see `background_sensitive_port_probes`.
  - **`_analyze_windows_events`** targets `wevtutil qe <Log> /f:text` output
    specifically — not raw `.evtx` (binary) and not the XML export. It's
    structurally different from every other format here: one event is a
    multi-line block starting at an `Event[N]:` header, not one line, so
    `_analyze_windows_events` first groups `lines` into blocks before any
    field extraction, and every regex (`WINDOWS_EVENT_ID_RE`,
    `WINDOWS_ACCOUNT_NAME_RE`, etc.) runs with `re.MULTILINE` against the
    whole re-joined block text, not per-line. `parsed_lines` counts every
    line belonging to a block that had a recognizable Event ID, not one
    per event, so the "X of Y lines matched" ratio in the UI stays
    meaningful for these much longer records.
    - Most of these event templates list an acting "Subject" account
      first and the actual target account later in the same block (e.g.
      4625's "Account For Which Logon Failed", 4732's "Member") — both
      show up as separate `Account Name:` matches. Taking the *last*
      non-placeholder (`WINDOWS_ACCOUNT_NAME_RE.findall` + reversed) match
      is what correctly extracts the target rather than the Subject
      (frequently `-` for anonymous/failed attempts). Don't switch this to
      the first match.
    - Only a curated set of event IDs is handled (4624/4625 logons, 4740
      lockout, 4720 account creation, 4728/4732/4756 privileged group
      membership, 1102 audit-log-cleared, 7045/4697 service installed) —
      this is deliberately not a generic "parse every event" engine, same
      reasoning as not generalizing regexes across the other formats.
    - Verified against Microsoft's documented Security-Auditing event
      schema (field names/structure are stable and well-documented) plus
      a constructed test file built from that schema — no real anonymized
      wevtutil export was available to test against, unlike the SSH/web
      datasets. If a real one ever surfaces, re-verify against it.
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
  is the template to keep in sync when adding new config. `.dockerignore`
  also excludes it from the build context — don't remove that entry, or a
  local `.env` gets baked into the image.
- When touching billing, re-read the "Razorpay setup" section of
  `README.md` first — it has the up-to-date account-gating caveat and the
  webhook/test-card setup steps.
- `main.py`'s startup hook refuses to boot if `SECRET_KEY` is still the
  default dev value and `APP_BASE_URL` isn't `localhost` — this is
  intentional (a forgotten `SECRET_KEY` in production silently signs every
  session cookie with a public string). Don't relax it; set a real
  `SECRET_KEY` in the deploy environment instead.
- `auth.py` only marks the session cookie `Secure` when `APP_BASE_URL`
  starts with `https://`, so it still works over plain `http://localhost`
  in dev but won't be sent unencrypted once deployed behind HTTPS.
