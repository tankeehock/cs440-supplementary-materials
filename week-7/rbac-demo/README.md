# RBAC demo server

> ### ⚠ Deliberately vulnerable
> This server ships **seven planted bugs** — three broken authorisation checks
> and four output-encoding flaws — and they are live by default. It is a
> teaching target in the spirit of DVWA or WebGoat. Run it on localhost, never
> expose it to a network, and never copy these patterns into real code.
> `--safe` fixes the output-encoding family so you can compare.

A small Flask application whose only real feature is **saying no correctly**.

The rest of week 7 is about ACLs, which attach the policy to the *object*: this
file lists these principals with these rights. RBAC attaches it to the
*subject* instead, through a level of indirection:

```
subject ──assigned──▶ role ──grants──▶ permission ──guards──▶ action
```

Nobody is ever granted a permission directly. They are put in a role, and the
role carries the permissions. That indirection is the whole idea: when someone
changes jobs you change one role assignment, not every object they touched.

Everything the server decides is printed to the console as a trace, and the
same trace is readable at `/audit` — which is itself behind a permission, so
you need the right role to see it.

---

## Run it

```bash
uv run week-7/rbac-demo/app.py               # http://127.0.0.1:8000
uv run week-7/rbac-demo/app.py --port 9000
uv run week-7/rbac-demo/app.py --policy      # print the policy matrix and exit
uv run week-7/rbac-demo/app.py --quiet       # suppress the decision traces
uv run week-7/rbac-demo/app.py --safe        # fix the steps 10-13 bugs
```

Flask is declared in a [PEP 723](https://peps.python.org/pep-0723/) header
inside `app.py`, so uv builds a throwaway environment on first run — no
`uv sync`, no `pip install`. All state is in memory; restarting resets the
data, the role assignments and the session keys. It binds to `127.0.0.1` only.

> Port 8000 rather than Flask's usual 5000, because macOS uses 5000 for AirPlay
> Receiver and the collision is confusing.

## Accounts

| user | password | roles | can do |
| --- | --- | --- | --- |
| `carol` | `carol123` | viewer | read reports |
| `bob` | `bob123` | editor | read + create reports |
| `dave` | `dave123` | auditor | read reports + read the audit log |
| `alice` | `alice123` | admin | everything, including role assignment |
| `mallory` | `mallory123` | *(none)* | **nothing** — authenticated, authorised for nothing |

`mallory` is the account worth remembering. Logging in successfully and being
allowed to do something are different questions, and the server answers them in
different places: `current_user()` for authentication, `check()` for
authorisation.

Passwords are printed here because it is a teaching demo. They are still stored
as salted `scrypt` hashes and compared in constant time — week 6's lesson.

---

## The policy

The entire security model is three tables at the top of `app.py`. You can read
it in one screen, which is the argument for RBAC in a sentence.

| role | inherits | report:read | report:write | report:delete | audit:read | user:manage |
| --- | --- | :-: | :-: | :-: | :-: | :-: |
| `viewer` | — | ✔ | | | | |
| `editor` | viewer | ✔ | ✔ | | | |
| `auditor` | viewer | ✔ | | | ✔ | |
| `admin` | editor, auditor | ✔ | ✔ | ✔ | ✔ | ✔ |

Roles **inherit**, so `admin` never restates what `editor` already grants. The
server serves this same matrix at `/policy`, deliberately without requiring a
login: the policy is not the secret, the credentials are.

---

## Walkthrough

Everything below is designed to be run **in order, against one freshly started
server**, with the console visible in a second terminal — the traces printed
there are half the lesson. Steps 1-5 change nothing; the three broken endpoints
that follow each destroy a different report on purpose, so they do not spoil
each other.

**Restarting the server resets everything** — reports, role assignments and
sessions. Do that whenever you want a clean slate.

```bash
# terminal 1                              # terminal 2
uv run week-7/rbac-demo/app.py            curl ...
```

The seed data is three reports with three different authors, which is what
makes ownership a real question in step 8:

| id | title | author |
| --- | --- | --- |
| 1 | Q3 incident review | `bob` |
| 2 | Access review 2026 | `alice` |
| 3 | Phishing drill notes | `dave` |

### 1. Watch a denial happen

Log in as `carol` and open `/reports`. She can read them, and there is no
"create" form — she lacks `report:write`. Now try it anyway from another
terminal:

```bash
curl -u carol:carol123 -X POST -H 'Content-Type: application/json' \
     -d '{"title":"nope"}' http://127.0.0.1:8000/api/reports
```

```json
{"error":"no role held by this subject grants report:write",
 "required":"report:write","roles":["viewer"],"subject":"carol"}
```

and on the server console:

```
  [DENY ] POST   /api/reports    subject=carol      needs=report:write
          roles     : viewer
          expands to: report:read
          reason    : no role held by this subject grants report:write
```

The trace is the reference monitor thinking out loud: subject, roles held,
what those roles expand to, what was required, verdict.

### 2. Watch inheritance do its job

```bash
curl -u bob:bob123 http://127.0.0.1:8000/api/whoami
```

```json
{"subject":"bob","roles":["editor"],"effective_roles":["editor","viewer"],
 "permissions":["report:read","report:write"]}
```

`bob` was assigned exactly one role. `report:read` arrives through
`editor → viewer`, and nothing in the policy mentions bob at all.

### 3. Watch 401 and 403 differ

```bash
curl -i http://127.0.0.1:8000/api/reports                      # 401
curl -i -u mallory:mallory123 http://127.0.0.1:8000/api/reports # 403
```

**401** means "I do not know who you are"; **403** means "I know, and no."
Returning 403 to an anonymous request, or 401 to an authenticated one, leaks
information about which credentials would have worked. This is a real bug
class, not pedantry.

### 4. Change the policy without changing the code

Log in as `alice`, go to `/admin/users`, grant `viewer` to `mallory`. Then,
with no restart and no code change:

```bash
curl -u mallory:mallory123 http://127.0.0.1:8000/api/reports    # now 200
```

That is the payoff. Authorisation moved because *data* moved.

### 5. Read the audit log — if you may

```bash
curl -u dave:dave123  http://127.0.0.1:8000/audit    # 200, auditor
curl -u bob:bob123    http://127.0.0.1:8000/audit    # 403, editor
```

The log of access decisions is itself an object under access control. Systems
that forget this let an attacker read, or quietly edit, the record of what they
did.

---

## Steps 6-8: three endpoints that are broken on purpose

Section 6 of `app.py` holds three routes that get authorisation wrong, in the
three ways real applications get it wrong. Each has a correct twin elsewhere in
the file, and the difference between them is a line or two — which is the
lesson. **Broken authorisation does not look broken. It looks like working code
with a line missing.**

| Step | Bug | Endpoint | Correct twin | What is missing |
| --- | --- | --- | --- | --- |
| 6 | No check at all | `/broken/reports/<id>/delete` | `delete_report()` | `@requires("report:delete")` |
| 7 | Check trusts the client | `/broken/reports/<id>/delete-checked` | `check()` | server-held state |
| 8 | Right check, wrong granularity (IDOR) | `/broken/reports/<id>/edit` | `api_edit()` | `may_modify(user, report)` |

### 6. No check at all

The route confirms you are **logged in** and stops there. Authentication
mistaken for authorisation. carol is a viewer, and **report 1** is bob's:

```bash
curl -u carol:carol123 -X POST \
     http://127.0.0.1:8000/broken/reports/1/delete       # 200, deleted
```

Now the guarded route, same user, same intent:

```bash
curl -u carol:carol123 -X DELETE \
     http://127.0.0.1:8000/api/reports/2                 # 403
```

The bug is invisible from a browser, because the UI hides the delete button for
users without `report:delete`, so the feature looks protected.
**The button is a hint, not a control.**

### 7. A check that trusts the client

More interesting, because there *is* a check. It runs on every request, it
returns a correct-looking 403 when it fails, and reviewers skim past it:

This one takes **report 3**, which belongs to dave:

```bash
curl -u carol:carol123 -X POST \
     http://127.0.0.1:8000/broken/reports/3/delete-checked
# 403 {"error":"role 'viewer' may not delete reports"}      the check works!

curl -u carol:carol123 -H 'X-Acting-Role: admin' -X POST \
     http://127.0.0.1:8000/broken/reports/3/delete-checked
# 200 {"deleted":3,"real_roles":["viewer"],"claimed_role":"admin"}
```

carol said she was an admin, and the server believed her. This gets written
when someone builds a "switch role" feature, keeps the active role in a header
or hidden field so the front end can manage it, then reads that field back for
the security decision.

> **The rule:** an authorisation decision may only read state **the server
> itself holds**. Everything from the client is input — headers, cookies,
> hidden fields, JSON bodies, the URL, and any `user_id`, `role` or `is_admin`
> among them. Compare `check()`, whose two inputs are a `User` the server
> looked up and a permission the *route* named. Neither can be influenced by
> the caller.

### 8. The right check, at the wrong granularity

The subtlest of the three, and the one that survives code review, because the
decorator is not a mistake:

```python
@app.post("/broken/reports/<int:rid>/edit")
@requires("report:write")           # correct, necessary — and not enough
def broken_edit(rid): ...
```

It proves you may edit reports. It cannot prove you may edit **this** report,
because permissions name verbs, not objects — `report:write` contains no
report — so the id in the URL goes unexamined:

**Report 2 belongs to alice.** bob is an editor who does not own it:

```bash
curl -u bob:bob123 -X POST -H 'Content-Type: application/json' \
     -d '{"title":"bob was here"}' \
     http://127.0.0.1:8000/broken/reports/2/edit
# 200 {"owner":"alice","editor":"bob","title_was":"Access review 2026", ...}
```

Now the correct twin — same decorator, four more lines:

```bash
curl -u bob:bob123 -X POST -H 'Content-Type: application/json' \
     -d '{"title":"bob again"}' \
     http://127.0.0.1:8000/api/reports/2/edit
# 403 {"error":"report 2 belongs to alice",
#      "note":"RBAC allowed the verb; ownership denied the noun"}
```

Check that the correct route still lets the right people through, or you have
only proved it refuses everybody:

```bash
curl -u alice:alice123 -X POST -H 'Content-Type: application/json' \
     -d '{"title":"alice edits her own"}' \
     http://127.0.0.1:8000/api/reports/2/edit           # 200, she owns it

curl -u carol:carol123 -X POST -H 'Content-Type: application/json' \
     -d '{"title":"nope"}' \
     http://127.0.0.1:8000/api/reports/2/edit           # 403, no report:write
```

This is **IDOR** — Insecure Direct Object Reference, or broken object-level
authorisation — number one in the OWASP API Security Top 10. The fix is the
two-layer check in `may_modify()`: RBAC decides whether the verb is available
to you at all, and an object-level rule decides whether this particular noun is
yours.

### 9. What they share: the audit log stays clean

Having run steps 6, 7 and 8, go and look for them:

```bash
curl -u dave:dave123 http://127.0.0.1:8000/audit | grep broken
```

Only **step 8** is there — and it is logged as an **ALLOW**.

Steps 6 and 7 never call `check()`, so the record of who was refused contains
no trace of the bypass whatsoever. #3 does appear, honestly, as a success,
because the check that ran genuinely succeeded; it was answering a coarser
question than the situation required.

> A clean audit log is not evidence that nothing happened. It is evidence that
> nothing *the monitor was asked about* happened.

### Finding these as a tester

All three connect to the privilege-escalation section of
[`../README.md`](../README.md). The enumeration is the same in each case: log
in as the **lowest-privileged account** that can reach an endpoint at all, then

- replay the high-privilege requests the UI never offered you (step 6),
- re-send them with any identity or role field you can find, tampered (step 7),
- walk the object id in the URL and see what comes back (step 8).

Anything the server does not re-check, it grants. Sequential integer ids make
step 8 trivial to find; UUIDs make it slower and not one bit safer, because
obscurity is not the control.

---

## Reading the code

`app.py` is one file, in the order the ideas depend on each other:

| Section | What it holds |
| --- | --- |
| 1. The policy | `PERMISSIONS`, `ROLES`, `SEED_USERS`, `expand_role()` |
| 2. Subjects | `User`, scrypt password hashing |
| 3. Objects | the in-memory reports |
| 4. The reference monitor | `check()`, `current_user()`, `requires()` |
| 5. The web app | routes, HTML, JSON API |
| 6. Broken on purpose | three endpoints, three ways to get it wrong |

Three properties are worth noticing while reading:

1. **One decision point.** `check()` is the only function that computes
   "allowed". One place to audit, one place to test, one place to get wrong.
2. **Routes name permissions, never people.** Every guard is
   `@requires("report:delete")` — never `if user.name == "alice"`, never
   `if "admin" in user.roles`. Checking the *role* instead of the permission is
   the subtle version of the same mistake: it hard-codes today's policy into
   the handler and quietly breaks the moment a new role needs the same access.
3. **Deny by default.** No matching role, no roles at all, no session, or a
   permission that does not exist — every path ends at denied. A policy engine
   should fail closed, including when the failure is a typo in the policy.

---

## Steps 10-13: bypassing every check without touching one

The three bugs above break authorisation directly. This family does something
worse: it defeats the guards **without going near them**.

If a value a user controls reaches the page unescaped, that user can store a
script — and the script runs in the **next** visitor's browser, with that
visitor's session and that visitor's roles. `check()` is not violated. The
victim's browser makes the request, the victim's roles are checked, and the
check honestly passes. Every `@requires` is intact and completely bypassed.

| Step | Bug | Who can set it | Whose browser runs it |
| --- | --- | --- | --- |
| 10 | Stored XSS — report title/body | anyone with `report:write` | anyone with `report:read` |
| 11 | Reflected XSS — `?next=` on `/login` | anyone with a link | whoever clicks it |
| 12 | Stored XSS — **the request path**, on `/audit` | **anyone at all** | the **auditor** |
| 13 | Open redirect — `next=` on `POST /login` | anyone with a link | whoever clicks it |

All four are live by default. Run the server with `--safe` to turn output
encoding on and fire the identical payloads at it — that comparison is the
lesson, so do both.

### 10. Stored XSS, and why it is an RBAC bug

Log in as `bob` (editor) in the browser and create a report titled:

```html
<script>alert(1)</script>
```

It fires for every user who opens `/reports`. Now the version that shows what
it is actually worth — the same injection, escalating privilege:

```html
<script>fetch("/admin/users/mallory/roles",{method:"POST",
  headers:{"Content-Type":"application/x-www-form-urlencoded"},
  body:"role=admin&action=grant"})</script>
```

bob holds `report:write` and nothing else. `mallory` holds no roles at all.
Store that as a report title as bob, then open `/reports` **as alice**, and:

```bash
curl -u mallory:mallory123 http://127.0.0.1:8000/api/whoami
# {"roles":["admin"],"permissions":["audit:read","report:delete", ...]}
```

An editor just granted the admin role, using the admin's own browser. Then look
at `/audit`: the request is logged as a perfectly ordinary **ALLOW for alice**,
because from the reference monitor's point of view that is exactly what it was.
Nothing detected anything, because nothing went wrong — in section 4's terms.

(Nothing stops the request either: this app has no CSRF token, so the injected
`fetch` is accepted on alice's cookie alone. Output encoding and CSRF defence
are separate controls, and both are missing here.)

### 11. Reflected XSS

No stored data needed, just a link somebody clicks:

```bash
curl 'http://127.0.0.1:8000/login?next="><script>alert(3)</script>'
```

The value is interpolated into the hidden `next` field, and `">` closes the
attribute and the tag. A login page is the ideal host for this, because it is
where people expect to type a password.

### 12. Being refused is enough

The one to sit with. `check()` records `request.path` on **every** decision,
`/audit` renders it, and a **denied** request is still recorded:

```bash
# mallory holds no roles and is refused everything
curl -u mallory:mallory123 -X POST \
  'http://127.0.0.1:8000/admin/users/<img src=x onerror=alert(6)>/roles'
# 403. And the 403 is logged, with her path.
```

Now `dave` opens `/audit` — the security log, the page an auditor is *most*
likely to visit — and it fires in his browser. mallory needed no permission
whatsoever. She only needed to be **rejected**, at a route whose path she
chooses. The log of who was refused became the delivery mechanism.

Note it must be a route that *matches* but denies: `/admin/users/<name>/roles`
takes a string, so anything matches. `/api/reports/<int:rid>` would 404 at
routing and never reach `check()`.

### 13. Open redirect

```bash
curl -i -X POST -d 'username=bob&password=bob123&next=https://example.com/evil' \
     http://127.0.0.1:8000/login
# Location: https://example.com/evil
```

The user authenticated against a domain they trust and was handed straight to
one they should not. This is how a phishing link is built out of a legitimate
login page. `//example.com` works too, which is why `is_safe_next()` tests the
second character as well as the first.

### Then fix them, and try again

```bash
uv run week-7/rbac-demo/app.py --safe
```

Every payload above becomes inert. The whole fix is one function — `out()` in
section 5 — and that is the last point worth making: the real defence is not
"remember to call `out()`", because this file calls it in fourteen places and
would only need to miss one. It is to use a template engine that escapes **by
default**, so being unsafe is the thing you have to ask for. Escaping by hand
means being right every single time.

## Where RBAC stops

RBAC answers "may this *kind of* user do this *kind of* thing". It cannot
express "may **this** user touch **this** record" — bob may edit reports, but
should he edit *alice's* report? That question is about the object, and it needs
either an ACL (week 7's main lab), an ownership check, or ABAC. Real systems run
both layers: RBAC decides whether the verb is available to you at all, and a
per-object check decides whether this particular noun is yours.

This demo deliberately implements only the first layer, so you can see where the
gap is: every user with `report:write` can edit every report.
