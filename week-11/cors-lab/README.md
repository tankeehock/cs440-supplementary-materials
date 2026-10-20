# CORS lab — who gets to read the response?

> ### ⚠ Deliberately misconfigured, localhost only
> This runs **two** servers — a "bank" API and an "attacker" site — both bound
> to `127.0.0.1`. The bank ships three broken CORS policies by default; the
> flag is made-up data. It is a teaching target in the spirit of DVWA / WebGoat.
> Never expose it to a network, and never copy these header patterns into real
> code. `--safe` fixes all three so you can fire the same attack at both.

Cross-Origin Resource Sharing is the set of rules your browser uses to decide
**whether one website's JavaScript is allowed to read a response from a
different website.** Get the rules wrong on a site that holds private data and
*any* page on the internet can read your logged-in users' data out of their
browsers.

Because CORS is about *two* origins, this lab is two sites:

| origin | role | what it is |
| --- | --- | --- |
| `http://127.0.0.1:8000` | **the bank** | an API that serves Alice's account behind a session cookie |
| `http://127.0.0.1:9000` | **the attacker** | a page you visit that tries to read the bank's response |

A port is part of an origin, so `:8000` and `:9000` are **different origins** —
which is the whole point: the attacker's page is a genuinely foreign origin to
the bank, exactly as `evil.com` is to `bank.com`.

---

## Run it

```bash
uv run week-11/cors-lab/app.py            # vulnerable, bank :8000 / evil :9000
uv run week-11/cors-lab/app.py --safe     # the three bugs fixed
uv run week-11/cors-lab/app.py --bank-port 8100 --evil-port 9100
```

Flask is declared in a [PEP 723](https://peps.python.org/pep-0723/) header
inside `app.py`, so uv builds a throwaway environment on first run. Both servers
bind `127.0.0.1` only; all state is in memory. Use Chrome or Firefox.

---

## Before you start: the Same-Origin Policy, and what CORS changes

By default the browser enforces the **Same-Origin Policy (SOP)**: a page may
*send* a request to any origin, but it may only *read the response* if that
response came from its **own** origin. SOP is why a random site you visit cannot
quietly read your webmail: its script can fire the request, but the browser
hides the reply.

**CORS is the server's way to grant exceptions to SOP.** When a response comes
back, the browser looks for CORS headers on it and uses them to decide whether
to hand the body to the calling page's JavaScript. The two that matter here:

- `Access-Control-Allow-Origin: <origin>` — "this origin may read this
  response." It is a **single** origin or the wildcard `*`, never a list.
- `Access-Control-Allow-Credentials: true` — "...and it may do so even for a
  request that carried cookies."

Three facts that the rest of the lab leans on, and that trip up almost everyone:

1. **CORS is enforced by the browser, not the server.** A blocked cross-origin
   request usually *still reaches the server and still runs*. The browser just
   refuses to show the response to the foreign page. So **CORS is not access
   control, and it is not CSRF protection** — it governs who may *read* a
   response, never who may *send* a request.
2. **To expose a credentialed response, the server must return the *exact*
   origin** in `Access-Control-Allow-Origin` **and** `...Allow-Credentials:
   true`. The browser specifically forbids `*` together with credentials.
3. **`HttpOnly` on the cookie does not help.** The attack never reads the
   cookie; it rides the cookie to read the *response*.

---

## The scenario

Open the bank at `http://127.0.0.1:8000` and click **Log in as Alice**. That
sets a session cookie and the page shows her account — read *same-origin*, which
never involves CORS. Now you are the victim: logged in, cookie in your browser.

Everything below is the attacker trying to read that same account from
`http://127.0.0.1:9000`, a site Alice never logged into.

---

## 1. Reflected origin + credentials — `/api/reflect`

The classic, catastrophic one. The bank reads the incoming `Origin` header and
echoes it straight back into `Access-Control-Allow-Origin`, with
`Access-Control-Allow-Credentials: true`. That satisfies rule 2 above for
*whatever origin asked* — so every origin is allowed.

**Try it (headers).** No browser needed — watch the bank bless a hostile origin:

```bash
curl -i -H "Origin: http://evil.example" http://127.0.0.1:8000/api/reflect
# Access-Control-Allow-Origin: http://evil.example      <- your origin, reflected
# Access-Control-Allow-Credentials: true
```

**Try it (the real attack).** Log in at the bank, then open
`http://127.0.0.1:9000`. The first fetch runs automatically on page load — no
click, no prompt — and Alice's account JSON, cookie and all, appears on the
attacker's page. That is the attack: *visiting a page is enough.*

---

## 2. Naive `startswith()` check — `/api/naive`

Here the developer *tried*. The intent was "only allow our own host,
`127.0.0.1`", so they wrote something like
`if origin.startswith("http://127.0.0.1")`. But an origin includes the **port**,
and the check ignores it — so the attacker on `:9000` passes just as well as the
bank on `:8000`.

**Try it.** On the attacker page, press *fetch /api/naive*. It reads the account
too. The real-world version of this bug is
`origin.startswith("https://bank.com")`, which cheerfully accepts
`https://bank.com.evil.com` — an origin the attacker owns.

The lesson: **validate the *whole* origin against an exact list.** Substring,
prefix, and "contains" checks are all bypassable, because the attacker controls
the parts of their origin string your check didn't pin down.

---

## 3. Wildcard `*` — `/api/wildcard`

The subtle one, and the most misunderstood. The bank sends
`Access-Control-Allow-Origin: *` and no credentials header.

**Try it.** On the attacker page, press *fetch /api/wildcard (with cookies)* —
it is **BLOCKED**, even though the bugs above worked. The browser enforces rule
2 in reverse: a response that says `*` may **not** be read by a credentialed
request. So `*` cannot leak cookie-protected data.

Now press *fetch /api/wildcard (no cookies)* — it **succeeds**, and returns the
unauthenticated `401` body. That is the real risk of `*`: it exposes the
endpoint to *every* origin for requests that don't need a cookie. Harmless for a
truly public API; dangerous the moment the endpoint was relying on **network
position** (an internal service reachable only from the corporate network, say)
rather than a cookie to keep strangers out.

> **Takeaway:** `*` is not the same mistake as reflection. Reflection hands over
> *credentialed* data to anyone; `*` only ever exposes *un*credentialed
> responses. Neither is what you want on private data, but confusing the two is
> how people "fix" a reflection bug by switching to `*` and think they're done.

---

## Then fix them, and try again

Restart with `--safe` and repeat every step. The `curl` reflection now comes
back with **no** `Access-Control-Allow-Origin` for `http://evil.example`, and on
the attacker page all three fetches are **BLOCKED**. One policy replaces all
three:

```python
# --safe: allow only an exact, closed allow-list
allowed = {"http://127.0.0.1:8000"}     # your real front-end origin(s)
if origin in allowed:                    # == , not startswith / in / *
    headers["Access-Control-Allow-Origin"] = origin
    headers["Access-Control-Allow-Credentials"] = "true"
    headers["Vary"] = "Origin"           # so caches don't mix origins up
# unknown origin -> send nothing -> the browser blocks the read
```

The bank's own page still works, because a site reading *itself* is same-origin
and never needed CORS in the first place.

---

## A note on SameSite cookies (why the cookie arrives at all)

For the attack to matter, two separate things must happen: the browser must
**send** Alice's cookie on the cross-origin request, *and* CORS must let the
attacker **read** the reply. This lab is about the second. The first is governed
by the cookie's `SameSite` attribute, and the bank deliberately sets
`SameSite=None` so the cookie is sent — the realistic setting for an API that is
*meant* to serve other origins.

In the wider world `SameSite=Lax` is the browser default, and it would **not**
send the cookie on a cross-*site* request (`evil.com` → `bank.com`), blocking
this particular attack before CORS even enters the picture. That is a real and
valuable defence — but it is a *second* layer, not the fix for a broken CORS
policy: plenty of APIs legitimately set `SameSite=None`, and a reflected-origin
policy betrays every one of them. Fix the CORS policy regardless of SameSite.

---

## Where CORS stops

- **CORS is not CSRF protection.** The request still reaches the server and runs
  even when the read is blocked. State-changing endpoints need their own
  anti-CSRF defences (tokens, `SameSite`), independent of CORS.
- **CORS is not server-side authorization.** Never decide *what to return* based
  on the `Origin` header — it is attacker-controllable and absent on non-browser
  clients. Authenticate and authorize the request on its own merits.
- **Preflight is not a security boundary you can lean on.** "Non-simple"
  requests trigger an `OPTIONS` preflight the browser checks first, but a broken
  allow-origin policy fails preflight and the actual request identically — the
  bug is the policy, not whether a preflight happened.
- **Reflecting `null` is its own trap.** Some apps allow-list the literal origin
  `null`; sandboxed iframes and certain redirects send `Origin: null`, so an
  attacker can arrange to be `null`. `null` is not a safe value to trust.

The lesson in one sentence: **a response may be read cross-origin only by the
exact origins you explicitly trust — so never reflect `Origin`, never pair
credentials with `*`, and remember CORS controls who may read the reply, not who
may send the request.**
