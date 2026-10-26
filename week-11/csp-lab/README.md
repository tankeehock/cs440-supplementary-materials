# CSP lab

> ### ⚠ Deliberately vulnerable
> Every page in this server ships a live reflected cross-site scripting bug. It
> is a teaching target in the spirit of DVWA or WebGoat. Run it on localhost,
> never expose it to a network, and never copy the vulnerable patterns into real
> code. `--safe` applies a strict policy to every page so you can fire the same
> payload at both.

The capstone to the [xss-lab](../xss-lab) next door. The xss-lab taught the
*primary* fix for XSS — **encode untrusted data for its context**. This lab is
about the *second wall*, the one that catches the day you forget: a
**Content-Security-Policy** (CSP), an HTTP response header that tells the browser
which scripts it is allowed to run, so a script an attacker managed to inject
simply never executes.

To isolate the lesson, every page ships the **same** bug — the reflected-XSS
`/search` sink from the xss-lab, copying `?q=` into the HTML with no encoding.
Nothing about the bug changes between pages. Only the CSP header changes, and
that alone decides whether the injection runs:

| page | CSP header | the same injection… |
| --- | --- | --- |
| `/none` | *(none sent)* | **runs** — CSP is opt-in; absent, nothing stops it |
| `/unsafe` | `script-src 'self' 'unsafe-inline' …` | **still runs** — the classic false sense of security |
| `/strict` | `script-src 'nonce-RANDOM'; object-src 'none'; base-uri 'none'` | **blocked** — injected script has no nonce |

---

## Run it

```bash
uv run week-11/csp-lab/app.py            # vulnerable, http://127.0.0.1:8000
uv run week-11/csp-lab/app.py --safe     # strict CSP on every page
uv run week-11/csp-lab/app.py --port 9000
```

Flask is declared in a [PEP 723](https://peps.python.org/pep-0723/) header inside
`app.py`, so uv builds a throwaway environment on first run — no `uv sync`, no
`pip install`. State is per-request; it binds to `127.0.0.1` only.

**Open your browser's dev-tools console before you start.** The whole lesson of
the strict page is the violation it logs when the browser refuses the injected
script.

The proof-of-concept payloads below pop an `alert()` box. Read `alert(1)` as
"arbitrary code here": a payload that can open a box can also read your session
cookie, make requests as you, or rewrite the page to phish. CSP's job is to stop
that payload from running in the first place.

---

## What a CSP is (and is not)

A CSP is an allow-list the **server sends** and the **browser enforces**. For
scripts, the directive that matters is `script-src`: it lists what may run. If a
`<script>` tag or an inline event handler is not covered by the policy, the
browser refuses to execute it and reports a violation.

- **CSP is defence in depth, not a primary fix.** It does not stop the injection
  from *landing* in the HTML — output encoding does that. CSP stops the injected
  markup from *doing* anything once it has landed. Deploy both; this lab leaves
  the encoding bug open on purpose so there is a live injection for the CSP to
  catch or miss.
- **A CSP is only as strong as its weakest directive.** `'unsafe-inline'` in
  `script-src` defeats the entire purpose — it tells the browser "run any inline
  script", which is exactly what an injected inline script is.
- **The modern strong recipe is a per-response nonce**: a fresh random token put
  on every legitimate `<script>` tag and named in the policy
  (`script-src 'nonce-RANDOM'`). The attacker cannot guess the token, so injected
  tags are refused while the site's own tags run.

---

## 1. No CSP — `/none`

No `Content-Security-Policy` header is sent, so the browser runs whatever is in
the page.

**Try it.** Search for, or open the URL:

```
/none?q=<script>alert(document.domain)</script>
```

The box pops. This is the baseline — and the default for any site that has never
deployed a CSP. The reflected-XSS bug is fully live.

---

## 2. unsafe-inline — `/unsafe`

This page sends a **real-looking** policy — it even scopes scripts to `'self'`
and a CDN:

```
Content-Security-Policy: script-src 'self' 'unsafe-inline' https://cdn.example.com
```

**Try it.** The exact same payload:

```
/unsafe?q=<script>alert(document.domain)</script>
```

The box pops anyway. `'unsafe-inline'` tells the browser to run *any* inline
script, which is precisely what the injected `<script>` is. This is the single
most common real-world CSP mistake: a policy that stops nothing it was deployed
to stop, while giving everyone a false sense of security because "we have a CSP".

> A subtlety worth knowing: the page also puts a nonce on its *own* script tag,
> yet `'unsafe-inline'` is still honoured. That is because the browser only
> ignores `'unsafe-inline'` when a nonce or hash appears **in the policy
> string** — a nonce on a tag alone does nothing. The fix on `/strict` puts the
> nonce in the policy.

---

## 3. Strict nonce — `/strict`

This page sends a strict policy with a fresh per-response nonce and no inline:

```
Content-Security-Policy: script-src 'nonce-RANDOM'; object-src 'none'; base-uri 'none'
```

**Try it.** Both payload shapes:

```
/strict?q=<script>alert(document.domain)</script>
/strict?q=<img src=x onerror=alert(document.domain)>
```

No box. Watch the console:

- the injected `<script>` has no nonce, so it is **refused** (`Refused to
  execute inline script because it violates … 'nonce-…'`);
- the injected `<img onerror=…>` is an **inline event handler** — a nonce does
  not cover those, so it is refused too;
- meanwhile the page's **own** `<script>`, which carries this response's nonce,
  still runs (you see "✓ The page's own nonce'd script ran").

The bug is still there — `?q=` is still reflected un-encoded, same as `/none`.
The CSP has not fixed the bug; it has made the injection **inert**. That is
exactly the "turns a missed encoding into an inert string" line from the
xss-lab's remediation.

---

## Then apply it everywhere, and try again

Restart with `--safe` and fire the exact same payloads at all three pages. Each
one now sends the strict nonce policy, so the injection is blocked everywhere —
including on `/none` and `/unsafe`, which no longer get to misbehave. One
function changes: `csp_for()` in `app.py` returns `strict_policy(nonce)` for
every page.

---

## Inspect it without a browser

The headers are the whole story, and `curl` shows them plainly:

```bash
curl -i "http://127.0.0.1:8000/none?q=x"     # no CSP header
curl -i "http://127.0.0.1:8000/unsafe?q=x"   # the unsafe-inline policy
curl -i "http://127.0.0.1:8000/strict?q=x"   # the nonce policy (fresh each request)
```

Note the nonce on `/strict` is different on every request — that is the point of
a nonce. A policy whose nonce is static or reused is no better than no nonce.

---

## Remediation

In priority order.

1. **Fix the XSS first; CSP is the second wall.** Contextually output-encode
   untrusted data and use a template engine that does it by default (the xss-lab
   covers this). A CSP is insurance for the encoding you missed, not a substitute
   for encoding.
2. **Deploy a nonce- (or hash-) based `script-src` with no `'unsafe-inline'`.**
   Generate a fresh random nonce per response, name it in the policy, and put it
   on every legitimate `<script>`. For apps that load scripts dynamically, add
   [`'strict-dynamic'`](https://web.dev/articles/strict-csp) so a nonce'd script
   may load further scripts without each needing its own nonce — and so host
   allow-lists (a frequent source of bypass gadgets) can be dropped entirely.
3. **Lock the other script vectors.** `object-src 'none'` (kills Flash/plugin
   injection), `base-uri 'none'` (stops an injected `<base>` from rewriting where
   relative script URLs resolve). These are cheap and close real bypasses.
4. **Avoid the footguns:** `'unsafe-inline'` and `'unsafe-eval'` in `script-src`,
   broad host wildcards (`https:`, `*`, or a CDN that hosts JSONP/Angular/`eval`
   gadgets an attacker can abuse), and a nonce that is static, guessable, or
   reused across responses.
5. **Roll out with `Content-Security-Policy-Report-Only` and a `report-to`
   endpoint first.** You get the violation reports without breaking the site, so
   you can find every legitimate inline script before you enforce.
6. **Remember CSP's limits.** It is enforced by the browser, so it does not
   protect non-browser API clients, and it does not stop the injection from
   *reaching* the page. It reduces the *impact* of an XSS; it does not remove the
   vulnerability.

---

## Finding it in a code review (interview checklist)

CSP review is two separate questions — *is there a policy?* and *is the policy
any good?* — and the second is where the findings are.

**Is there a policy at all?**

- Grep responses/headers/middleware for `Content-Security-Policy`. Absent on
  HTML responses → no second wall (the `/none` case).
- Set via a `<meta http-equiv>` tag only? That works but cannot express some
  directives (e.g. frame-ancestors) and is editable by an injection that lands
  before it — prefer the header.

**Is the policy any good? — the weak-directive hunt:**

| Red flag in `script-src` | Why it is a finding |
| --- | --- |
| `'unsafe-inline'` | runs any injected inline script — defeats the policy (the `/unsafe` case) |
| `'unsafe-eval'` | re-enables `eval`/`Function`/string `setTimeout` — a code sink |
| `*`, `https:`, broad host | any origin (or any HTTPS site) can host the "trusted" script |
| a CDN with known gadgets | JSONP endpoints, old AngularJS, etc. let an attacker smuggle execution past an allow-list |
| a static / reused / guessable nonce | an attacker can just copy the nonce onto their tag |
| no `object-src` / `base-uri` | plugin and `<base>` injection vectors left open |

**Then check the nonce is real:** generated per response from a CSPRNG
(`secrets.token_urlsafe`, not a timestamp or counter), and the same value in the
header and on the tags. A nonce on the tags but not in the policy (this lab's
`/unsafe`) does nothing.

**Grep first:** `Content-Security-Policy`, `unsafe-inline`, `unsafe-eval`,
`script-src`, `nonce`, `report-only`.

In this lab the three findings are exactly those shapes: a response with no CSP
(`/none`), a CSP neutered by `'unsafe-inline'` (`/unsafe`), and — as the
contrast — a correct nonce policy (`/strict`) that still runs the site's own
script while refusing the injected one.

---

## Where this sits with the other week-11 labs

- [`xss-lab`](../xss-lab) — the bug this lab defends against, in its three
  flavours, and the *primary* fix (output encoding).
- [`cors-lab`](../cors-lab) — a different browser-enforced policy
  (`Access-Control-Allow-Origin`) with its own classic misconfigurations. CORS
  governs who may **read** a response; CSP governs what script may **run**. Both
  are headers the server sends and the browser enforces, and both are only as
  good as the exact strings in them.
