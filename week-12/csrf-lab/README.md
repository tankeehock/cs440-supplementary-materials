# CSRF lab — your browser, acting against you

> ### ⚠ Deliberately vulnerable, localhost only
> This runs **two** servers — a "bank" and an "attacker" site — both bound to
> `127.0.0.1`. The bank's money-transfer action trusts the session cookie alone
> by default. It is a teaching target in the spirit of DVWA / WebGoat. Never
> expose it, and never copy these patterns into real code. `--safe` adds a CSRF
> token and makes the action POST-only.

Cross-Site Request Forgery abuses one browser behaviour: **the browser attaches
your cookies to a request based on where the request is *going*, not on which
site *caused* it.** So a page on `evil.com` can make your browser fire a
logged-in request at `bank.com`, carrying your bank cookie, and the bank — which
sees a valid session — does the thing.

Two sites, because it takes two origins:

| origin | role | what it is |
| --- | --- | --- |
| `http://127.0.0.1:8000` | **the bank** | you log in; you can transfer money |
| `http://127.0.0.1:9000` | **the attacker** | a page that forges transfers from your account |

The crucial contrast with the [cors-lab](../../week-11/cors-lab/): CORS is about
an attacker **reading** your data, and the Same-Origin Policy already blocks
that by default. CSRF is about an attacker **triggering an action** — a
*write* — and the attacker never needs to read the response at all. So SOP and
CORS do nothing to stop it; it needs its own defence.

---

## Run it

```bash
uv run week-12/csrf-lab/app.py            # vulnerable, bank :8000 / evil :9000
uv run week-12/csrf-lab/app.py --safe      # both vectors fixed
uv run week-12/csrf-lab/app.py --bank-port 8100 --evil-port 9100
```

Flask is declared in a [PEP 723](https://peps.python.org/pep-0723/) header, so
uv builds a throwaway environment on first run. Both servers bind `127.0.0.1`
only; all state is in memory. Use Chrome or Firefox.

---

## The scenario

Open the bank at `http://127.0.0.1:8000` and click **Log in as Alice**. You get
a session cookie and a $1000 balance, and a form to transfer money. A normal
transfer works the same in both modes — that is the legitimate use we must not
break.

Now you are the victim: logged in, cookie in your browser. Keep that tab open
and visit the attacker's page. You will not click anything there.

---

## 1. Forged POST — the auto-submitting form

The attacker's page contains a hidden `<form>` pointed at the bank's
`/transfer`, with the recipient and amount pre-filled, and a line of script that
**submits it on page load** into an invisible frame:

```html
<form action="http://127.0.0.1:8000/transfer" method="POST" target="sink">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="500">
</form>
<script>document.getElementById("f").submit();</script>
```

**Try it.** With the bank logged in, open `http://127.0.0.1:9000`. Go back to
the bank tab and refresh: **$500 is gone** and a transfer to `attacker` is in
your history. You never saw a form, never clicked submit.

Why it works: the POST goes to the bank, so the browser attaches your bank
cookie. The bank's vulnerable `/transfer` checks only that cookie — a valid
session — and cannot tell this request originated on the attacker's page instead
of its own. (The attacker can't *read* the bank's reply — the Same-Origin Policy
blocks that — but it doesn't need to. The money already moved.)

---

## 2. Forged GET — just an image tag

The bank's vulnerable endpoint also accepts a transfer over **GET**. That is a
second, worse bug, because a GET needs no form and no JavaScript — an `<img>`
whose "source" is the transfer URL is enough:

```html
<img src="http://127.0.0.1:8000/transfer?to=attacker&amount=250">
```

**Try it.** The same attacker page includes exactly this tag. When the browser
tries to load the "image", it fires a GET transfer — with your cookie attached —
and **$250 more** leaves your account. An image on a forum post, in an email, in
an ad, would do the same.

The lesson: **never change state on a GET.** GETs get prefetched, cached,
embedded as images, and followed by crawlers; anything that mutates data must be
a POST (or PUT/DELETE) *and* carry a token — see below.

---

## Then fix them, and try again

Restart with `--safe` and repeat both attacks. The POST is now **rejected
(missing or invalid CSRF token)** and the GET is **rejected (transfers must use
POST)**. Alice's balance stays at $1000. Two changes do it:

```python
# FIX 1 — state changes only over POST
if request.method != "POST":
    return reject(405)

# FIX 2 — require an unguessable, per-session token, compared in constant time
if not hmac.compare_digest(request.form.get("csrf", ""), session["csrf"]):
    return reject(403)
```

The token (the **synchronizer token pattern**) is a random value the bank
generates per session and embeds in its *own* transfer form. A genuine request
from the bank's page carries it; the attacker's forged request cannot, for three
reasons that all have to hold:

- **Unpredictable** — `secrets.token_hex(16)`, so it can't be guessed.
- **Per session** — tied to your session, so a token from the attacker's own
  bank session won't validate against yours.
- **Not readable cross-origin** — it lives in the page body, not in a cookie, so
  it doesn't ride along automatically; and the attacker can't fetch the bank's
  page to scrape it, because the Same-Origin Policy blocks reading the response.
  *This is where SOP finally helps CSRF defence — by keeping the token secret.*

The lesson in one sentence: **a cookie proves who you are, not that you meant to
send this request — so require a per-session token the attacker cannot obtain,
and never mutate state on a GET.**

---

## A note on SameSite cookies (the modern first line of defence)

Why isn't the whole web constantly robbed this way? Because browsers now default
cookies to **`SameSite=Lax`**, which tells the browser *not* to attach the
cookie to most **cross-site** requests — including a cross-site form POST. That
alone blocks the classic attack above, and it is why CSRF is less common than it
was.

This lab sets the bank cookie to **`SameSite=None`** on purpose, so the attack
still fires and you can study the real defence. That is not as artificial as it
sounds:

- Plenty of apps genuinely need `SameSite=None` (third-party widgets, SSO,
  embedded flows), and for them the token is the defence that remains.
- `Lax` still allows cookies on **top-level GET navigations**, so a
  state-changing GET reached via a link or redirect can bypass `Lax` — another
  reason vector 2 (don't mutate on GET) matters.
- Defence in depth: set `SameSite=Lax` *or* `Strict` **and** use tokens. Neither
  alone is a reason to skip the other.

> **Localhost caveat.** In this lab the two ports are the *same site*
> (`127.0.0.1`), differing only by origin, so even `SameSite=Lax` would send the
> cookie between them. We set `None` to be explicit and to mirror the real
> cross-*site* case (`evil.com` → `bank.com`), which is the threat the token
> actually defends against.

---

## Where CSRF fits

- **CSRF ≠ XSS.** XSS runs the attacker's script *on your site's origin* and can
  read the token, so it defeats CSRF defences outright — fix XSS first (see the
  [week-11 xss-lab](../../week-11/xss-lab/)).
- **CSRF ≠ CORS.** CORS governs *reading* cross-origin responses; CSRF is a
  blind *write*. A permissive CORS policy doesn't cause CSRF, and a strict one
  doesn't prevent it.
- **Double-submit cookie** is a common tokenless variant: send the token both as
  a cookie and as a form field and check they match. It avoids server-side
  session storage but is weaker if subdomains can set cookies — the synchronizer
  token here is the sturdier default.
