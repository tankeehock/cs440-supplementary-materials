# XSS lab

> ### ⚠ Deliberately vulnerable
> This server ships three live cross-site scripting bugs by default. It is a
> teaching target in the spirit of DVWA or WebGoat. Run it on localhost, never
> expose it to a network, and never copy these patterns into real code.
> `--safe` fixes all three so you can fire the same payloads at both.

One tiny Flask site, three pages, the three classic flavours of XSS side by
side:

| page | type | where the payload lives | who writes it into the page |
| --- | --- | --- | --- |
| `/search` | **reflected** | the request (URL / form) | the server, in one response |
| `/guestbook` | **stored** | the server's own storage | the server, in every response |
| `/welcome` | **DOM-based** | the URL `#fragment` | the page's own JavaScript |

All three are the same mistake in different clothes: **untrusted data reaches an
HTML (or JavaScript) context without being encoded for that context.** The
browser cannot tell markup the developer wrote from markup an attacker supplied,
so it parses and runs both.

---

## Run it

```bash
uv run week-11/xss-lab/app.py            # vulnerable, http://127.0.0.1:8000
uv run week-11/xss-lab/app.py --safe     # the three bugs fixed
uv run week-11/xss-lab/app.py --port 9000
```

Flask is declared in a [PEP 723](https://peps.python.org/pep-0723/) header
inside `app.py`, so uv builds a throwaway environment on first run — no
`uv sync`, no `pip install`. All state is in memory; restarting resets the
guestbook. It binds to `127.0.0.1` only.

The proof-of-concept payloads below pop an `alert()` box. Read `alert(1)` as
"arbitrary code here": a payload that can open a box can also read your session
cookie, make requests as you, or rewrite the page to phish — it runs in your
browser, in your session, on the site's own origin.

---

## 1. Reflected — `/search`

The server copies your search term straight into the results page and sends it
back. Nothing is saved; the payload lives in the URL.

**Try it.** Search for, or open the URL:

```
/search?q=<script>alert(document.domain)</script>
```

The box pops. Because the payload is in the link, a real reflected attack is
*"get the victim to click a URL you crafted"* — a link in an email, a chat
message, or embedded in another page. Only that one victim, only that one
response.

---

## 2. Stored — `/guestbook`

Sign the guestbook with a message, and it is saved and shown to **everyone** who
visits afterwards.

**Try it.** Sign with the message:

```
<script>alert(document.domain)</script>
```

Reload, or open `/guestbook` in a different browser. It fires for every visitor,
with no crafted link — they just open a normal, trusted URL. That persistence is
what makes stored XSS the most dangerous of the three: one POST by the attacker,
then it runs in every reader's session.

---

## 3. DOM-based — `/welcome`

The server sends the **same** payload-free HTML every time — open "view source"
and your input is not there. The bug is in the JavaScript the page ships: it
reads `location.hash` (the part after `#`) and assigns it to `innerHTML`. The
browser never sends the `#...` fragment to the server, so there is nothing to
see or fix server-side.

**Try it.** Append to the URL and press Enter:

```
/welcome#<img src=x onerror=alert(document.domain)>
```

Note the `<img onerror>` rather than a `<script>` tag: the HTML spec says a
`<script>` inserted via `innerHTML` does **not** execute, so DOM-XSS payloads
reach for event handlers (`onerror`, `onload`) instead. Same bug, different
payload shape.

---

## Then fix them, and try again

Restart with `--safe` and fire the exact same three payloads. Each box now shows
your input as literal text instead of running it. One function changes:

- **Reflected and stored** (`enc()` in `app.py`): the server HTML-escapes the
  data before writing it, so `<` becomes `&lt;` and the browser renders the
  characters instead of parsing them as a tag.
- **DOM-based** (`/welcome`): the client switches from `innerHTML` (parse as
  markup) to `textContent` (insert as text). The fix for a client-side sink is
  client-side.

The lesson in one sentence: **encode data for the context you drop it into, and
prefer sinks that treat it as text.** In vulnerable mode `enc()` is a no-op on
purpose — real frameworks (Jinja2, React, …) escape by *default*, so forgetting
is what takes effort, not remembering.

---

## Where XSS stops

Output encoding is the primary fix, but defence in depth helps when something
slips through:

- **`HttpOnly` cookies** keep `document.cookie` out of JavaScript's reach, so a
  payload cannot read the session token (it can still *act* as the user).
- **Content-Security-Policy** can block inline scripts and untrusted sources,
  turning many injections into inert text even if encoding was missed.
- **Framework defaults**: use a template engine that auto-escapes and never
  hand-concatenate HTML, as this file does to be unsafe.
