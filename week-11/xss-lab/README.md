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

## Remediation

In priority order — the first item is the fix, the rest are depth.

1. **Contextually output-encode every piece of untrusted data, and prefer a
   template engine that does it by default.** Jinja2 (Flask's default via
   `render_template`), Django templates, and React JSX all auto-escape for the
   HTML context. The remediation for the server-side bugs in this lab is simply
   *to stop hand-concatenating HTML* and let the engine escape — and to not turn
   that escaping off (`| safe`, `{% autoescape false %}`, `Markup()`,
   `dangerouslySetInnerHTML`, `v-html`).
2. **For the DOM, write data as text, not markup.** Assign `textContent`, use
   `setAttribute` / `createElement`, or framework data binding. Treat `innerHTML`,
   `outerHTML`, `insertAdjacentHTML`, and `document.write` as code sinks.
3. **If you must accept rich HTML, sanitise with a vetted library and a strict
   allow-list** — [DOMPurify](https://github.com/cure53/DOMPurify) in the browser,
   `nh3`/`bleach` on the server. Never a hand-rolled regex "sanitiser"; they are
   bypassed as a sport.
4. **Add a Content-Security-Policy** that forbids inline script
   (`script-src 'self'` with per-response nonces/hashes, no `unsafe-inline`). A
   good CSP turns a missed encoding into an inert string instead of code.
5. **Set session cookies `HttpOnly`, `Secure`, `SameSite`.** `HttpOnly` keeps a
   payload from reading the token via `document.cookie` (it does not stop the
   payload acting as the user — encoding is still the fix).
6. **Lock down DOM sinks with [Trusted Types](https://web.dev/articles/trusted-types)**
   (`Content-Security-Policy: require-trusted-types-for 'script'`) so assigning a
   raw string to `innerHTML` throws — a structural guarantee against DOM XSS.

Input validation (allow-listing expected characters) is worth doing but is
**secondary**: it narrows the attack surface, while output encoding is what
actually makes the data safe in its destination.

---

## Finding it in a code review (interview checklist)

Handed this code cold, you find XSS by tracing **untrusted data from a source to
a sink**: does any value a user controls reach an HTML or JavaScript context
without being encoded *for that context*? In a framework that auto-escapes, the
bug is wherever someone opted *out* — so you are hunting for the escape hatch.

**Sources — where untrusted data enters:**

- Server: `request.args` / `form` / `values` / `json`, `request.headers`,
  `request.cookies`, path segments.
- Client: `location.*` (`search`, `hash`, `href`), `document.referrer`,
  `document.cookie`, `window.name`, `postMessage` data — and, for **stored** XSS,
  anything read back from a database, file, or API.

**Sinks — where it becomes markup or code:**

| Kind | What to look for |
| --- | --- |
| hand-built HTML | f-string / `+` / `%` / `.format()` into HTML, `Response(html)` |
| escaping switched off | Jinja `\| safe`, `{% autoescape false %}`, `Markup(...)`, `render_template_string(user_data)` |
| DOM HTML sinks | `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write(ln)`, jQuery `.html()` / `.append(str)` / `$(str)`, React `dangerouslySetInnerHTML`, Vue `v-html`, Angular `[innerHTML]` / `bypassSecurityTrust*` |
| code sinks (worse) | `eval`, `Function`, `setTimeout`/`setInterval("string")`, a `javascript:` URL assigned to `href` / `src` / `location` |

**Grep first:** `innerHTML`, `document.write`, `dangerouslySetInnerHTML`,
`v-html`, `|safe`, `Markup(`, `render_template_string(`, `eval(`.

**Then ask, for each hit:** where does the value come from, does it cross a trust
boundary, what context is it dropped into (HTML body? attribute? JS string? URL?
CSS?), and is it encoded for *that* context — automatically, or by hand?

**Context is the trap.** Escaping for an HTML body (`<` → `&lt;`) does nothing
inside a `<script>` block, a `javascript:` URL, or an unquoted attribute. A value
"sanitised" for the wrong context is still XSS.

In this lab the three findings are exactly those shapes: a request param reaching
the HTML body through the no-op `enc()` (reflected), a stored value re-rendered
the same way (stored), and `location.hash` assigned to `innerHTML` (DOM-based).
Note the DOM one has **no server-side tell at all** — the only way to find it is
to read the client-side JavaScript, which is the step reviewers most often skip.

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
