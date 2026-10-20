# /// script
# requires-python = ">=3.11"
# dependencies = ["flask>=3.0"]
# ///
"""
app.py — three flavours of cross-site scripting, side by side
=============================================================

Week 11's lab target, a companion to the week-7 rbac-demo. One tiny Flask site,
three pages, three bugs:

    /search?q=...     REFLECTED XSS   the server copies your input into THIS
                                      response, and only this one
    /guestbook        STORED XSS      the server saves your input and copies it
                                      into EVERY later visitor's response
    /welcome          DOM-BASED XSS   the server never sees the payload; the
                                      page's own JavaScript reads it from the
                                      URL fragment and writes it into the DOM

All three are the same mistake wearing three coats: **untrusted data reaches an
HTML (or JavaScript) context without being encoded for that context.** The
browser cannot tell markup the developer wrote from markup an attacker supplied,
so it parses and runs both.

                     where the payload lives        who writes it into the page
    reflected        the request (URL / form)       server, one response
    stored           the server's own storage       server, every response
    dom-based        the URL, often the #fragment    the page's JavaScript


WHY THIS IS A SECURITY BUG, NOT A COSMETIC ONE
----------------------------------------------
A successful payload runs JavaScript in the victim's browser, inside the
victim's session, with the victim's cookies, on the site's own origin. So it can
read document.cookie, make authenticated requests as the victim, rewrite the
page to phish, or key-log the form. The classic demonstrations are harmless on
purpose:

    <script>alert(document.domain)</script>     prove script runs, name the origin
    <img src=x onerror=alert(1)>                 fire without a <script> tag

Read "alert(1)" as "arbitrary code here". If a box can pop, it can also do the
serious things above.


THE FIX, IN ONE SENTENCE
------------------------
Encode data for the context you are dropping it into. Text going between HTML
tags gets HTML-entity encoding (< becomes &lt;), so the browser shows it instead
of parsing it. This file ships the bug live and the fix behind --safe, so you
can fire the same payload at both and watch one of them stop working.

    uv run week-11/xss-lab/app.py            # vulnerable, on http://127.0.0.1:8000
    uv run week-11/xss-lab/app.py --safe     # the three bugs fixed
    uv run week-11/xss-lab/app.py --port 9000

It binds to 127.0.0.1 only. All state is in memory; restart to reset the
guestbook. This is a teaching target in the spirit of DVWA / WebGoat — never
expose it, never copy these patterns into real code.
"""
from __future__ import annotations

import argparse
from html import escape

from flask import Flask, Response, request

app = Flask(__name__)

# --safe flips this on. When False (the default) the site is vulnerable; when
# True the three sinks encode their output and the same payloads go inert.
SAFE = False


# ---------------------------------------------------------------------------
# The one function that decides safe-vs-vulnerable.
#
# enc() is the output encoder. In vulnerable mode it is the identity function:
# untrusted text is dropped into HTML verbatim, so any markup in it is parsed as
# markup. In --safe mode it HTML-escapes, turning < > & " ' into entities, so the
# browser renders the characters as text instead of acting on them.
#
# This is deliberately a no-op by default to make the point that being safe is a
# thing you have to DO. A real app uses a template engine (Jinja2, here, via
# Flask's render_template) that escapes by default, so forgetting is the thing
# that takes effort, not remembering.
# ---------------------------------------------------------------------------
def enc(value: object) -> str:
    """Encode untrusted text for an HTML body context — unless we are vulnerable."""
    text = str(value)
    return escape(text, quote=True) if SAFE else text


# A shared page chrome so every page looks the same and links to the others.
def page(title: str, body: str) -> str:
    mode = "SAFE (output encoded)" if SAFE else "VULNERABLE (output raw)"
    banner_colour = "#1b5e20" if SAFE else "#b71c1c"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{escape(title)} — XSS lab</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 48rem; margin: 2rem auto;
            padding: 0 1rem; line-height: 1.5; color: #222; }}
    .mode {{ background: {banner_colour}; color: white; padding: .4rem .8rem;
             border-radius: .3rem; font-size: .85rem; display: inline-block; }}
    nav a {{ margin-right: 1rem; }}
    .card {{ border: 1px solid #ccc; border-radius: .5rem; padding: 1rem;
             margin: 1rem 0; }}
    input[type=text] {{ width: 100%; padding: .5rem; font-size: 1rem; }}
    button {{ padding: .5rem 1rem; font-size: 1rem; cursor: pointer; }}
    code {{ background: #f0f0f0; padding: 0 .2rem; }}
  </style>
</head>
<body>
  <p><span class="mode">{mode}</span></p>
  <nav>
    <a href="/">home</a>
    <a href="/search">reflected</a>
    <a href="/guestbook">stored</a>
    <a href="/welcome">dom-based</a>
  </nav>
  <h1>{escape(title)}</h1>
  {body}
</body>
</html>"""


# ===========================================================================
# HOME
# ===========================================================================
@app.get("/")
def home() -> str:
    body = """
    <p>Three pages, three cross-site scripting bugs. Try each one with a harmless
    proof-of-concept first, then read why it worked.</p>
    <div class="card">
      <h2>1. Reflected — <a href="/search">/search</a></h2>
      <p>Your input is echoed into one response: the search results page.</p>
    </div>
    <div class="card">
      <h2>2. Stored — <a href="/guestbook">/guestbook</a></h2>
      <p>Your input is saved and shown to everyone who visits afterwards.</p>
    </div>
    <div class="card">
      <h2>3. DOM-based — <a href="/welcome">/welcome</a></h2>
      <p>The server never sees your input; the page's own JavaScript writes it.</p>
    </div>
    <p>Restart the server with <code>--safe</code> and fire the same payloads to
    watch the fix work.</p>
    """
    return page("Cross-site scripting lab", body)


# ===========================================================================
# 1. REFLECTED XSS   —   /search?q=...
#
# The server takes q straight off the query string and writes it back into this
# one response. A link like
#     /search?q=<script>alert(document.domain)</script>
# runs script in the browser of whoever clicks it. That is the delivery model
# for reflected XSS: the payload lives in the URL, so the attack is "get the
# victim to click a link you crafted" (email, chat, another site).
# ===========================================================================
@app.get("/search")
def search() -> str:
    q = request.args.get("q", "")
    results = ""
    if q:
        # THE BUG: enc(q) is a no-op in vulnerable mode, so q lands in the HTML
        # body verbatim and any tags in it are parsed as tags.
        results = f"""
        <p>You searched for: <strong>{enc(q)}</strong></p>
        <p>No matching documents. (This demo has no real search index — the
        point is the line above.)</p>
        """
    body = f"""
    <form method="get" action="/search">
      <p><input type="text" name="q" value="{escape(q, quote=True)}"
                placeholder="search term" autofocus></p>
      <button type="submit">Search</button>
    </form>
    {results}
    <div class="card">
      <h3>Try it</h3>
      <p>Put this in the box, or in the URL as <code>?q=</code>:</p>
      <p><code>&lt;script&gt;alert(document.domain)&lt;/script&gt;</code></p>
      <p>The payload lives in the <em>link</em>, so a real attack is a crafted
      URL you get a victim to open.</p>
    </div>
    """
    return page("Reflected: /search", body)


# ===========================================================================
# 2. STORED XSS   —   /guestbook
#
# Posted messages are kept in memory and rendered into the page for every later
# visitor. One attacker POST plants a payload that then runs in every reader's
# browser with no further action from the attacker. No crafted link needed: the
# victim just visits a normal, trusted URL. That persistence is what makes
# stored XSS the most dangerous of the three.
# ===========================================================================
GUESTBOOK: list[dict[str, str]] = [
    {"name": "admin", "message": "Welcome! Leave a note below."},
]


@app.get("/guestbook")
def guestbook() -> str:
    entries = ""
    for e in GUESTBOOK:
        # THE BUG: both fields pass through the no-op encoder, so a stored
        # <script> in either one runs for every visitor.
        entries += f"""
        <div class="card">
          <strong>{enc(e['name'])}</strong> says:
          <div>{enc(e['message'])}</div>
        </div>
        """
    body = f"""
    <form method="post" action="/guestbook">
      <p><input type="text" name="name" placeholder="your name"></p>
      <p><input type="text" name="message" placeholder="your message"></p>
      <button type="submit">Sign the guestbook</button>
    </form>
    <h2>Entries</h2>
    {entries}
    <div class="card">
      <h3>Try it</h3>
      <p>Sign with message <code>&lt;script&gt;alert(document.domain)&lt;/script&gt;</code>,
      then reload — or open the page in another browser. It fires for everyone,
      with no crafted link.</p>
    </div>
    """
    return page("Stored: /guestbook", body)


@app.post("/guestbook")
def guestbook_post() -> Response:
    GUESTBOOK.append(
        {
            "name": request.form.get("name", "anonymous") or "anonymous",
            "message": request.form.get("message", ""),
        }
    )
    # Post/Redirect/Get so a reload does not re-submit.
    return app.redirect("/guestbook")


# ===========================================================================
# 3. DOM-BASED XSS   —   /welcome
#
# The server's response is a FIXED, payload-free page. The vulnerability is in
# the JavaScript it ships: that script reads location.hash (the part after #)
# and assigns it to element.innerHTML. The fragment is never sent to the server
# — browsers do not transmit #... — so there is nothing to see or fix on the
# server side. The sink is innerHTML in the client.
#
#     /welcome#<img src=x onerror=alert(document.domain)>
#
# The fix is in the client too: write the value as text (element.textContent)
# instead of as markup (element.innerHTML). --safe switches which line runs.
# ===========================================================================
@app.get("/welcome")
def welcome() -> str:
    # These two lines are the whole lesson. Only one is wired up at a time.
    vulnerable_js = "box.innerHTML = name;        // SINK: parses name as HTML"
    safe_js = "box.textContent = name;       // SAFE: name is shown as text"
    chosen = safe_js if SAFE else vulnerable_js

    body = f"""
    <p>Hello, <span id="greeting">stranger</span>!</p>
    <p>This page personalises itself from the URL fragment. Notice the server
    sends the <em>same</em> HTML every time — open "view source" and the payload
    is not in it. The browser never sends the <code>#...</code> part to the
    server at all.</p>

    <script>
      // Read the name out of the URL fragment, e.g. /welcome#Alice
      var name = decodeURIComponent(location.hash.slice(1)) || "stranger";
      var box = document.getElementById("greeting");
      {chosen}
    </script>

    <div class="card">
      <h3>Try it</h3>
      <p>Append this to the URL and press Enter:</p>
      <p><code>#&lt;img src=x onerror=alert(document.domain)&gt;</code></p>
      <p>A plain <code>&lt;script&gt;</code> tag assigned via innerHTML will
      <em>not</em> run — the HTML spec forbids it — which is exactly why DOM XSS
      payloads reach for event handlers like <code>onerror</code> instead.</p>
    </div>
    """
    return page("DOM-based: /welcome", body)


# ===========================================================================
# STARTUP
# ===========================================================================
def main() -> None:
    ap = argparse.ArgumentParser(description="Week 11 XSS teaching lab (localhost only).")
    ap.add_argument("--safe", action="store_true",
                    help="encode output / use textContent — the three bugs fixed")
    ap.add_argument("--port", type=int, default=8000, help="port (default 8000)")
    args = ap.parse_args()

    globals()["SAFE"] = args.safe

    print("=" * 64)
    print("  Week 11 — cross-site scripting lab")
    print(f"  Mode: {'SAFE (output encoded)' if SAFE else 'VULNERABLE (output raw)'}")
    print(f"  http://127.0.0.1:{args.port}")
    print("  Deliberately vulnerable. Localhost only. Never expose this.")
    print("=" * 64)

    # 127.0.0.1 only — do not bind 0.0.0.0.
    app.run(host="127.0.0.1", port=args.port, debug=False)


if __name__ == "__main__":
    main()
