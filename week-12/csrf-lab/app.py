# /// script
# requires-python = ">=3.11"
# dependencies = ["flask>=3.0"]
# ///
"""
app.py — cross-site request forgery (CSRF), two vectors, one fix
================================================================

Week 12's second lab target, the counterpart to the week-11 cors-lab. Where
CORS is about an attacker *reading* your data, CSRF is about an attacker making
your browser *perform an action* — spending your money, changing your email —
on a site you are logged into, without ever seeing the response.

Like CORS it is a two-origin story, so this is two servers in one process:

    http://127.0.0.1:8000   THE BANK   you log in and can transfer money
    http://127.0.0.1:9000   THE EVIL   a page you visit that forges transfers
                                        from your account

The whole lab turns on one fact: **the browser attaches your bank cookie to
requests to the bank no matter which site caused the request.** So a form or an
image on the attacker's page can drive a logged-in action on the bank, and the
bank — seeing a valid session cookie — cannot tell it wasn't you.

TWO VECTORS, on the bank's one money-transfer action:

    forged POST     a hidden <form> on the evil page auto-submits a transfer.
                    The cross-site POST carries your cookie; the bank executes it.

    forged GET      the bank foolishly also accepts transfers over GET, so the
                    attacker needs only an <img src="...transfer?to=...">: no
                    form, no JavaScript, fires the instant the page loads.

Note what the attacker never needs: to READ any response. CSRF is a blind,
write-only attack — which is exactly why the Same-Origin Policy and CORS (both
about reading) do nothing to stop it.


THE FIX, IN ONE SENTENCE
------------------------
Require proof that each state-changing request came from your own page — an
unguessable, per-session CSRF token submitted with the request and checked on
the server — and never change state on a GET. --safe does both: the transfer
form carries a random per-session token, the server rejects any POST without
the matching one, and GET transfers stop working entirely.

    uv run week-12/csrf-lab/app.py            # vulnerable, bank :8000 / evil :9000
    uv run week-12/csrf-lab/app.py --safe      # both vectors fixed
    uv run week-12/csrf-lab/app.py --bank-port 8100 --evil-port 9100

Both servers bind 127.0.0.1 only. All state is in memory. This is a teaching
target in the spirit of DVWA / WebGoat — never expose it, never copy the
vulnerable patterns into real code.
"""
from __future__ import annotations

import argparse
import hmac
import secrets
import threading
from html import escape

from flask import Flask, Response, redirect, request
from werkzeug.serving import make_server

# --safe flips this on. When False (the default) the transfer endpoint trusts
# the session cookie alone; when True it also requires a per-session CSRF token
# and refuses to act on GET.
SAFE = False

BANK_PORT = 8000
EVIL_PORT = 9000


def bank_origin() -> str:
    return f"http://127.0.0.1:{BANK_PORT}"


def evil_origin() -> str:
    return f"http://127.0.0.1:{EVIL_PORT}"


# ---------------------------------------------------------------------------
# Server-side session store: sid -> {balance, csrf, log}. The session cookie
# holds only the opaque sid. The CSRF token is a SEPARATE secret kept here and
# echoed into the bank's own forms — never into a cookie, so it cannot ride a
# cross-site request automatically the way the cookie does. That asymmetry is
# the entire defence.
# ---------------------------------------------------------------------------
SESSION_COOKIE = "session"
SESSIONS: dict[str, dict] = {}
_lock = threading.Lock()


def current_session() -> dict | None:
    return SESSIONS.get(request.cookies.get(SESSION_COOKIE, ""))


def page(title: str, body: str, *, evil: bool = False) -> str:
    mode = "SAFE (CSRF token + POST-only)" if SAFE else "VULNERABLE (cookie trusted alone)"
    mode_colour = "#1b5e20" if SAFE else "#b71c1c"
    site_colour = "#4a148c" if evil else "#0d47a1"
    site_label = f"EVIL · {evil_origin()}" if evil else f"BANK · {bank_origin()}"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{escape(title)} — CSRF lab</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 48rem; margin: 2rem auto;
            padding: 0 1rem; line-height: 1.5; color: #222; }}
    .tag {{ color: white; padding: .4rem .8rem; border-radius: .3rem;
            font-size: .85rem; display: inline-block; margin-right: .4rem; }}
    .card {{ border: 1px solid #ccc; border-radius: .5rem; padding: 1rem; margin: 1rem 0; }}
    input {{ padding: .4rem; font-size: 1rem; }}
    button {{ padding: .5rem 1rem; font-size: 1rem; cursor: pointer; }}
    code {{ background: #f0f0f0; padding: 0 .2rem; }}
    pre {{ background: #111; color: #0f0; padding: .8rem; border-radius: .4rem;
           overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
    .ok {{ color: #1b5e20; font-weight: bold; }}
    .bad {{ color: #b71c1c; font-weight: bold; }}
    .balance {{ font-size: 1.6rem; font-weight: bold; }}
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

    def do_transfer(sess: dict, to: str, amount_raw: str) -> str:
        try:
            amount = int(amount_raw)
        except (TypeError, ValueError):
            return '<p class="bad">Invalid amount.</p>'
        if amount <= 0:
            return '<p class="bad">Amount must be positive.</p>'
        with _lock:
            sess["balance"] -= amount
            sess["log"].append(f"-{amount} to {to}")
        return (
            f'<p class="ok">Transferred ${amount} to '
            f"{escape(to)}.</p>"
        )

    @app.get("/")
    def home() -> str:
        sess = current_session()
        if not sess:
            body = """
            <div class="card">
              <p class="bad">You are not logged in.</p>
              <form method="post" action="/login"><button>Log in as Alice</button></form>
            </div>"""
            return page("Your bank", body)

        # The transfer form. In --safe mode it carries the per-session CSRF
        # token in a hidden field; in vulnerable mode there is no token at all.
        token_field = (
            f'<input type="hidden" name="csrf" value="{escape(sess["csrf"])}">'
            if SAFE else ""
        )
        log = "".join(f"<li>{escape(x)}</li>" for x in sess["log"]) or "<li>(none yet)</li>"
        body = f"""
        <div class="card">
          <p>Signed in as <strong>Alice</strong>.</p>
          <p>Balance: <span class="balance">${sess['balance']}</span></p>
          <p>Transfers so far:</p><ul>{log}</ul>
          <form method="post" action="/transfer"><button>Log out? use nav</button></form>
        </div>
        <div class="card">
          <h3>Transfer money</h3>
          <form method="post" action="/transfer">
            {token_field}
            <p>To: <input type="text" name="to" value="a-friend"></p>
            <p>Amount: <input type="text" name="amount" value="10"></p>
            <button type="submit">Send</button>
          </form>
        </div>
        <div class="card">
          <h3>Now play the victim</h3>
          <p>Leave this session logged in and open the attacker's page:</p>
          <p><a href="{evil_origin()}">{evil_origin()}</a></p>
        </div>
        <form method="post" action="/logout"><button>Log out</button></form>"""
        return page("Your bank", body)

    @app.post("/login")
    def login() -> Response:
        sid = secrets.token_hex(16)
        with _lock:
            SESSIONS[sid] = {"balance": 1000, "csrf": secrets.token_hex(16), "log": []}
        resp = redirect("/")
        # SameSite=None so the cookie rides cross-site requests (the realistic
        # setting that makes CSRF possible; see the README's SameSite note).
        resp.set_cookie(SESSION_COOKIE, sid,
                        httponly=True, samesite="None", secure=True, path="/")
        return resp

    @app.post("/logout")
    def logout() -> Response:
        with _lock:
            SESSIONS.pop(request.cookies.get(SESSION_COOKIE, ""), None)
        resp = redirect("/")
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    @app.route("/transfer", methods=["GET", "POST"])
    def transfer() -> Response:
        sess = current_session()
        if not sess:
            return Response(page("Transfer", '<p class="bad">Log in first.</p>'), status=401)

        if SAFE:
            # FIX 1: state changes only over POST. A GET must be safe to repeat
            # and must never be triggerable by an <img> or a link.
            if request.method != "POST":
                return Response(
                    page("Transfer", '<p class="bad">Rejected: transfers must use POST.</p>'),
                    status=405,
                )
            # FIX 2: require the per-session token, compared in constant time.
            # The attacker's page cannot read it (it is not in a cookie and the
            # Same-Origin Policy stops them fetching the bank page to scrape it),
            # so it cannot forge a request that carries the right one.
            supplied = request.form.get("csrf", "")
            if not hmac.compare_digest(supplied, sess["csrf"]):
                return Response(
                    page("Transfer", '<p class="bad">Rejected: missing or invalid CSRF token.</p>'),
                    status=403,
                )
            result = do_transfer(sess, request.form.get("to", ""), request.form.get("amount", ""))
        else:
            # THE BUG: the session cookie is the ONLY thing checked. Any request
            # that carries it — from any site, by any method — is honoured.
            src = request.form if request.method == "POST" else request.args
            result = do_transfer(sess, src.get("to", ""), src.get("amount", ""))

        body = result + f'<p><a href="/">back to your account</a></p>'
        return Response(page("Transfer", body))

    return app


# ===========================================================================
# THE EVIL SITE  —  http://127.0.0.1:9000
#
# A separate origin that never sees your cookie or the CSRF token. It just
# emits requests to the bank; the browser supplies the cookie automatically.
# ===========================================================================
def make_evil() -> Flask:
    app = Flask("evil")

    @app.get("/")
    def home() -> str:
        bank = bank_origin()
        body = f"""
        <p>You are on the attacker's page, <code>{evil_origin()}</code>. There is
        nothing here but cat pictures — and some hidden requests to your bank.</p>

        <div class="card">
          <p><strong>Be logged in at <a href="{bank}" target="_blank">{bank}</a>
          first.</strong> Then just... stay on this page.</p>
        </div>

        <div class="card">
          <h3>Vector 1 — forged POST (auto-submitting hidden form)</h3>
          <p>This form submits itself on load, into a hidden frame so you never
          see it happen. It transfers <strong>$500</strong> to the attacker.</p>
          <iframe name="sink" style="display:none"></iframe>
          <form id="f" action="{bank}/transfer" method="POST" target="sink">
            <input type="hidden" name="to" value="attacker">
            <input type="hidden" name="amount" value="500">
          </form>
        </div>

        <div class="card">
          <h3>Vector 2 — forged GET (just an image tag)</h3>
          <p>No form, no script: the browser fetches this "image", which is really
          a transfer of <strong>$250</strong>. Fires the moment the page loads.</p>
          <img src="{bank}/transfer?to=attacker&amount=250"
               alt="(this 'image' is a money transfer)" width="1" height="1">
        </div>

        <div class="card">
          <p>Refresh your bank account page. In vulnerable mode the balance has
          dropped by $750 and two transfers to <code>attacker</code> appear —
          you never clicked anything. In <code>--safe</code> mode both are
          rejected and the balance is untouched.</p>
        </div>

        <script>
          // Fire the POST automatically — no victim interaction required.
          window.addEventListener("load", () => document.getElementById("f").submit());
        </script>"""
        return page("Totally Legit Cat Pictures", body, evil=True)

    return app


# ===========================================================================
# STARTUP — bank in a daemon thread, evil in the main thread.
# ===========================================================================
def _serve(app: Flask, port: int) -> None:
    make_server("127.0.0.1", port, app).serve_forever()


def main() -> None:
    ap = argparse.ArgumentParser(description="Week 12 CSRF teaching lab (localhost only).")
    ap.add_argument("--safe", action="store_true",
                    help="require a CSRF token and POST-only — both vectors fixed")
    ap.add_argument("--bank-port", type=int, default=8000, help="bank port (default 8000)")
    ap.add_argument("--evil-port", type=int, default=9000, help="attacker port (default 9000)")
    args = ap.parse_args()

    globals()["SAFE"] = args.safe
    globals()["BANK_PORT"] = args.bank_port
    globals()["EVIL_PORT"] = args.evil_port

    bank, evil = make_bank(), make_evil()

    print("=" * 64)
    print("  Week 12 — CSRF lab")
    print(f"  Mode: {'SAFE (CSRF token + POST-only)' if SAFE else 'VULNERABLE (cookie trusted alone)'}")
    print(f"  Bank (victim) : {bank_origin()}")
    print(f"  Evil (attacker): {evil_origin()}")
    print("  Log in at the bank, then open the evil site. Localhost only.")
    print("=" * 64)

    threading.Thread(target=_serve, args=(bank, BANK_PORT), daemon=True).start()
    _serve(evil, EVIL_PORT)


if __name__ == "__main__":
    main()
