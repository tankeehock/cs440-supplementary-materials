# /// script
# requires-python = ">=3.11"
# dependencies = ["flask>=3.0"]
# ///
"""
app.py — Content-Security-Policy as the second wall against XSS
===============================================================

Week 11's third lab target, the capstone to the xss-lab next door. The xss-lab
taught the *primary* fix for cross-site scripting: encode untrusted data for the
context you drop it into. This lab is about the *second* wall — the one that
catches the day you forget. That wall is a Content-Security-Policy (CSP): an
HTTP response header that tells the browser which scripts it is allowed to run,
so a script an attacker managed to inject simply never executes.

To make the point, every page here ships the SAME deliberate bug: a reflected
XSS sink that copies ?q= straight into the HTML with no encoding (exactly the
/search bug from the xss-lab). Nothing about that bug changes between the three
pages. The only thing that changes is the CSP header, and that alone decides
whether the injected script runs:

    /none      NO CSP header at all        -> the injection runs. Baseline: CSP
                                              is opt-in, and absent it stops
                                              nothing.

    /unsafe    a CSP that LOOKS protective  -> the injection STILL runs. The
               but contains 'unsafe-inline'    single most common real-world CSP
                                               mistake: a policy that re-opens
                                               the exact hole CSP exists to close,
                                               giving a false sense of security.

    /strict    a nonce-based CSP, no        -> the injection is BLOCKED by the
               'unsafe-inline'                 browser. The page's own script
                                               carries the nonce and runs; the
                                               injected <script> has no nonce and
                                               an injected onerror= handler is an
                                               inline handler, so both are refused.


WHAT A CSP ACTUALLY IS (AND IS NOT)
-----------------------------------
A CSP is an allow-list the server sends and the BROWSER enforces. For scripts,
the key directive is script-src: it lists what may run. If a <script> or an
inline event handler is not covered by the policy, the browser refuses to
execute it and reports a violation to the console.

  * CSP is DEFENCE IN DEPTH, not a primary fix. It does not stop the injection
    from landing in the HTML — output encoding does that. CSP stops the injected
    markup from *doing* anything once it has landed.
  * A CSP is only as strong as its weakest directive. 'unsafe-inline' in
    script-src defeats the entire purpose: it tells the browser "run any inline
    script", which is precisely what an injected inline script is.
  * The modern strong recipe is a per-response NONCE: a fresh random token put
    on every legitimate <script> tag and named in the policy
    (script-src 'nonce-RANDOM'). The attacker cannot guess the token, so injected
    script tags are refused while the site's own tags run. Crucially, when a
    policy carries a nonce the browser IGNORES any 'unsafe-inline' alongside it —
    so a nonce is backward-compatible with old browsers but strict in new ones.


THE FIX, IN ONE SENTENCE
------------------------
Send a strict script-src with a per-response nonce (and object-src 'none',
base-uri 'none'), never 'unsafe-inline'. --safe applies that one strict policy to
every page, so the same payload that ran on /none and /unsafe is blocked
everywhere.

    uv run week-11/csp-lab/app.py            # vulnerable, on http://127.0.0.1:8000
    uv run week-11/csp-lab/app.py --safe     # strict CSP on every page
    uv run week-11/csp-lab/app.py --port 9000

It binds to 127.0.0.1 only. All state is per-request. This is a teaching target
in the spirit of DVWA / WebGoat — never expose it, never copy the vulnerable
patterns into real code. Open the browser's dev-tools console while you test:
the whole lesson of the strict page is the violation message it prints.
"""
from __future__ import annotations

import argparse
import secrets

from flask import Flask, Response, request

app = Flask(__name__)

# --safe flips this on. When False (the default) each page sends its own CSP
# (or none) to demonstrate a point; when True every page sends the one strict
# nonce policy, so the injection is blocked everywhere.
SAFE = False


# ---------------------------------------------------------------------------
# THE DELIBERATE BUG, shared by all three pages.
#
# This is the /search reflected-XSS sink from the xss-lab, unchanged and never
# fixed in this file: q is copied into the HTML body verbatim. This lab is NOT
# about fixing this — it is about what a CSP does when you *haven't*. In real
# code you would encode here (and a template engine would do it for you); here
# we leave it open so there is a live injection for the CSP to catch or miss.
# ---------------------------------------------------------------------------
def reflect(q: str) -> str:
    """Drop the search term into the HTML body with NO encoding. The bug."""
    if not q:
        return ""
    return f"""
    <p>You searched for: <strong>{q}</strong></p>
    <p>No matching documents. (The point is the un-encoded line above — and
    whether your CSP lets it do anything.)</p>
    """


# ---------------------------------------------------------------------------
# THE ONE FUNCTION THAT DECIDES THE POLICY.
#
# Given which page was hit and this response's nonce, return the CSP header
# string (or None for "send no header at all"). In --safe mode every page gets
# the strict policy; otherwise each page demonstrates its own.
# ---------------------------------------------------------------------------
def strict_policy(nonce: str) -> str:
    """The recommended recipe: only nonce'd scripts run; no inline, no plugins,
    no <base> hijack. This is the policy that makes injected script inert."""
    return (
        f"script-src 'nonce-{nonce}'; "
        "object-src 'none'; "
        "base-uri 'none'"
    )


def csp_for(policy: str, nonce: str) -> str | None:
    if SAFE:
        return strict_policy(nonce)

    if policy == "none":
        # No CSP header at all. The browser runs whatever is in the page.
        return None

    if policy == "unsafe":
        # THE BUG: this looks like a real policy — it even scopes scripts to
        # 'self' and a CDN — but 'unsafe-inline' tells the browser to run ANY
        # inline script, which is exactly what the injected <script> is. The
        # nonce the page puts on its own tags is ignored, because without a
        # nonce/hash IN THE POLICY the browser honours 'unsafe-inline'. Net
        # effect: a policy that stops nothing it was deployed to stop.
        return "script-src 'self' 'unsafe-inline' https://cdn.example.com"

    if policy == "strict":
        # The fix, shown live even in vulnerable mode so you can see what good
        # looks like next to what bad looks like.
        return strict_policy(nonce)

    return None


def apply_csp(resp: Response, policy: str, nonce: str) -> Response:
    header = csp_for(policy, nonce)
    if header is not None:
        resp.headers["Content-Security-Policy"] = header
    return resp


# A shared page chrome so every page looks the same and links to the others.
def page(title: str, body: str) -> str:
    mode = "SAFE (strict CSP everywhere)" if SAFE else "VULNERABLE (policy varies)"
    banner_colour = "#1b5e20" if SAFE else "#b71c1c"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{title} — CSP lab</title>
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
    pre {{ background: #111; color: #0f0; padding: .8rem; border-radius: .4rem;
           overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
    .selftest {{ color: #1b5e20; font-weight: bold; }}
  </style>
</head>
<body>
  <p><span class="mode">{mode}</span></p>
  <nav>
    <a href="/">home</a>
    <a href="/none">no CSP</a>
    <a href="/unsafe">unsafe-inline</a>
    <a href="/strict">strict nonce</a>
  </nav>
  <h1>{title}</h1>
  {body}
</body>
</html>"""


# ===========================================================================
# HOME
# ===========================================================================
@app.get("/")
def home() -> str:
    body = """
    <p>Every page below ships the <em>same</em> reflected-XSS bug: your
    <code>?q=</code> is copied into the HTML with no encoding. Only the
    Content-Security-Policy header changes. Fire the same payload at each and
    watch the header — not the bug — decide whether it runs.</p>
    <p><strong>Open your browser's dev-tools console before you start.</strong>
    The strict page's whole lesson is the violation it logs.</p>
    <div class="card">
      <h2>1. No CSP — <a href="/none">/none</a></h2>
      <p>No header at all. The injected script runs. CSP is opt-in.</p>
    </div>
    <div class="card">
      <h2>2. unsafe-inline — <a href="/unsafe">/unsafe</a></h2>
      <p>A policy that looks careful but allows inline script. Same injection,
      still runs — the classic false sense of security.</p>
    </div>
    <div class="card">
      <h2>3. Strict nonce — <a href="/strict">/strict</a></h2>
      <p>A per-response nonce, no inline. The injected script is blocked; the
      page's own nonce'd script still runs.</p>
    </div>
    <p>Restart with <code>--safe</code> to apply the strict policy to all three
    and watch the injection die everywhere.</p>
    """
    return page("Content-Security-Policy lab", body)


# ===========================================================================
# THE THREE POLICY PAGES — same bug, different header.
#
# Each page generates a fresh per-response nonce, puts it on its own legitimate
# <script> (the "selftest" that proves good script still runs), reflects q
# un-encoded, and attaches its CSP via apply_csp().
# ===========================================================================
def policy_page(policy: str, title: str, lede: str) -> Response:
    nonce = secrets.token_urlsafe(16)
    q = request.args.get("q", "")

    body = f"""
    <p>{lede}</p>
    <form method="get">
      <p><input type="text" name="q" value="{q}" placeholder="search term" autofocus></p>
      <button type="submit">Search</button>
    </form>
    {reflect(q)}

    <div class="card">
      <h3>The page's own script</h3>
      <p id="selftest" class="selftest">(this script did not run)</p>
      <p>This legitimate <code>&lt;script&gt;</code> carries the page nonce.
      Under the strict policy it still runs — only script <em>without</em> the
      nonce is refused.</p>
    </div>
    <script nonce="{nonce}">
      document.getElementById("selftest").textContent =
        "✓ The page's own nonce'd script ran.";
    </script>

    <div class="card">
      <h3>The CSP this page sent</h3>
      <pre>{escape_text(csp_for(policy, nonce) or '(no Content-Security-Policy header sent)')}</pre>
      <p>See it on the wire with curl (headers only, no browser):</p>
      <pre>curl -i "http://127.0.0.1:{request.host.split(':')[-1]}/{policy}?q=x"</pre>
    </div>

    <div class="card">
      <h3>Try it</h3>
      <p>Put either payload in the box, or in the URL as <code>?q=</code>:</p>
      <pre>&lt;script&gt;alert(document.domain)&lt;/script&gt;
&lt;img src=x onerror=alert(document.domain)&gt;</pre>
      <p>Watch whether a box pops, and watch the dev-tools console for a CSP
      violation.</p>
    </div>
    """
    resp = Response(page(title, body), mimetype="text/html")
    return apply_csp(resp, policy, nonce)


def escape_text(value: str) -> str:
    """Minimal HTML-escape, used ONLY for the trusted CSP-header display box so
    the policy text shows as text. The reflected q is left un-encoded on purpose
    — that is the bug the CSP is meant to catch."""
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


@app.get("/none")
def none_page() -> Response:
    return policy_page(
        "none",
        "No CSP: /none",
        "No Content-Security-Policy header is sent, so nothing stops the "
        "injected script. This is the baseline — and the default for any site "
        "that has not deployed a CSP.",
    )


@app.get("/unsafe")
def unsafe_page() -> Response:
    return policy_page(
        "unsafe",
        "unsafe-inline: /unsafe",
        "This page sends a real-looking CSP that scopes scripts to 'self' and a "
        "CDN — but also includes 'unsafe-inline'. That one token tells the "
        "browser to run any inline script, so the injection runs exactly as if "
        "there were no policy at all.",
    )


@app.get("/strict")
def strict_page() -> Response:
    return policy_page(
        "strict",
        "Strict nonce: /strict",
        "This page sends a strict CSP: scripts run only if they carry this "
        "response's nonce. The injected <script> has no nonce, and an injected "
        "onerror= is an inline handler — the browser refuses both. The bug is "
        "still here; the CSP just makes it inert.",
    )


# ===========================================================================
# STARTUP
# ===========================================================================
def main() -> None:
    ap = argparse.ArgumentParser(description="Week 11 CSP teaching lab (localhost only).")
    ap.add_argument("--safe", action="store_true",
                    help="send the strict nonce CSP on every page — the injection blocked everywhere")
    ap.add_argument("--port", type=int, default=8000, help="port (default 8000)")
    args = ap.parse_args()

    globals()["SAFE"] = args.safe

    print("=" * 64)
    print("  Week 11 — Content-Security-Policy lab")
    print(f"  Mode: {'SAFE (strict CSP everywhere)' if SAFE else 'VULNERABLE (policy varies)'}")
    print(f"  http://127.0.0.1:{args.port}")
    print("  Open the dev-tools console. Localhost only. Never expose this.")
    print("=" * 64)

    # 127.0.0.1 only — do not bind 0.0.0.0.
    app.run(host="127.0.0.1", port=args.port, debug=False)


if __name__ == "__main__":
    main()
