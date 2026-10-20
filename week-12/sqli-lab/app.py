# /// script
# requires-python = ">=3.11"
# dependencies = ["flask>=3.0"]
# ///
"""
app.py — SQL injection, three techniques, side by side
======================================================

Week 12's lab target, a companion to the week-11 xss-lab and cors-lab. One tiny
Flask site backed by an in-memory SQLite database, three pages, the three
classic shapes of SQL injection:

    /login     AUTH BYPASS      inject a tautology so the WHERE clause is always
                                true, and log in as someone without the password
    /search    UNION-BASED      bolt a UNION SELECT onto a product search to read
                                rows from a DIFFERENT table (the users table)
    /track     BLIND BOOLEAN    an endpoint that only says "found" or "not found"
                                — leak the admin password one character at a time
                                by asking true/false questions

All three are the same mistake in different clothes: **untrusted input is pasted
into a SQL statement as code instead of being passed as data.** The database
cannot tell the query the developer wrote from the query fragment the attacker
supplied, so it parses and runs both.

                     where the input lands              what the attacker gets
    auth bypass      the WHERE of a login query         a session they shouldn't have
    union-based      the WHERE of a search query        rows from other tables, in-band
    blind boolean    a yes/no lookup                    any value, inferred bit by bit


THE FIX, IN ONE SENTENCE
------------------------
Never build SQL by string formatting. Use **parameterised queries** (a.k.a.
prepared statements): write the SQL with `?` placeholders and hand the values
to the driver separately, so they can only ever be *data*, never syntax. This
file ships the bug live and the fix behind --safe, so you can fire the same
payload at both and watch one of them stop working.

    uv run week-12/sqli-lab/app.py            # vulnerable, http://127.0.0.1:8000
    uv run week-12/sqli-lab/app.py --safe     # the three bugs fixed
    uv run week-12/sqli-lab/app.py --port 9000

It binds to 127.0.0.1 only. The database is in memory and reseeded every start.
This is a teaching target in the spirit of DVWA / WebGoat — never expose it,
never copy the vulnerable patterns into real code.

A note on realism: the users table stores PLAINTEXT passwords to keep the lesson
on injection. Real systems store salted password *hashes* — that is the week-6
password lab. Here, plaintext just makes the prize easy to see once you've
pulled it out.
"""
from __future__ import annotations

import argparse
import sqlite3
import threading
from html import escape

from flask import Flask, Response, request

app = Flask(__name__)

# --safe flips this on. When False (the default) queries are built by string
# formatting and are injectable; when True the same queries use ? placeholders
# and the same payloads become inert.
SAFE = False

# One in-memory database shared across requests. check_same_thread=False lets
# the dev server's worker threads use it; a lock keeps our use serial.
_db = sqlite3.connect(":memory:", check_same_thread=False)
_lock = threading.Lock()


def seed() -> None:
    cur = _db.cursor()
    cur.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,     -- plaintext ON PURPOSE; see the module docstring
            role TEXT
        );
        INSERT INTO users (username, password, role) VALUES
            ('alice', 'alicepassword',   'user'),
            ('bob',   'hunter2',          'user'),
            ('admin', 'S3cr3t_Admin_Pw!', 'admin');

        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            description TEXT
        );
        INSERT INTO products (name, description) VALUES
            ('Widget', 'A dependable widget'),
            ('Gadget', 'A fancy gadget'),
            ('Gizmo',  'A small gizmo');

        CREATE TABLE orders (
            id INTEGER PRIMARY KEY,
            item TEXT
        );
        INSERT INTO orders (id, item) VALUES
            (1001, 'Widget'),
            (1002, 'Gadget'),
            (1003, 'Gizmo');
        """
    )
    _db.commit()


# A shared page chrome so every page looks the same and links to the others.
def page(title: str, body: str) -> str:
    mode = "SAFE (parameterised queries)" if SAFE else "VULNERABLE (string-built SQL)"
    banner_colour = "#1b5e20" if SAFE else "#b71c1c"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{escape(title)} — SQL injection lab</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 48rem; margin: 2rem auto;
            padding: 0 1rem; line-height: 1.5; color: #222; }}
    .mode {{ background: {banner_colour}; color: white; padding: .4rem .8rem;
             border-radius: .3rem; font-size: .85rem; display: inline-block; }}
    nav a {{ margin-right: 1rem; }}
    .card {{ border: 1px solid #ccc; border-radius: .5rem; padding: 1rem; margin: 1rem 0; }}
    input[type=text], input[type=password] {{ width: 100%; padding: .5rem; font-size: 1rem; }}
    button {{ padding: .5rem 1rem; font-size: 1rem; cursor: pointer; }}
    code {{ background: #f0f0f0; padding: 0 .2rem; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ccc; padding: .3rem .5rem; text-align: left; }}
    pre {{ background: #111; color: #0f0; padding: .8rem; border-radius: .4rem;
           overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
    .ok {{ color: #1b5e20; font-weight: bold; }}
    .bad {{ color: #b71c1c; font-weight: bold; }}
  </style>
</head>
<body>
  <p><span class="mode">{mode}</span></p>
  <nav>
    <a href="/">home</a>
    <a href="/login">auth bypass</a>
    <a href="/search">union</a>
    <a href="/track">blind</a>
  </nav>
  <h1>{escape(title)}</h1>
  {body}
</body>
</html>"""


def show_sql(sql: str, params: tuple | None = None) -> str:
    """Render the statement that was actually run, so the injection is visible."""
    out = f"-- the statement sent to SQLite:\n{sql}"
    if SAFE:
        out += f"\n-- with parameters (bound as DATA, never parsed as SQL):\n{params!r}"
    return f"<p>What the server ran:</p><pre>{escape(out)}</pre>"


# ===========================================================================
# HOME
# ===========================================================================
@app.get("/")
def home() -> str:
    body = """
    <p>Three pages, three SQL-injection techniques. Try each one, then read why
    it worked.</p>
    <div class="card">
      <h2>1. Auth bypass — <a href="/login">/login</a></h2>
      <p>Log in as the admin without knowing the password.</p>
    </div>
    <div class="card">
      <h2>2. UNION-based — <a href="/search">/search</a></h2>
      <p>Turn a product search into a dump of the users table.</p>
    </div>
    <div class="card">
      <h2>3. Blind boolean — <a href="/track">/track</a></h2>
      <p>Only "found / not found" comes back — leak the admin password anyway.</p>
    </div>
    <p>Restart the server with <code>--safe</code> and fire the same payloads to
    watch parameterised queries shut every one of them down.</p>
    """
    return page("SQL injection lab", body)


# ===========================================================================
# 1. AUTH BYPASS   —   /login
#
# The query asks "is there a row where username AND password match?" and logs
# you in if a row comes back. Built by string formatting, a username of
#     admin' --
# turns the statement into
#     SELECT ... WHERE username = 'admin' --' AND password = '...'
# where -- comments out the password check entirely. Or ' OR '1'='1' -- makes
# the WHERE always true and returns the first user.
# ===========================================================================
@app.get("/login")
def login_form() -> str:
    return page("Auth bypass: /login", _login_body("", None))


@app.post("/login")
def login_submit() -> str:
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if SAFE:
        # THE FIX: placeholders. username/password are sent to SQLite as values,
        # so quotes and -- in them are just characters in a string, not syntax.
        sql = "SELECT username, role FROM users WHERE username = ? AND password = ?"
        params = (username, password)
        rows = run(sql, params)
        ran = show_sql(sql, params)
    else:
        # THE BUG: the input is pasted straight into the statement.
        sql = (
            "SELECT username, role FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        rows = run(sql)
        ran = show_sql(sql)

    if rows:
        name, role = rows[0]
        result = (
            f'<p class="ok">Logged in as <strong>{escape(name)}</strong> '
            f"(role: {escape(role)}).</p>"
        )
    else:
        result = '<p class="bad">Login failed.</p>'
    return page("Auth bypass: /login", _login_body(username, result + ran))


def _login_body(username: str, result: str | None) -> str:
    return f"""
    <form method="post" action="/login">
      <p><input type="text" name="username" placeholder="username"
                value="{escape(username)}" autofocus></p>
      <p><input type="password" name="password" placeholder="password"></p>
      <button type="submit">Log in</button>
    </form>
    {result or ""}
    <div class="card">
      <h3>Try it</h3>
      <p>Put this in the <em>username</em> box and leave the password blank:</p>
      <p><code>admin' --</code></p>
      <p>The <code>--</code> comments out the password check, so SQLite only has
      to find a user named <code>admin</code>. Or try <code>' OR '1'='1' --</code>
      to make the condition always true and log in as the first user in the table.</p>
    </div>
    """


# ===========================================================================
# 2. UNION-BASED   —   /search?q=...
#
# The search runs  SELECT name, description FROM products WHERE name LIKE '%q%'.
# Because the result is printed back, an attacker appends a UNION that selects
# the SAME NUMBER of columns from another table:
#     ' UNION SELECT username, password FROM users --
# and the users' credentials come back rendered as if they were products. The
# two keys to UNION injection: match the column count (here, 2), and find a
# place the output is shown.
# ===========================================================================
@app.get("/search")
def search() -> str:
    q = request.args.get("q", "")
    result = ""
    if q:
        if SAFE:
            # THE FIX: the whole search term — % wildcards and all — is one bound
            # value. A UNION inside it is just text to match against name.
            sql = "SELECT name, description FROM products WHERE name LIKE ?"
            params = (f"%{q}%",)
            ran = show_sql(sql, params)
            rows, err = run_or_error(sql, params)
        else:
            # THE BUG: q is pasted into the LIKE pattern, so it can close the
            # string and add clauses of its own.
            sql = f"SELECT name, description FROM products WHERE name LIKE '%{q}%'"
            ran = show_sql(sql)
            rows, err = run_or_error(sql)

        if err:
            # Showing raw DB errors is itself a gift to attackers (error-based
            # SQLi) — here it helps you tune a UNION's column count.
            result = f'<p class="bad">SQL error:</p><pre>{escape(err)}</pre>' + ran
        else:
            table = "".join(
                f"<tr><td>{escape(str(a))}</td><td>{escape(str(b))}</td></tr>"
                for a, b in rows
            )
            result = (
                f"<p>{len(rows)} result(s):</p>"
                f"<table><tr><th>name</th><th>description</th></tr>{table}</table>" + ran
            )

    body = f"""
    <form method="get" action="/search">
      <p><input type="text" name="q" value="{escape(q)}"
                placeholder="search products" autofocus></p>
      <button type="submit">Search</button>
    </form>
    {result}
    <div class="card">
      <h3>Try it</h3>
      <p>A normal search like <code>Widget</code> works. Now read another table:</p>
      <p><code>' UNION SELECT username, password FROM users --</code></p>
      <p>It lines up 2 columns with the 2 the search selects, so the users'
      credentials come back in the results table. (Wrong column count? The DB
      error tells you the right number — that is error-based injection.)</p>
    </div>
    """
    return page("UNION: /search", body)


# ===========================================================================
# 3. BLIND BOOLEAN   —   /track?order=...
#
# This endpoint shows only "Order found" or "No such order" — no data comes
# back directly. But the lookup is injectable, and the true/false answer is a
# one-bit oracle. Append a condition about the admin password and the
# found/not-found flips with it:
#     1001 AND (SELECT substr(password,1,1) FROM users WHERE username='admin')='S'
# Ask "is character 1 an 'S'?", "...a 'T'?", ... and you read the password out
# one character at a time without it ever being printed. README has a script
# that automates the guessing.
# ===========================================================================
@app.get("/track")
def track() -> str:
    order = request.args.get("order", "")
    result = ""
    if order:
        if SAFE:
            # THE FIX: the id is bound as data. A string like "1001 AND ..." is
            # compared against an integer column and simply matches nothing — no
            # part of it is ever parsed as SQL.
            sql = "SELECT item FROM orders WHERE id = ?"
            params = (order,)
            ran = show_sql(sql, params)
            rows, err = run_or_error(sql, params)
        else:
            # THE BUG: numeric context, so no quotes even — the value is pasted
            # straight in and a boolean condition rides along.
            sql = f"SELECT item FROM orders WHERE id = {order}"
            ran = show_sql(sql)
            rows, err = run_or_error(sql)

        if err:
            result = f'<p class="bad">SQL error:</p><pre>{escape(err)}</pre>' + ran
        elif rows:
            result = '<p class="ok">Order found.</p>' + ran
        else:
            result = '<p class="bad">No such order.</p>' + ran

    body = f"""
    <form method="get" action="/track">
      <p><input type="text" name="order" value="{escape(order)}"
                placeholder="order number, e.g. 1001" autofocus></p>
      <button type="submit">Track</button>
    </form>
    {result}
    <div class="card">
      <h3>Try it</h3>
      <p><code>1001</code> is found; <code>9999</code> is not. Now ask a question
      about data you cannot see:</p>
      <p><code>1001 AND (SELECT substr(password,1,1) FROM users WHERE username='admin')='S'</code></p>
      <p>"Found" means the first character of the admin password IS <code>S</code>;
      "not found" means it is not. Walk the alphabet and the position, and you
      read the whole password — see the automation in the README.</p>
    </div>
    """
    return page("Blind boolean: /track", body)


# ---------------------------------------------------------------------------
# Tiny query helpers.
# ---------------------------------------------------------------------------
def run(sql: str, params: tuple | None = None) -> list:
    with _lock:
        cur = _db.execute(sql, params or ())
        return cur.fetchall()


def run_or_error(sql: str, params: tuple | None = None) -> tuple[list, str | None]:
    try:
        return run(sql, params), None
    except sqlite3.Error as exc:
        return [], f"{type(exc).__name__}: {exc}"


# ===========================================================================
# STARTUP
# ===========================================================================
def main() -> None:
    ap = argparse.ArgumentParser(description="Week 12 SQL injection teaching lab (localhost only).")
    ap.add_argument("--safe", action="store_true",
                    help="use parameterised queries — the three bugs fixed")
    ap.add_argument("--port", type=int, default=8000, help="port (default 8000)")
    args = ap.parse_args()

    globals()["SAFE"] = args.safe
    seed()

    print("=" * 64)
    print("  Week 12 — SQL injection lab")
    print(f"  Mode: {'SAFE (parameterised queries)' if SAFE else 'VULNERABLE (string-built SQL)'}")
    print(f"  http://127.0.0.1:{args.port}")
    print("  Deliberately vulnerable. Localhost only. Never expose this.")
    print("=" * 64)

    app.run(host="127.0.0.1", port=args.port, debug=False)


if __name__ == "__main__":
    main()
