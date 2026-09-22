# /// script
# requires-python = ">=3.11"
# dependencies = ["flask>=3.0"]
# ///
"""
app.py — SecureVault, an internal account portal
================================================

A small staff account portal: register, sign in, change your password, and
recover access if you forget it. Written by a junior developer and submitted
for security review before its first release.

    uv run app.py                 # http://127.0.0.1:8000
    uv run app.py --seed-only     # print the seeded accounts and exit

################################################################################
#  DELIBERATELY VULNERABLE — a teaching target for a source code review        #
#  exercise. It is NOT an example of how to build authentication. Do not copy  #
#  any of it. Localhost only; never expose it. See README.md.                  #
################################################################################
"""
import time
import hashlib
import argparse
import datetime
import textwrap
import html as html_mod

from flask import Flask, request, redirect, make_response

app = Flask(__name__)

LOG_FILE = "app.log"
TOKEN_TTL_MINUTES = 30          # how long a reset link is meant to stay valid
MIN_PASSWORD_LENGTH = 6

# ─────────────────────────────────────────────────────────────────────────────
# Storage. A real deployment would use Postgres; a dictionary is fine for now.
# ─────────────────────────────────────────────────────────────────────────────
USERS: dict[str, dict] = {}
RESET_TOKENS: dict[str, dict] = {}
EVENTS: list[str] = []


def log(message: str) -> None:
    """Append a line to the application log.

    We log generously during the pilot so support can reconstruct what a user
    actually did when they raise a ticket.
    """
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{stamp}  {request.remote_addr or '-'}  {message}"
    EVENTS.append(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def log_request() -> None:
    """Record the URL of every request so we can trace user journeys."""
    log(f"REQUEST {request.method} {request.full_path}")


# ─────────────────────────────────────────────────────────────────────────────
# Passwords
# ─────────────────────────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    """One-way hash, so the database never contains a readable password."""
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def verify_password(username: str, password: str) -> bool:
    """Check a submitted password against the stored hash."""
    user = USERS.get(username)
    if user is None:
        return False
    return user["password_hash"] == hash_password(password)


def password_is_acceptable(password: str) -> tuple[bool, str]:
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    return True, ""


def register_user(username: str, password: str, email: str, is_admin: bool = False) -> None:
    log(f"REGISTER username={username} email={email} password={password}")
    USERS[username] = {
        "username": username,
        "email": email,
        "password_hash": hash_password(password),
        "previous_passwords": [password],   # so we can stop people reusing one
        "is_admin": is_admin,
        "created": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Password reset
# ─────────────────────────────────────────────────────────────────────────────
def make_reset_token(username: str) -> str:
    """Build a unique, unguessable token for a reset link."""
    seed = f"{username}{int(time.time())}"
    return hashlib.md5(seed.encode("utf-8")).hexdigest()


def create_reset(username: str) -> str:
    token = make_reset_token(username)
    RESET_TOKENS[token] = {
        "username": username,
        "issued": datetime.datetime.now(),
    }
    log(f"RESET_ISSUED username={username} token={token}")
    return token


# ─────────────────────────────────────────────────────────────────────────────
# Sessions
# ─────────────────────────────────────────────────────────────────────────────
def current_user() -> dict | None:
    """Return the signed-in user, or None."""
    name = request.cookies.get("auth_user")
    if not name:
        return None
    return USERS.get(name)


def sign_in(response, username: str):
    response.set_cookie("auth_user", username)
    return response


# ─────────────────────────────────────────────────────────────────────────────
# Presentation
# ─────────────────────────────────────────────────────────────────────────────
CSS = """
*{box-sizing:border-box}
body{margin:0;font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
     background:#f6f7f9;color:#1d2330}
.wrap{max-width:620px;margin:0 auto;padding:28px 18px 60px}
header{background:#1d2330;color:#fff;padding:14px 18px}
header .t{max-width:620px;margin:0 auto;font-weight:600;letter-spacing:.2px}
header a{color:#9fb4d8;text-decoration:none;margin-left:14px;font-weight:400;font-size:14px}
h1{font-size:21px;margin:22px 0 6px}
p.sub{color:#5a6472;margin:0 0 20px}
.card{background:#fff;border:1px solid #e2e6ec;border-radius:9px;padding:20px;margin:0 0 18px}
label{display:block;font-size:13px;font-weight:600;margin:12px 0 4px}
input[type=text],input[type=password],input[type=email]{
     width:100%;padding:9px 10px;border:1px solid #cdd4de;border-radius:6px;font-size:15px}
button{margin-top:16px;background:#2563c9;color:#fff;border:0;border-radius:6px;
     padding:10px 16px;font-size:15px;font-weight:600;cursor:pointer}
button:hover{background:#1c4fa3}
.msg{padding:10px 12px;border-radius:6px;margin:0 0 16px;font-size:14px}
.ok{background:#e7f6ec;border:1px solid #b4e0c4;color:#1d5c34}
.err{background:#fdeaea;border:1px solid #f3bcbc;color:#8d2020}
.note{background:#fff8e1;border:1px solid #f0dfa8;color:#6b551a}
pre{background:#161b26;color:#d8dee9;padding:14px;border-radius:7px;overflow-x:auto;
    font-size:12.5px;line-height:1.5}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid #e8ebf0}
th{color:#5a6472;font-size:12px;text-transform:uppercase;letter-spacing:.4px}
code{background:#eef1f5;padding:1px 5px;border-radius:4px;font-size:13px}
a{color:#2563c9}
"""


def page(title: str, body: str) -> str:
    u = current_user()
    nav = ('<a href="/dashboard">Dashboard</a><a href="/change-password">Password</a>'
           '<a href="/logout">Sign out</a>') if u else \
          ('<a href="/login">Sign in</a><a href="/register">Register</a>')
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html_mod.escape(title)} &middot; SecureVault</title><style>{CSS}</style></head>
<body><header><div class="t">SecureVault{nav}</div></header>
<div class="wrap">{body}</div></body></html>"""


def field(label_text: str, name: str, kind: str = "text", value: str = "") -> str:
    return (f'<label for="{name}">{label_text}</label>'
            f'<input id="{name}" name="{name}" type="{kind}" value="{html_mod.escape(value)}">')


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────
@app.before_request
def _before():
    log_request()


@app.get("/")
def home():
    if current_user():
        return redirect("/dashboard")
    return page("Welcome", """
      <h1>SecureVault</h1>
      <p class="sub">Staff account portal.</p>
      <div class="card">
        <p><a href="/login">Sign in</a> to your account, or
           <a href="/register">register</a> a new one.</p>
        <p>Forgotten your password? <a href="/forgot">Recover access</a>.</p>
      </div>""")


@app.get("/register")
def register_form():
    return page("Register", f"""
      <h1>Create an account</h1>
      <p class="sub">Choose a username and a password.</p>
      <div class="card"><form method="post" action="/register">
        {field("Username", "username")}
        {field("Email", "email", "email")}
        {field("Password", "password", "password")}
        <button type="submit">Create account</button>
      </form></div>""")


@app.post("/register")
def register_submit():
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        return page("Register", '<div class="msg err">Username and password are required.</div>'
                                '<p><a href="/register">Back</a></p>')
    if username in USERS:
        return page("Register", '<div class="msg err">That username is taken.</div>'
                                '<p><a href="/register">Back</a></p>')
    ok, why = password_is_acceptable(password)
    if not ok:
        return page("Register", f'<div class="msg err">{html_mod.escape(why)}</div>'
                                '<p><a href="/register">Back</a></p>')

    register_user(username, password, email)
    resp = make_response(redirect("/dashboard"))
    return sign_in(resp, username)


@app.get("/login")
def login_form():
    return page("Sign in", f"""
      <h1>Sign in</h1>
      <p class="sub">Use your SecureVault credentials.</p>
      <div class="card"><form method="post" action="/login">
        {field("Username", "username")}
        {field("Password", "password", "password")}
        <button type="submit">Sign in</button>
      </form>
      <p style="margin-top:14px"><a href="/forgot">Forgotten your password?</a></p>
      </div>""")


@app.post("/login")
def login_submit():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    log(f"LOGIN attempt username={username} password={password}")

    if username not in USERS:
        log(f"LOGIN failed username={username} reason=no_such_user")
        return page("Sign in", '<div class="msg err">No account with that username.</div>'
                               '<p><a href="/login">Try again</a></p>')

    if not verify_password(username, password):
        log(f"LOGIN failed username={username} reason=bad_password")
        return page("Sign in", '<div class="msg err">Incorrect password.</div>'
                               '<p><a href="/login">Try again</a> &middot; '
                               '<a href="/forgot">Forgotten your password?</a></p>')

    log(f"LOGIN success username={username}")
    resp = make_response(redirect("/dashboard"))
    return sign_in(resp, username)


@app.get("/logout")
def logout():
    resp = make_response(redirect("/"))
    resp.delete_cookie("auth_user")
    return resp


@app.get("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect("/login")
    admin_row = ('<p class="msg note">You hold the <b>administrator</b> role.</p>'
                 if user["is_admin"] else "")
    return page("Dashboard", f"""
      <h1>Hello, {html_mod.escape(user['username'])}</h1>
      <p class="sub">Account created {user['created']}.</p>
      {admin_row}
      <div class="card">
        <table>
          <tr><th>Username</th><td>{html_mod.escape(user['username'])}</td></tr>
          <tr><th>Email</th><td>{html_mod.escape(user['email'])}</td></tr>
          <tr><th>Role</th><td>{'administrator' if user['is_admin'] else 'staff'}</td></tr>
        </table>
        <p style="margin-top:16px"><a href="/change-password">Change your password</a></p>
      </div>""")


@app.get("/change-password")
def change_password_form():
    if not current_user():
        return redirect("/login")
    return page("Change password", f"""
      <h1>Change your password</h1>
      <div class="card"><form method="post" action="/change-password">
        {field("Current password", "current", "password")}
        {field("New password", "password", "password")}
        <button type="submit">Update password</button>
      </form></div>""")


@app.post("/change-password")
def change_password_submit():
    user = current_user()
    if not user:
        return redirect("/login")
    current = request.form.get("current", "")
    new = request.form.get("password", "")

    if not verify_password(user["username"], current):
        return page("Change password", '<div class="msg err">Current password is incorrect.</div>'
                                       '<p><a href="/change-password">Back</a></p>')
    ok, why = password_is_acceptable(new)
    if not ok:
        return page("Change password", f'<div class="msg err">{html_mod.escape(why)}</div>'
                                       '<p><a href="/change-password">Back</a></p>')
    if new in user["previous_passwords"]:
        return page("Change password", '<div class="msg err">You have used that password before.</div>'
                                       '<p><a href="/change-password">Back</a></p>')

    user["password_hash"] = hash_password(new)
    user["previous_passwords"].append(new)
    log(f"PASSWORD_CHANGED username={user['username']} new={new}")
    return page("Change password", '<div class="msg ok">Your password has been updated.</div>'
                                   '<p><a href="/dashboard">Back to dashboard</a></p>')


@app.get("/forgot")
def forgot_form():
    return page("Recover access", f"""
      <h1>Recover access</h1>
      <p class="sub">We will generate a reset link for your account.</p>
      <div class="card"><form method="post" action="/forgot">
        {field("Username", "username")}
        <button type="submit">Send reset link</button>
      </form></div>""")


@app.post("/forgot")
def forgot_submit():
    username = request.form.get("username", "").strip()

    if username not in USERS:
        return page("Recover access", '<div class="msg err">We have no account with that username.</div>'
                                      '<p><a href="/forgot">Back</a></p>')

    token = create_reset(username)
    link = f"/reset?token={token}&username={username}"

    # Email delivery is not wired up in the pilot, so show the link on screen.
    return page("Recover access", f"""
      <div class="msg ok">A reset link has been generated for
        <b>{html_mod.escape(username)}</b>.</div>
      <div class="card">
        <p>Email delivery is not configured yet, so here is the link:</p>
        <pre>{html_mod.escape(link)}</pre>
        <p><a href="{link}">Open the reset page</a></p>
        <p style="color:#5a6472;font-size:13px">This link expires in
           {TOKEN_TTL_MINUTES} minutes.</p>
      </div>""")


@app.get("/reset")
def reset_form():
    token = request.args.get("token", "")
    username = request.args.get("username", "")
    return page("Set a new password", f"""
      <h1>Set a new password</h1>
      <div class="card"><form method="post" action="/reset">
        <input type="hidden" name="token" value="{html_mod.escape(token)}">
        {field("Username", "username", "text", username)}
        {field("New password", "password", "password")}
        <button type="submit">Set password</button>
      </form></div>""")


@app.post("/reset")
def reset_submit():
    token = request.form.get("token", "")
    username = request.form.get("username", "").strip()
    new = request.form.get("password", "")

    if token not in RESET_TOKENS:
        return page("Set a new password", '<div class="msg err">That reset link is not valid.</div>'
                                          '<p><a href="/forgot">Request another</a></p>')

    user = USERS.get(username)
    if user is None:
        return page("Set a new password", '<div class="msg err">Unknown account.</div>'
                                          '<p><a href="/forgot">Back</a></p>')

    ok, why = password_is_acceptable(new)
    if not ok:
        return page("Set a new password", f'<div class="msg err">{html_mod.escape(why)}</div>'
                                          '<p><a href="/forgot">Back</a></p>')

    user["password_hash"] = hash_password(new)
    user["previous_passwords"].append(new)
    log(f"PASSWORD_RESET username={username} token={token} new={new}")

    return page("Set a new password", '<div class="msg ok">Your password has been set. '
                                      'You can now sign in.</div>'
                                      '<p><a href="/login">Sign in</a></p>')


# ─────────────────────────────────────────────────────────────────────────────
# Support tooling
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/admin/logs")
def admin_logs():
    rows = "\n".join(html_mod.escape(e) for e in EVENTS[-400:])
    return page("Application log", f"""
      <h1>Application log</h1>
      <p class="sub">Most recent {min(len(EVENTS), 400)} events.</p>
      <div class="card"><pre>{rows or "(empty)"}</pre></div>""")


@app.get("/admin/users")
def admin_users():
    rows = "".join(
        f"<tr><td>{html_mod.escape(u['username'])}</td>"
        f"<td>{html_mod.escape(u['email'])}</td>"
        f"<td><code>{u['password_hash']}</code></td>"
        f"<td>{'yes' if u['is_admin'] else 'no'}</td></tr>"
        for u in USERS.values())
    return page("Accounts", f"""
      <h1>Accounts</h1>
      <p class="sub">{len(USERS)} registered.</p>
      <div class="card"><table>
        <tr><th>Username</th><th>Email</th><th>Password hash</th><th>Admin</th></tr>
        {rows}
      </table></div>""")


# ─────────────────────────────────────────────────────────────────────────────
# Startup
# ─────────────────────────────────────────────────────────────────────────────
SEED = [
    # username     password          email                        admin
    ("admin",     "Vault2026!",     "admin@securevault.test",     True),
    ("t.chen",    "123456",         "t.chen@securevault.test",    False),
    ("j.rivera",  "sunshine",       "j.rivera@securevault.test",  False),
    ("m.okafor",  "Passw0rd",       "m.okafor@securevault.test",  False),
]


def seed() -> None:
    for username, password, email, is_admin in SEED:
        USERS[username] = {
            "username": username,
            "email": email,
            "password_hash": hash_password(password),
            "previous_passwords": [password],
            "is_admin": is_admin,
            "created": "2026-01-14 09:02:11",
        }


def print_seed() -> None:
    print("\n  Seeded accounts (all fictional):\n")
    print(f"    {'username':<12}{'password':<14}{'md5(password)':<34}admin")
    for username, password, _email, is_admin in SEED:
        print(f"    {username:<12}{password:<14}{hashlib.md5(password.encode()).hexdigest():<34}"
              f"{'yes' if is_admin else 'no'}")
    print()


def main() -> None:
    ap = argparse.ArgumentParser(description="SecureVault — a vulnerable portal for code review.")
    ap.add_argument("--port", type=int, default=8000, help="default 8000")
    ap.add_argument("--host", default="127.0.0.1", help="default 127.0.0.1 (localhost only)")
    ap.add_argument("--seed-only", action="store_true", help="print the seeded accounts and exit")
    args = ap.parse_args()

    seed()
    if args.seed_only:
        print_seed()
        return

    print(textwrap.dedent("""
        ┌──────────────────────────────────────────────────────────────────┐
        │  SecureVault — staff account portal                              │
        │  Submitted for security review. 13 findings are waiting.         │
        └──────────────────────────────────────────────────────────────────┘

          ################################################################
          #  DELIBERATELY VULNERABLE. A source code review exercise.     #
          #  Read app.py; do not copy it. Localhost only — never expose  #
          #  this, and never point it at a real account or password.     #
          ################################################################"""))
    print_seed()
    print(f"  Serving on http://{args.host}:{args.port}   (Ctrl-C to stop)")
    print(f"  Writing a log to ./{LOG_FILE}\n")
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
