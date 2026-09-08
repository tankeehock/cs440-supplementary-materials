# /// script
# requires-python = ">=3.11"
# dependencies = ["flask>=3.0"]
# ///
"""
app.py — a transparent RBAC web server
======================================

Week 7's companion to the ACL lab. The ACL model asks "which principals are
listed on this *object*?". RBAC turns the question around and asks "which
*role* is this subject acting in, and what does that role permit?".

    subject  ──assigned──▶  role  ──grants──▶  permission  ──guards──▶  action

Nobody is ever handed a permission directly. They are put in a role, and the
role carries the permissions. That one level of indirection is the whole idea:
when someone changes jobs you edit a role assignment, not every object they
ever touched.


THREE WORDS THAT ARE NOT SYNONYMS
---------------------------------
Most authorisation bugs are really one of these three being mistaken for
another, so the code keeps them in separate functions on purpose:

  authentication   WHO are you?          -> current_user()   (section 4)
  authorisation    MAY you do this?      -> check()          (section 4)
  policy           WHO MAY do what?      -> the tables in    (section 1)

"Logged in" is authentication. It says nothing at all about what you may do.
The account `mallory` exists in this demo to make that concrete: her password
works perfectly and she is allowed to do nothing whatsoever.


HOW ONE REQUEST FLOWS
---------------------
Follow a single POST /api/reports from the browser to the answer. Every
protected route in this file takes exactly this path:

    HTTP request
         │
         ▼
    Flask matches the URL to a view function        (section 5)
         │
         ▼
    @requires("report:write") wraps that view       (section 4)
         │
         ├─▶ current_user()   who is asking?  session cookie or HTTP Basic
         │                    └─ nobody?  ──▶ user = None
         ▼
    check(user, "report:write")                     (section 4)
         │        │
         │        ├─ permissions_of(user)  ─▶ expand_role() per role
         │        │                            (walks the inheritance graph)
         │        └─ is "report:write" in that set?
         │
         ├── yes ─▶ run the view ─▶ 200/201 and the report is created
         └── no  ─▶ 401 if we do not know who you are
                    403 if we do, and the answer is still no

Nothing is hidden along the way: every call to check() prints a trace to the
console naming the subject, the roles it holds, the permissions those roles
expand to, what the route demanded, and the verdict. The same records are
readable at /audit — which is itself behind a permission, so you need the
right role to read the log of who was refused.


READING ORDER
-------------
The file is laid out in the order the ideas depend on each other. Read top to
bottom, or jump to the section you want:

    1. THE POLICY            permissions, roles, role inheritance
    2. SUBJECTS              users and password hashing
    3. OBJECTS               the reports being protected
    4. THE REFERENCE MONITOR check(), current_user(), @requires  <- the core
    5. THE WEB APP           routes, HTML pages, JSON API
    6. BROKEN ON PURPOSE     one endpoint with the check left out
    7. STARTUP               the command line

If you only read one section, read 4. Sections 1-3 are data; section 5 is
plumbing; section 4 is where every access decision is actually made.


A LITTLE FLASK, IF YOU HAVE NOT MET IT
--------------------------------------
Only five pieces of the framework appear here:

  @app.get("/reports")    register the function below as the handler ("view")
                          for GET /reports; @app.post for POST, and
                          "/reports/<int:rid>" captures a number from the URL
                          and passes it to the view as rid
  request                 the incoming request: .form, .args, .method, .path,
                          .authorization
  session                 a dict stored in a cookie that Flask signs with
                          app.secret_key, so the client can read it but cannot
                          forge it. We keep only the username there
  redirect(...)           reply "go to this other URL instead"
  jsonify(...)            reply with JSON; return (body, 404) to set a status

A view returns a string (HTML) or a jsonify(...) result. That is all you need
to follow this file.


RUNNING IT
----------
    uv run week-7/rbac-demo/app.py               # serve on http://127.0.0.1:8000
    uv run week-7/rbac-demo/app.py --port 9000
    uv run week-7/rbac-demo/app.py --policy      # print the policy matrix and exit
    uv run week-7/rbac-demo/app.py --quiet       # do not print decision traces

Everything lives in memory. Restarting the server resets the data, the roles
and the session keys. It listens on 127.0.0.1 only.

This is a teaching demo, not a template to copy into production: a real system
keeps users and role assignments in a database, serves HTML from templates that
escape their inputs, and runs behind a proper WSGI server over HTTPS.
"""
from __future__ import annotations

import sys
import hmac                       # compare_digest: constant-time comparison
import secrets                    # cryptographically secure random bytes
import hashlib                    # scrypt password hashing
import argparse
import textwrap
from html import escape       # out(): turn < > & " into entities. See out()
from functools import wraps       # keeps the wrapped view's name (see @requires)
from datetime import datetime, timezone
from dataclasses import dataclass, field

from flask import Flask, request, session, redirect, url_for, jsonify

# ═════════════════════════════════════════════════════════════════════════════
# 1. THE POLICY
#
# In RBAC the policy is *data*, not code. The three tables below are the entire
# security model of this application — you can read the whole thing in one
# screen and say exactly who may do what. That is the argument for RBAC over
# per-object ACLs: a thousand files times a hundred people is a policy nobody
# can hold in their head, and what nobody can read, nobody can audit.
#
# The tables are also the only thing you should need to edit to change the
# rules. If you ever find yourself adding an `if` to a route handler to make a
# permission decision, the policy has leaked into the code and this property is
# gone.
# ═════════════════════════════════════════════════════════════════════════════

# ── Permissions: the verbs the application knows how to guard ────────────────
#
# A permission is one thing a subject might be allowed to DO. Named
# "<resource>:<action>" so it always reads as an action, never as a job title:
# "report:delete", not "is_admin". The difference matters — the moment a
# permission is named after a person or a rank, every route that checks it has
# quietly hard-coded today's org chart.
#
# The values are human descriptions, used by /policy and the --policy flag.
# The KEYS are what the code actually enforces.
PERMISSIONS: dict[str, str] = {
    "report:read":   "List reports and read their contents",
    "report:write":  "Create a new report",
    "report:delete": "Delete any report",
    "audit:read":    "Read the authorisation decision log",
    "user:manage":   "Grant and revoke roles",
}

# ── Roles: named bundles of permissions, with inheritance ────────────────────
#
# Each role says two things:
#   "grants"   — permissions this role adds by itself
#   "inherits" — other roles whose permissions it also gets, automatically
#
# That second field is *hierarchical RBAC*. `admin` inherits editor and
# auditor, so it never restates report:read or report:write; adding a
# permission to `viewer` silently gives it to every role above. Senior roles
# inherit from junior ones and never the other way round — draw the arrows and
# they must all point the same way, or you have a cycle.
#
# Worked example, resolved by expand_role() below:
#
#   admin  grants   {report:delete, user:manage}
#     ├── editor    grants {report:write}
#     │     └── viewer  grants {report:read}
#     └── auditor   grants {audit:read}
#           └── viewer  (already visited — contributes nothing new)
#     ⇒ {report:delete, user:manage, report:write, report:read, audit:read}
ROLES: dict[str, dict] = {
    "viewer":  {"inherits": [],                   "grants": ["report:read"]},
    "editor":  {"inherits": ["viewer"],           "grants": ["report:write"]},
    "auditor": {"inherits": ["viewer"],           "grants": ["audit:read"]},
    "admin":   {"inherits": ["editor", "auditor"],"grants": ["report:delete", "user:manage"]},
}

# ── Seed accounts: who holds which role ──────────────────────────────────────
#
# This is the *assignment* half of RBAC: which subject acts in which role. Note
# what these entries do NOT contain — a list of permissions. The role assignment
# is the only thing that differs between these five users, and there is no
# per-user permission anywhere in this program by design. The moment a system
# needs "alice, plus this one extra thing", its roles have stopped describing
# the organisation.
#
# Passwords appear here in plaintext because this is a teaching demo; they are
# hashed at startup (section 2) and the plaintext is never stored anywhere the
# server can reach at runtime. Real systems obviously do not seed like this.
SEED_USERS: dict[str, tuple[str, list[str]]] = {
    # username    password        roles
    "carol":     ("carol123",    ["viewer"]),
    "bob":       ("bob123",      ["editor"]),
    "dave":      ("dave123",     ["auditor"]),
    "alice":     ("alice123",    ["admin"]),
    "mallory":   ("mallory123",  []),          # authenticated, but authorised for nothing
}


def expand_role(role: str, _seen: set[str] | None = None) -> set[str]:
    """Every permission `role` confers, directly or through inheritance.

    This is the only place role inheritance is resolved, and it is a plain
    depth-first walk of the graph:

        start at `role`, take its own "grants",
        then recurse into each role it "inherits" and union those in.

    Args:
        role:  the role name to expand, e.g. "admin".
        _seen: internal. The set of roles already visited on this walk;
               callers leave it out. It exists for two reasons — it stops a
               cycle in ROLES (a inherits b inherits a) from recursing until
               Python gives up, and it saves re-walking a role reached by two
               different paths, as `viewer` is under `admin`.

    Returns:
        A set of permission strings. Sets, not lists, so the union operator
        `|=` does the deduplicating for us — `viewer` being inherited twice
        contributes `report:read` exactly once.

    An UNKNOWN role name returns the empty set rather than raising. That is a
    deliberate choice about which way to fail: a typo in the policy then grants
    *less* than intended, never more. A policy engine should fail closed, and
    that includes failing closed on its own bugs.

    >>> sorted(expand_role("editor"))
    ['report:read', 'report:write']
    >>> expand_role("typo")
    set()
    """
    seen = _seen if _seen is not None else set()
    if role in seen or role not in ROLES:
        return set()
    seen.add(role)

    perms = set(ROLES[role]["grants"])
    for parent in ROLES[role]["inherits"]:
        perms |= expand_role(parent, seen)
    return perms


def permissions_of(user: "User") -> set[str]:
    """Every permission a user has, across all of their roles.

    A user may hold several roles at once, so this is the union of each
    expanded role. Union, never intersection: RBAC is additive, and holding a
    second role can only ever add permissions.

    Note there is no subtraction anywhere — no "role X, except report:delete".
    Deny rules are what ACLs have (see the deny ACEs in the week 7 lab); plain
    RBAC has no such thing, and adding one is how a readable policy starts
    becoming an unreadable one.
    """
    perms: set[str] = set()
    for role in user.roles:
        perms |= expand_role(role)
    return perms


# ═════════════════════════════════════════════════════════════════════════════
# 2. SUBJECTS
#
# The people (or programs) making requests. This section is week 6's lesson
# applied: never store a password, store a slow one-way function of it, with a
# unique random salt per user so two people with the same password get
# different stored values and one cracked hash does not reveal the other.
# ═════════════════════════════════════════════════════════════════════════════

# scrypt work factors. n is the memory/CPU cost — the number here is
# deliberately modest (2^14) so the demo starts instantly and five accounts
# hash in well under a second. Production values are higher; the point of a
# slow hash is that it is slow for the attacker guessing billions of times,
# and the cost you pick is how much you slow them down.
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**14, 8, 1


def hash_password(password: str, salt: bytes) -> bytes:
    """Derive the 32-byte stored value for a password.

    Deterministic given the same password and salt — that is exactly how
    verification works: hash the attempt with the stored salt and compare the
    result to the stored hash. The password itself is never stored, and this
    function cannot be run backwards.
    """
    return hashlib.scrypt(
        password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32
    )


@dataclass
class User:
    """One subject: a name, the credential material to prove it, and the roles
    assigned to it.

    @dataclass just writes the __init__ for us from these four annotations, so
    User("bob", salt, pwhash, {"editor"}) works with no boilerplate.

    Note the shape of `roles`: a set of role NAMES, not permissions. Nothing
    about what bob may do is stored on bob. Change ROLES above and bob's
    abilities change with it, with no user record touched — which is what
    makes the /admin/users page a one-line operation later.
    """
    name: str
    salt: bytes
    pwhash: bytes
    # default_factory=set gives every User its own empty set. A bare
    # `roles: set = set()` would share ONE set between all users — a classic
    # Python trap, and here it would mean granting one person a role granted
    # it to everybody.
    roles: set[str] = field(default_factory=set)

    def verify(self, password: str) -> bool:
        """True if `password` is this user's password.

        compare_digest, never ==. A plain == returns as soon as it finds a
        differing byte, so the time it takes leaks how many leading bytes were
        correct, and an attacker who can measure that can recover the value a
        byte at a time. compare_digest always looks at everything.
        """
        return hmac.compare_digest(self.pwhash, hash_password(password, self.salt))


# Build the in-memory user table at startup: fresh random salt per account,
# then hash the seed password with it. After this loop the plaintext passwords
# exist only in SEED_USERS (for the login page's demo table) and never in a
# User object.
USERS: dict[str, User] = {}
for _name, (_pw, _roles) in SEED_USERS.items():
    _salt = secrets.token_bytes(16)          # 16 random bytes, per user
    USERS[_name] = User(_name, _salt, hash_password(_pw, _salt), set(_roles))


# ═════════════════════════════════════════════════════════════════════════════
# 3. OBJECTS
#
# The things being protected. Kept deliberately boring — a list of dicts in
# memory — because none of the interesting behaviour lives here. Note what a
# report does NOT carry: any permission information at all. In the ACL model
# from the main lab this is exactly where the policy would live, attached to
# each object; in RBAC it lives entirely in section 1, attached to the subject.
#
# `author` is stored but never checked. That is the deliberate gap discussed at
# the end of README.md: RBAC can say "editors may edit reports" but not "bob
# may edit *this* report", so in this demo everyone with report:write can edit
# everything. Answering the second question needs an ownership check or an ACL.
# ═════════════════════════════════════════════════════════════════════════════

# Three reports with three different authors, so ownership is a real question
# (see may_modify) and so each demo in section 6 has its own report to destroy
# without spoiling the next one. Restart the server to restore this list.
REPORTS: list[dict] = [
    {"id": 1, "title": "Q3 incident review",   "body": "Three phishing attempts, none successful.", "author": "bob"},
    {"id": 2, "title": "Access review 2026",   "body": "17 dormant accounts found and disabled.",   "author": "alice"},
    {"id": 3, "title": "Phishing drill notes", "body": "12% click rate, down from 31% last year.",  "author": "dave"},
]
_next_report_id = 4      # trivial id allocator; a database would do this


# ═════════════════════════════════════════════════════════════════════════════
# 4. THE REFERENCE MONITOR
#
# The heart of the program. A "reference monitor" is the classical name for the
# component that sits between every request and every resource and decides
# whether to allow it. The theory asks three properties of it, and they are
# worth checking against the code as you read:
#
#   always invoked    — nothing reaches a protected resource around it.
#                       Here that is @requires on every protected route... and
#                       section 6 is what happens when someone forgets one.
#   tamper-proof      — the subject cannot edit the policy to suit itself.
#                       Changing roles needs user:manage, like anything else.
#   small enough to verify — one function, check(), fifty lines, no branches
#                       that depend on which route called it.
#
# That last property is the one to take away. There is exactly ONE place in
# this program where the word "allowed" is computed, which means exactly one
# place to audit, one place to test, and one place to get wrong.
#
# The section has four pieces, in dependency order:
#   check()         decide, record, and explain            <- the decision
#   format_decision() render one decision as a console trace
#   current_user()  authenticate the caller                <- who is asking
#   requires()      the decorator that puts them together  <- the enforcement
# ═════════════════════════════════════════════════════════════════════════════

DECISIONS: list[dict] = []      # every decision ever made; newest last. /audit
                                # reads this, and it is capped only by the -100
                                # slice when rendering. A real system writes to
                                # an append-only log the application cannot edit.
QUIET = False                   # --quiet suppresses the console traces
SAFE_OUTPUT = False             # --safe turns on the output encoding that
                                # section 6B is missing. Off by default: this
                                # server is deliberately vulnerable.


def check(user: User | None, permission: str) -> tuple[bool, dict]:
    """Decide whether `user` may exercise `permission`, and record why.

    THE function. Every access decision in this program is made here, and the
    only input that matters is the pair (subject, permission) — never the URL,
    never the route name, never who the caller happens to be. That is what
    makes the policy in section 1 the single source of truth.

    Args:
        user:       the authenticated subject, or None if nobody is logged in.
                    None is a normal value here, not an error case.
        permission: the permission the caller demands, e.g. "report:write".

    Returns:
        (allowed, record) — the verdict, and a dict explaining how it was
        reached. The record is appended to DECISIONS (so /audit can show it)
        and printed to the console, which is why every denial in this demo
        arrives with its own reasoning attached.

    DENY BY DEFAULT is the structure of the if/elif chain below. Read the
    branches as a list of everything that can go wrong — no session, a
    permission that does not exist, a subject with no roles, a subject whose
    roles do not add up — and notice that only ONE branch sets allowed=True,
    and it is reached only by the permission being present in the expanded set.
    Everything else, including cases nobody thought of, falls through to a
    denial. Written the other way round (deny a list of bad cases, allow the
    rest) the forgotten case becomes an allow, and forgotten cases are the ones
    you ship.

    The distinct `reason` strings are a teaching aid, not a template. Telling a
    real attacker precisely why they were refused is often more help than you
    want to give; production systems typically log the detail and return
    something bland.
    """
    # Sorted lists rather than sets: stable ordering for the log and the UI.
    roles = sorted(user.roles) if user else []
    granted = sorted(permissions_of(user)) if user else []   # after inheritance

    if user is None:
        allowed, reason = False, "no authenticated subject"
    elif permission not in PERMISSIONS:
        allowed, reason = False, f"unknown permission {permission!r} — denying by default"
    elif permission in granted:
        # Which of the user's roles actually supplied it — purely so the trace
        # can say "granted via editor" instead of just "allowed".
        holders = [r for r in roles if permission in expand_role(r)]
        allowed, reason = True, f"granted via role(s): {', '.join(holders)}"
    elif not roles:
        allowed, reason = False, "subject holds no roles"
    else:
        allowed, reason = False, f"no role held by this subject grants {permission}"

    record = {
        "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
        "subject": user.name if user else "<anonymous>",
        "roles": roles,
        "granted": granted,
        "required": permission,
        "allowed": allowed,
        "reason": reason,
        # `request` is Flask's per-request object. The guard lets check() be
        # called outside a request (e.g. from a test) without blowing up.
        "method": request.method if request else "-",
        "path": request.path if request else "-",
    }
    DECISIONS.append(record)
    if not QUIET:
        print(format_decision(record), file=sys.stderr, flush=True)
    return allowed, record


def format_decision(d: dict) -> str:
    """Render one decision as the four-line console trace.

    The shape is the argument the reference monitor made, in order: what was
    asked, what the subject holds, what that expands to, and the conclusion.

        [DENY ] POST   /api/reports   subject=carol   needs=report:write
                roles     : viewer
                expands to: report:read
                reason    : no role held by this subject grants report:write

    Printed to stderr so that piping the server's stdout somewhere does not
    swallow the security log.
    """
    verdict = "ALLOW" if d["allowed"] else "DENY "
    return (
        f"  [{verdict}] {d['method']:<6} {d['path']:<28} "
        f"subject={d['subject']:<10} needs={d['required']}\n"
        f"          roles     : {', '.join(d['roles']) or '(none)'}\n"
        f"          expands to: {', '.join(d['granted']) or '(nothing)'}\n"
        f"          reason    : {d['reason']}"
    )


def current_user() -> User | None:
    """AUTHENTICATION — who is asking? Returns the User, or None.

    Deliberately a separate function from check(). Conflating the two is how
    "logged in" quietly becomes "authorised", which is the bug in section 6.
    This function's entire job is identity; it never looks at a permission,
    and returning a User says nothing about what that user may do.

    Two mechanisms are supported so that both a browser and curl work against
    the same routes:

      HTTP Basic     `curl -u bob:bob123 ...`. The password is verified on
                     every single request. Checked first so that passing -u
                     always overrides whatever cookie you happen to hold.
      Session cookie set by POST /login. Flask signs the cookie with
                     app.secret_key, so the client can READ it but cannot
                     forge it — which is why it is safe to keep the username
                     there. Note what is not stored in it: the roles. Those are
                     looked up fresh from USERS on every request, so revoking a
                     role takes effect immediately instead of when the victim
                     next logs in.

    Returns None for "no credentials" and for "wrong password" alike. The
    caller cannot tell the difference, and does not need to — both mean
    nobody is authenticated.
    """
    auth = request.authorization              # the Authorization: Basic header
    if auth and auth.username in USERS:
        user = USERS[auth.username]
        if user.verify(auth.password or ""):
            return user
        return None                           # bad password: do NOT fall back
                                              # to the cookie, or a wrong -u
                                              # would silently use the session
    name = session.get("user")                # the signed cookie
    return USERS.get(name) if name else None


def wants_json() -> bool:
    """Should an error be JSON rather than an HTML page?

    Content negotiation, kept crude on purpose. Anything under /api/ is an API
    route, and a request carrying HTTP Basic came from a script rather than a
    browser. Real applications inspect the Accept header instead.
    """
    return request.path.startswith("/api/") or bool(request.authorization)


def requires(permission: str):
    """Route guard: the whole of RBAC enforcement, in one decorator.

    Used like this, on any route that needs protecting:

        @app.post("/reports")
        @requires("report:write")
        def create_report():
            ...

    WHAT A DECORATOR IS DOING HERE, if this is the first one you have read
    closely. `@requires("report:write")` above a function means:

        create_report = requires("report:write")(create_report)

    so the name `create_report` no longer refers to the original function. It
    refers to `wrapper` below, which authenticates, calls check(), and only
    then — if allowed — calls the original view. The route Flask registered
    therefore cannot be reached without passing through the check. That is the
    "always invoked" property from the section header, bought with three
    nested functions:

        requires(permission)   captures WHICH permission this route needs
          └─ decorator(view)   receives the view function being wrapped
               └─ wrapper(...) runs on every request to that route

    Order matters when stacking them. @app.get(...) goes on TOP so that what
    Flask registers as the handler is the wrapper, not the bare view. Reversed,
    Flask would register the unguarded function and the check would never run —
    a real and very quiet way to lose an access control.

    @wraps(view) copies the original function's __name__ onto the wrapper.
    Without it every wrapped view would be called "wrapper", Flask would see
    several endpoints with the same name, and it would refuse to start.

    Note what this decorator does NOT do: it never looks at the username, and
    it never looks at a role. Routes name a permission and nothing else, so
    changing who may delete a report is an edit to ROLES in section 1, not a
    hunt through the handlers. `@requires("report:delete")` is right;
    `if "admin" in user.roles` scattered through the views is the same decision
    made in twenty places, nineteen of which will eventually disagree.
    """
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            # 1. WHO is asking (may be None — that is fine, check() handles it)
            user = current_user()
            # 2. MAY they? The one decision point. Also logs and traces.
            allowed, record = check(user, permission)
            # 3. Only now is the actual view function allowed to run. Note that
            #    *args/**kwargs pass through untouched, so a route like
            #    /reports/<int:rid>/delete still receives its rid.
            if allowed:
                return view(*args, **kwargs)

            # ── Denied. Now: which kind of "no"? ──────────────────────────
            # 401 Unauthorized = "I do not know who you are" (despite the name,
            #     401 is about authentication). Try again with credentials.
            # 403 Forbidden    = "I know exactly who you are, and no."
            #     Credentials will not help; you need a different role.
            # Getting these the wrong way round is a real bug, not pedantry:
            # answering 401 to an authenticated-but-unauthorised user tells an
            # attacker that some other credential would have worked, which is
            # precisely the thing they are trying to find out.
            status = 401 if user is None else 403
            if wants_json():
                return jsonify(error=record["reason"], required=permission,
                               subject=record["subject"], roles=record["roles"]), status
            if user is None:
                return redirect(url_for("login", next=request.path))
            return page("403 — Forbidden", f"""
              <h2 class=deny>403 &mdash; Forbidden</h2>
              <p>You are signed in as <b>{out(user.name)}</b>, holding
                 <b>{out(', '.join(sorted(user.roles))) or 'no roles'}</b>.</p>
              <p>This route requires <code>{out(permission)}</code>.
                 {out(record['reason'].capitalize())}.</p>
              <p class=muted>Authenticated is not the same as authorised.</p>
            """), status
        return wrapper
    return decorator


# ═════════════════════════════════════════════════════════════════════════════
# 5. THE WEB APP
#
# From here down it is plumbing: routes, some hand-written HTML, and a JSON
# API. The security is entirely in section 4 — every protected route below is
# one @requires line, and none of them contains a permission decision of its
# own. Read the decorators, and you have read the access control.
#
# The pages do use permissions_of() to decide what to *show* (hiding a delete
# button from someone who cannot delete). That is user interface, not security:
# the request still arrives at a guarded route and is still checked. Section 6
# is what happens when someone mistakes the first for the second.
#
# HTML is built with f-strings, and every value going into a page passes
# through out(). By default out() does NOTHING — that is bug family 6B, and it
# is deliberate. Read out()'s docstring before changing anything here: in an
# app built around access control, an injection IS an access-control bypass,
# because a script stored by one user runs with the next user's session and
# permissions. Run with --safe to turn the encoding on and compare.
# ═════════════════════════════════════════════════════════════════════════════

def out(value) -> str:
    """Render a value into page text. **Vulnerable by default — on purpose.**

    Every f-string in this file that drops a value into HTML goes through this
    one function, which means this is also the single place the bug lives:

        default          returns the value unchanged  -> injectable
        --safe           HTML-escapes it              -> not injectable

    Run the server both ways with the same payload. That is the lesson.

    WHY IT BELONGS IN AN RBAC DEMO. An injection here is not a separate topic
    from access control, it is an ACCESS CONTROL BYPASS:

        A script stored by one user runs in another user's browser, with that
        user's session, and therefore with THAT USER'S PERMISSIONS. No
        @requires is violated. The victim's browser makes the request, the
        victim's roles are checked, and the check honestly passes. Every guard
        in section 4 is intact and completely bypassed.

    So an `editor` who can get a script in front of an `admin` effectively
    holds `user:manage`, without ever being granted it. See section 6B.

    Note what the real fix is. It is not "remember to call out()" — this file
    calls it in fourteen places and would only need to miss one. It is to use a
    template engine that escapes by DEFAULT, so that being unsafe is the thing
    you have to ask for. Escaping by hand means being right every single time.
    """
    return escape(str(value), quote=True) if SAFE_OUTPUT else str(value)


def is_safe_next(target: str | None) -> bool:
    """Is `target` a safe post-login redirect? **Only consulted with --safe.**

    Same-site paths only: it must start with a single "/". Without this check
    ?next=https://evil.example redirects the freshly-authenticated user
    off-site, which is how a convincing phishing link is built out of a
    legitimate domain. "//evil.example" is protocol-relative and must be
    rejected too, which is why the second character is tested.
    """
    return bool(target) and target.startswith("/") and not target.startswith("//")


app = Flask(__name__)

# The key Flask uses to sign session cookies. Generated fresh on every run, so
# restarting the server invalidates every session — convenient for a demo,
# where "restart == everyone logged out" is a feature. A real deployment loads
# a persistent secret from configuration; if this value ever leaks, anyone can
# mint a cookie claiming to be any user, which is authentication bypassed.
app.secret_key = secrets.token_bytes(32)

CSS = """
:root { color-scheme: light dark; }
body   { font: 15px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
         max-width: 52rem; margin: 2rem auto; padding: 0 1.2rem; }
nav    { display:flex; gap:.9rem; flex-wrap:wrap; padding-bottom:.7rem;
         border-bottom:1px solid #8884; margin-bottom:1.4rem; }
nav .spacer { flex:1 }
h1     { font-size:1.25rem } h2 { font-size:1.05rem; margin-top:1.8rem }
table  { border-collapse:collapse; width:100%; margin:.6rem 0 }
th, td { border:1px solid #8884; padding:.35rem .55rem; text-align:left; vertical-align:top }
th     { background:#8881 }
code   { background:#8882; padding:.05rem .3rem; border-radius:3px }
.allow { color:#118a3d } .deny { color:#c62828 }
.muted { opacity:.65 } .yes { color:#118a3d; font-weight:bold } .no { opacity:.35 }
form.inline { display:inline }
button, input { font:inherit; padding:.25rem .5rem }
button { cursor:pointer }
pre    { background:#8881; padding:.7rem; overflow-x:auto; border-radius:4px }
.card  { border:1px solid #8884; border-radius:5px; padding:.7rem 1rem; margin:.7rem 0 }
"""


def page(title: str, body: str) -> str:
    """Wrap a fragment of HTML in the shared layout: title, CSS, nav bar.

    The nav shows who you are and what roles you hold, so every screenshot in
    this demo carries its own context. Note that the nav links to routes you
    may not be allowed to visit — deliberately. Clicking one and reading the
    403 is more instructive than never being shown it existed.
    """
    user = current_user()
    if user:
        who = (f"<b>{out(user.name)}</b> &mdash; "
               f"{out(', '.join(sorted(user.roles))) or 'no roles'} "
               f"<form class=inline method=post action='/logout'>"
               f"<button>log out</button></form>")
    else:
        who = "<a href='/login'>log in</a>"
    return f"""<!doctype html><meta charset=utf-8>
<title>{out(title)} &middot; RBAC demo</title><style>{CSS}</style>
<nav>
  <a href='/'>home</a> <a href='/reports'>reports</a> <a href='/audit'>audit</a>
  <a href='/admin/users'>users</a> <a href='/policy'>policy</a>
  <span class=spacer></span> {who}
</nav>
{body}"""


# ── Authentication ───────────────────────────────────────────────────────────

@app.get("/login")
def login():
    """Show the login form. Public, obviously — it is how you stop being
    anonymous. Every OTHER route is either public by explicit decision
    (/, /policy) or carries a @requires."""
    accounts = "".join(
        f"<tr><td><code>{out(n)}</code></td><td><code>{out(p)}</code></td>"
        f"<td>{out(', '.join(r)) or '<span class=muted>none</span>'}</td></tr>"
        for n, (p, r) in SEED_USERS.items()
    )
    return page("Log in", f"""
      <h1>Log in</h1>
      <form method=post>
        <p><input name=username placeholder=username autofocus>
           <input name=password type=password placeholder=password>
           <input type=hidden name=next value="{out(request.args.get('next', '/'))}">
           <button>log in</button></p>
      </form>
      <h2>Demo accounts</h2>
      <p class=muted>Passwords are printed here because this is a teaching demo.
         They are still stored as salted scrypt hashes, never in plaintext.</p>
      <table><tr><th>user</th><th>password</th><th>roles</th></tr>{accounts}</table>
    """)


@app.post("/login")
def do_login():
    """Verify credentials and start a session.

    Note the boundary: this is the ONLY place a password is checked, and it
    grants no permissions. All it does is write the username into the session
    cookie. What that user may then do is decided fresh on every subsequent
    request by check().
    """
    name = request.form.get("username", "")
    user = USERS.get(name)
    if user and user.verify(request.form.get("password", "")):
        session["user"] = user.name
        print(f"  [AUTH ] {name} authenticated, roles: "
              f"{', '.join(sorted(user.roles)) or '(none)'}", file=sys.stderr, flush=True)
        # BUG #7 (section 6B): `next` is used verbatim. With --safe it is
        # validated as a same-site path first.
        nxt = request.form.get("next")
        if SAFE_OUTPUT and not is_safe_next(nxt):
            nxt = "/"
        return redirect(nxt or "/")
    # Same message and same status whether the username was unknown or the
    # password was wrong. Distinguishing them turns the login form into a free
    # tool for enumerating valid accounts — half of a credential-stuffing
    # attack solved by an unnecessarily helpful error message.
    print(f"  [AUTH ] failed login for {name!r}", file=sys.stderr, flush=True)
    return page("Log in", "<h2 class=deny>Invalid credentials</h2>"
                          "<p><a href='/login'>try again</a></p>"), 401


@app.post("/logout")
def logout():
    """Drop the session. POST rather than GET on purpose: a GET /logout can be
    triggered by any image tag on any page, which is a (mild) CSRF."""
    session.pop("user", None)
    return redirect("/")


# ── Public ───────────────────────────────────────────────────────────────────

@app.get("/")
def home():
    """The subject's own view of the policy: roles held, roles after
    inheritance, permissions that expands to, and a table of what is allowed.

    Log in as each of the five accounts and compare this page. It is the same
    code and the same policy every time; only the role assignment differs.
    """
    user = current_user()
    if not user:
        return page("Home", """
          <h1>RBAC demo</h1>
          <p>An unauthenticated subject holds no roles, so it has no permissions.
             Everything below is denied until you <a href='/login'>log in</a>.</p>
          <p>Try a protected route while logged out &mdash;
             <a href='/reports'>/reports</a> &mdash; and watch the console.</p>
        """)

    rows = "".join(
        f"<tr><td><code>{out(p)}</code></td><td>{out(d)}</td>"
        f"<td class={'yes' if p in permissions_of(user) else 'no'}>"
        f"{'✔ allowed' if p in permissions_of(user) else '✘ denied'}</td></tr>"
        for p, d in PERMISSIONS.items()
    )
    return page("Home", f"""
      <h1>Signed in as {out(user.name)}</h1>
      <div class=card>
        <p><b>Roles assigned:</b> {out(', '.join(sorted(user.roles))) or '<span class=muted>none</span>'}</p>
        <p><b>Roles after inheritance:</b>
           {out(', '.join(sorted(effective_roles(user)))) or '<span class=muted>none</span>'}</p>
        <p><b>Permissions:</b>
           {out(', '.join(sorted(permissions_of(user)))) or '<span class=muted>none</span>'}</p>
      </div>
      <h2>What you may do</h2>
      <table><tr><th>permission</th><th>meaning</th><th>you</th></tr>{rows}</table>
      <p class=muted>This table is rendered from the same policy the server
         enforces &mdash; but rendering it is not enforcement. See
         <a href='/policy'>/policy</a>.</p>
    """)


def effective_roles(user: User) -> set[str]:
    """Assigned roles plus every role they inherit. For DISPLAY only.

    expand_role() answers "which permissions", this answers "which roles" — it
    is what lets the home page show that bob, assigned only `editor`, is also
    acting as `viewer`. Nothing enforces anything with this; check() works in
    permissions, not roles.

    Written as an explicit stack rather than recursion, as a second way to see
    the same graph walk: pop a role, record it, push everything it inherits,
    and skip anything already recorded so cycles terminate.
    """
    out: set[str] = set()
    stack = list(user.roles)
    while stack:
        r = stack.pop()
        if r in out or r not in ROLES:
            continue
        out.add(r)
        stack.extend(ROLES[r]["inherits"])
    return out


@app.get("/policy")
def policy():
    """The whole policy as a role x permission matrix, expanded.

    Deliberately public, with no @requires. The policy is not the secret; the
    credentials are. A system whose security depends on nobody knowing the
    rules is not secure, it is merely undocumented — and the people who most
    need to read the rules are the ones auditing them.

    This page is generated from ROLES and PERMISSIONS, so it cannot drift out
    of date with what the server enforces. Documentation that is derived from
    the policy stays true; documentation that describes it separately does not.
    """
    head = "".join(f"<th>{out(p)}</th>" for p in PERMISSIONS)
    rows = ""
    for role in ROLES:
        perms = expand_role(role)
        cells = "".join(
            f"<td class={'yes' if p in perms else 'no'}>"
            f"{'✔' if p in perms else '·'}</td>" for p in PERMISSIONS
        )
        inh = ", ".join(ROLES[role]["inherits"]) or "—"
        rows += f"<tr><th>{out(role)}</th><td class=muted>{out(inh)}</td>{cells}</tr>"
    return page("Policy", f"""
      <h1>Policy</h1>
      <p>The complete security model, expanded through role inheritance.</p>
      <table><tr><th>role</th><th>inherits</th>{head}</tr>{rows}</table>
      <h2>Why this shape</h2>
      <ul>
        <li>Routes are guarded by <b>permission</b>, never by role name and never
            by username. Changing who may do what is an edit to this table.</li>
        <li>Roles inherit, so <code>admin</code> never restates what
            <code>editor</code> already grants.</li>
        <li>There is no per-user exception anywhere. The moment a system needs
            one, its roles no longer describe the organisation.</li>
      </ul>
    """)


# ── Reports: guarded by permission ───────────────────────────────────────────

@app.get("/reports")
@requires("report:read")
def list_reports():
    """List reports. Requires report:read.

    Below, permissions_of() decides which buttons to render. Say it once more,
    because it is the single most misunderstood line in the file: THAT IS NOT
    THE SECURITY. Hiding the delete button is a courtesy to the user, so they
    are not offered something that will fail. What actually stops a viewer
    deleting a report is @requires("report:delete") on the delete route — and
    curl never sees a button at all.
    """
    user = current_user()
    may_delete = "report:delete" in permissions_of(user)   # UI only, not a check
    items = ""
    for r in REPORTS:
        btn = (f"<form class=inline method=post action='/reports/{r['id']}/delete'>"
               f"<button>delete</button></form>") if may_delete else ""
        items += (f"<div class=card><b>#{r['id']} {out(r['title'])}</b> "
                  f"<span class=muted>by {out(r['author'])}</span><br>"
                  f"{out(r['body'])}<br>{btn}</div>")

    new = ("""<h2>New report</h2>
      <form method=post action='/reports'>
        <p><input name=title placeholder=title size=30>
           <input name=body placeholder=body size=40>
           <button>create</button></p></form>"""
      if "report:write" in permissions_of(user) else
      "<p class=muted>You may read reports but not create them "
      "(<code>report:write</code> not granted).</p>")

    return page("Reports", f"<h1>Reports</h1>{items or '<p class=muted>None.</p>'}{new}")


@app.post("/reports")
@requires("report:write")
def create_report():
    """Create a report. Requires report:write.

    The body of this function has no security logic whatsoever, and that is
    the point of the design: by the time it runs, the decision is made. A view
    you can read as pure application logic is a view you can reason about.
    """
    global _next_report_id
    REPORTS.append({
        "id": _next_report_id,
        "title": request.form.get("title") or "untitled",
        "body": request.form.get("body") or "",
        "author": current_user().name,
    })
    _next_report_id += 1
    return redirect("/reports")


@app.post("/reports/<int:rid>/delete")
@requires("report:delete")
def delete_report(rid: int):
    """Delete any report. Requires report:delete.

    Compare with /broken/reports/<id>/delete in section 6, which is this same
    function with the decorator left off. One line is the difference between an
    enforced control and a UI suggestion.
    """
    global REPORTS
    REPORTS = [r for r in REPORTS if r["id"] != rid]
    return redirect("/reports")


# ── Audit log: the log itself is an object under access control ──────────────

@app.get("/audit")
@requires("audit:read")
def audit():
    """The decision log. Requires audit:read.

    Two things worth noticing. First, the log of access decisions is ITSELF an
    object under access control — systems that forget this let an intruder read,
    or quietly edit, the record of what they did. Second, loading this page
    generates a decision, so the top row is always the check that let you in.
    The monitor logs itself.
    """
    rows = ""
    for d in reversed(DECISIONS[-100:]):
        cls = "allow" if d["allowed"] else "deny"
        rows += (f"<tr><td class=muted>{out(d['time'])}</td>"
                 f"<td class={cls}>{'ALLOW' if d['allowed'] else 'DENY'}</td>"
                 f"<td>{out(d['subject'])}</td>"
                 f"<td class=muted>{out(d['method'])} {out(d['path'])}</td>"
                 f"<td><code>{out(d['required'])}</code></td>"
                 f"<td class=muted>{out(d['reason'])}</td></tr>")
    return page("Audit", f"""
      <h1>Authorisation decisions</h1>
      <p class=muted>Every call to the reference monitor, newest first &mdash;
         including the one that let you read this page.</p>
      <table><tr><th>time</th><th>verdict</th><th>subject</th><th>request</th>
      <th>required</th><th>reason</th></tr>{rows}</table>
    """)


# ── Role administration ──────────────────────────────────────────────────────

@app.get("/admin/users")
@requires("user:manage")
def admin_users():
    """Role assignment. Requires user:manage.

    This page is the payoff of the whole design. Granting `viewer` to mallory
    edits one set, and she can immediately read reports — no restart, no
    deployment, no code change, and nothing anywhere in the codebase mentions
    her. Administering access became data entry, which is what RBAC is for.
    """
    rows = ""
    for u in USERS.values():
        opts = "".join(f"<option>{out(r)}</option>" for r in ROLES)
        rows += f"""<tr><td><b>{out(u.name)}</b></td>
          <td>{out(', '.join(sorted(u.roles))) or '<span class=muted>none</span>'}</td>
          <td class=muted>{out(', '.join(sorted(permissions_of(u)))) or '—'}</td>
          <td><form class=inline method=post action='/admin/users/{out(u.name)}/roles'>
              <select name=role>{opts}</select>
              <button name=action value=grant>grant</button>
              <button name=action value=revoke>revoke</button></form></td></tr>"""
    return page("Users", f"""
      <h1>Users and role assignments</h1>
      <p class=muted>Grant <code>viewer</code> to mallory, then load
         <a href='/reports'>/reports</a> as mallory &mdash; no code changes,
         no restart. That is the point of RBAC.</p>
      <table><tr><th>user</th><th>roles</th><th>effective permissions</th>
      <th>assign</th></tr>{rows}</table>
    """)


@app.post("/admin/users/<name>/roles")
@requires("user:manage")
def set_roles(name: str):
    """Grant or revoke one role. Requires user:manage.

    Note the validation on the next few lines: the role must exist in ROLES and
    the action must be one of two known strings. Input arriving from a form is
    input from the client, whatever the <select> offered — a hand-written POST
    can carry any value at all, so the server checks rather than trusts.

    Also note the recursion in the permission itself: user:manage lets you
    grant user:manage. That is a real and deliberate property of admin roles,
    and the reason such assignments are worth auditing.
    """
    user = USERS.get(name)
    role = request.form.get("role", "")
    action = request.form.get("action")
    if user and role in ROLES and action in ("grant", "revoke"):
        if action == "grant":
            user.roles.add(role)
            verb = "granted"
        else:
            user.roles.discard(role)
            verb = "revoked"
        print(f"  [ADMIN] {current_user().name} {verb} {role!r} on {name}: "
              f"now {sorted(user.roles) or 'no roles'}", file=sys.stderr, flush=True)
    return redirect("/admin/users")


# ── JSON API — the same guards, no HTML ──────────────────────────────────────
# curl -u bob:bob123 http://127.0.0.1:8000/api/reports

@app.get("/api/whoami")
def api_whoami():
    """Report the caller's own identity and effective permissions.

    Public in the sense that it carries no @requires — it tells you about
    yourself and nothing else, and refuses if you are nobody. The quickest way
    to see role inheritance at work:

        curl -u bob:bob123 http://127.0.0.1:8000/api/whoami

    bob is assigned exactly one role, and comes back holding two.
    """
    user = current_user()
    if not user:
        return jsonify(error="not authenticated"), 401
    return jsonify(subject=user.name, roles=sorted(user.roles),
                   effective_roles=sorted(effective_roles(user)),
                   permissions=sorted(permissions_of(user)))


# The JSON routes below are the SAME guards as the HTML ones above, with the
# HTML removed. That is the demonstration: authorisation belongs to the route,
# not to the presentation layer, so the API cannot be a way around the UI.

@app.get("/api/reports")
@requires("report:read")
def api_reports():
    """curl -u carol:carol123 http://127.0.0.1:8000/api/reports"""
    return jsonify(REPORTS)


@app.post("/api/reports")
@requires("report:write")
def api_create():
    global _next_report_id
    data = request.get_json(silent=True) or {}
    report = {"id": _next_report_id, "title": data.get("title", "untitled"),
              "body": data.get("body", ""), "author": current_user().name}
    REPORTS.append(report)
    _next_report_id += 1
    return jsonify(report), 201


@app.delete("/api/reports/<int:rid>")
@requires("report:delete")
def api_delete(rid: int):
    global REPORTS
    REPORTS = [r for r in REPORTS if r["id"] != rid]
    return jsonify(deleted=rid)


def may_modify(user: User, report: dict) -> bool:
    """Object-level check: may this user change THIS report?

    RBAC and this function answer two different questions, and a complete
    decision needs both:

        @requires("report:write")   may you edit reports AT ALL?   (the verb)
        may_modify(user, report)    may you edit THIS one?         (the noun)

    RBAC alone cannot express the second. "editor" is a property of the
    subject; "alice's report" is a property of the object, and no amount of
    role modelling turns one into the other. So the rule lives here, next to
    the object, in the one place that can see both:

        you own it, or you hold report:delete (which is this demo's stand-in
        for "a moderator may override ownership").

    Skipping this second check is IDOR — Insecure Direct Object Reference,
    also called broken object-level authorisation. It is the most common
    serious flaw in real APIs, and section 6 has a working example of it.
    """
    return report["author"] == user.name or "report:delete" in permissions_of(user)


@app.post("/api/reports/<int:rid>/edit")
@requires("report:write")
def api_edit(rid: int):
    r"""Edit a report. Requires report:write AND ownership.

    The CORRECT version. Compare with /broken/reports/<id>/edit in section 6,
    which has the identical decorator and omits the four lines below.

        curl -u bob:bob123 -X POST -H 'Content-Type: application/json' \
             -d '{"title":"edited"}' http://127.0.0.1:8000/api/reports/1/edit
    """
    report = next((r for r in REPORTS if r["id"] == rid), None)
    if report is None:
        return jsonify(error="no such report"), 404

    # The decorator got us here; it proved this subject may edit reports in
    # general. It knows nothing about WHICH report, because the permission
    # does not mention one. That question is answered here, or nowhere.
    user = current_user()
    if not may_modify(user, report):
        print(f"  [DENY ] POST   {request.path:<28} subject={user.name:<10} "
              f"needs=ownership of report {rid}\n"
              f"          reason    : report belongs to {report['author']}, "
              f"and {user.name} does not hold report:delete",
              file=sys.stderr, flush=True)
        return jsonify(error=f"report {rid} belongs to {report['author']}",
                       subject=user.name,
                       note="RBAC allowed the verb; ownership denied the noun"), 403

    data = request.get_json(silent=True) or {}
    report["title"] = data.get("title", report["title"])
    report["body"] = data.get("body", report["body"])
    return jsonify(report)


@app.get("/api/policy")
def api_policy():
    """The machine-readable policy. Public, for the same reason /policy is."""
    return jsonify(permissions=PERMISSIONS,
                   roles={r: {"inherits": ROLES[r]["inherits"],
                              "grants": ROLES[r]["grants"],
                              "effective": sorted(expand_role(r))} for r in ROLES})


# ═════════════════════════════════════════════════════════════════════════════
# 6. BROKEN ON PURPOSE
#
# ############################################################################
# #  THIS SERVER IS DELIBERATELY VULNERABLE. It is a teaching target, like    #
# #  DVWA or WebGoat. Run it on localhost, never expose it, never copy these  #
# #  patterns into anything real. Seven planted bugs, in two families:        #
# ############################################################################
#
# 6A — BROKEN AUTHORISATION (#1-#3, below)
#      The check is missing, fooled, or too coarse. Each has a correct twin
#      elsewhere in the file, and the diff between them is small — which is the
#      point. Broken authorisation does not look broken. It looks like working
#      code with a line missing.
#
# 6B — BROKEN OUTPUT ENCODING (#4-#7, implemented in out() and do_login)
#      Three XSS and an open redirect, live because out() is a no-op by
#      default. These bypass authorisation WITHOUT TOUCHING IT: an injected
#      script runs in the victim's browser, so the victim's session and roles
#      are used, and every check in section 4 passes honestly while being
#      completely defeated.
#
#      #4  stored XSS   a report title/body        editor  -> anyone reading
#      #5  reflected    ?next= on /login           anyone  -> whoever clicks
#      #6  stored XSS   the REQUEST PATH, on /audit  ANYONE -> the auditor
#      #7  open redirect  next= on POST /login     anyone  -> whoever clicks
#
#      #6 is the one to sit with. check() records request.path on every
#      decision, /audit renders it, and a DENIED request is still recorded. So
#      `mallory`, who holds no roles and is refused everything, needs no
#      permission at all — only to be refused, at a route whose path she
#      chooses. Being rejected is sufficient.
#
#      Compare the two runs:
#          uv run app.py                 # payloads fire
#          uv run app.py --safe          # same payloads, inert
#
# 6A in detail:
#
#   #1  NO CHECK AT ALL          /broken/reports/<id>/delete
#       Authentication mistaken for authorisation. The route confirms you are
#       logged in and stops there.
#       twin: delete_report()          missing: @requires("report:delete")
#
#   #2  A CHECK THAT TRUSTS THE CLIENT   /broken/reports/<id>/delete-checked
#       A check runs, returns 403 when it fails, and is worthless, because the
#       value it tests is supplied by the caller.
#       twin: check()                  missing: server-side state
#
#   #3  THE RIGHT CHECK AT THE WRONG GRANULARITY   /broken/reports/<id>/edit
#       @requires is present and correct. It proves you may edit reports; it
#       cannot prove you may edit THIS report, because permissions do not name
#       objects. This is IDOR.
#       twin: api_edit()               missing: may_modify(user, report)
#
# A property they share, and the one worth taking away: NONE of them appear in
# /audit. The audit log records calls to check(), and in #1 and #2 check() is
# never called — so the log of who was refused has no trace of the bypass at
# all. #3 does appear, and it appears as an ALLOW, because the check that ran
# genuinely succeeded; it was simply answering a coarser question than the
# situation required. A clean audit log is not evidence that nothing happened.
#
# Run each one from the demo README's walkthrough, or:
#
#     curl -u carol:carol123 -X POST \
#          http://127.0.0.1:8000/broken/reports/1/delete
#     curl -u carol:carol123 -H 'X-Acting-Role: admin' -X POST \
#          http://127.0.0.1:8000/broken/reports/3/delete-checked
#     curl -u bob:bob123 -X POST -H 'Content-Type: application/json' \
#          -d '{"title":"bob was here"}' \
#          http://127.0.0.1:8000/broken/reports/2/edit
#
# carol is a viewer and bob does not own report 2. All three succeed. Each one
# uses a DIFFERENT report on purpose, so the three can be run in order against a
# single server without one destroying the next one's subject. Restart the
# server to put the seed data back.
# ═════════════════════════════════════════════════════════════════════════════

@app.post("/broken/reports/<int:rid>/delete")
def broken_delete(rid: int):
    """BROKEN #1 — no check at all. DO NOT COPY THIS.

    Compare it line by line with delete_report() above. The application logic
    is identical. The only difference is the missing @requires("report:delete")
    — and with it, the missing 403.

    The mental slip that produces this in real code is always the same one:
    the developer hid the delete button from users who cannot delete, saw the
    feature behave correctly in the browser, and concluded it was protected.
    But the browser is not where the request is authorised. Every HTTP request
    arrives at the server independently, carrying whatever the client chose to
    send, and a client under an attacker's control will not be sending what
    your UI would have sent.
    """
    global REPORTS
    user = current_user()
    if user is None:                       # authenticated ...
        return jsonify(error="not authenticated"), 401
    # ... and that is all that was checked. No permission check follows.
    before = len(REPORTS)
    REPORTS = [r for r in REPORTS if r["id"] != rid]
    print(f"  [BROKEN] {user.name} (roles: {sorted(user.roles) or 'none'}) deleted "
          f"report {rid} with NO permission check", file=sys.stderr, flush=True)
    return jsonify(deleted=rid, removed=before - len(REPORTS),
                   subject=user.name, roles=sorted(user.roles),
                   note="No authorisation check ran. This endpoint is the bug.")


@app.post("/broken/reports/<int:rid>/delete-checked")
def broken_delete_checked(rid: int):
    r"""BROKEN #2 — a check that trusts the client. DO NOT COPY THIS.

    This one is more interesting than #1, because there IS a check. It runs on
    every request. It returns a correct-looking 403 when it fails. Reviewers
    skim it and move on. And it is worthless, because the thing it tests
    arrives in the request:

        curl -u carol:carol123 -X POST \
             http://127.0.0.1:8000/broken/reports/3/delete-checked
        → 403, "role 'viewer' may not delete"          the check works!

        curl -u carol:carol123 -H 'X-Acting-Role: admin' -X POST \
             http://127.0.0.1:8000/broken/reports/3/delete-checked
        → 200, deleted                                  ...does it?

    carol is a viewer. She said she was an admin, and the server believed her.

    How this gets written: someone builds a "switch role" feature, keeps the
    active role in a header or a hidden form field so the front end can manage
    it, and then reads that field back for the security decision. The front end
    is not a trustworthy source, because the front end is not the front end —
    it is whatever the caller chose to send. Everything from the client is
    input: headers, cookies, hidden fields, JSON bodies, the URL, and any
    "user_id" or "role" or "is_admin" among them.

    THE RULE: an authorisation decision may only read state the server itself
    holds. In this application that means USERS[...].roles, reached through
    current_user() — never request.headers, request.form or request.args.

    Compare with check(), which takes a User object the server looked up and a
    permission the ROUTE named. Neither input can be influenced by the caller.
    Note also the second, quieter bug here: it tests a ROLE NAME rather than a
    permission, so it would have to be edited by hand the day a new role needs
    to delete things.
    """
    global REPORTS
    user = current_user()
    if user is None:
        return jsonify(error="not authenticated"), 401

    # ── THE BUG IS THIS EXPRESSION ───────────────────────────────────────────
    # It reads the caller's own claim first and only falls back to what the
    # server knows. Anyone may assert anything.
    acting_role = (request.headers.get("X-Acting-Role")
                   or request.form.get("acting_role")
                   or (sorted(user.roles)[0] if user.roles else "none"))

    # A real check, on a fabricated value. Note it never calls check(), so
    # nothing about this request — allowed or refused — reaches /audit.
    if acting_role != "admin":
        print(f"  [BROKEN] {user.name} refused: claimed role {acting_role!r}",
              file=sys.stderr, flush=True)
        return jsonify(error=f"role {acting_role!r} may not delete reports",
                       note="This 403 is real. The check is not."), 403

    before = len(REPORTS)
    REPORTS = [r for r in REPORTS if r["id"] != rid]
    print(f"  [BROKEN] {user.name} (real roles: {sorted(user.roles) or 'none'}) "
          f"deleted report {rid} by CLAIMING role {acting_role!r}",
          file=sys.stderr, flush=True)
    return jsonify(deleted=rid, removed=before - len(REPORTS),
                   subject=user.name, real_roles=sorted(user.roles),
                   claimed_role=acting_role,
                   note="The check read its input from the request. "
                        "Authorisation may only read server-held state.")


@app.post("/broken/reports/<int:rid>/edit")
@requires("report:write")
def broken_edit(rid: int):
    r"""BROKEN #3 — the right check, at the wrong granularity. DO NOT COPY THIS.

    The subtlest of the three, and the one that survives code review, because
    the decorator above is not a mistake. It is correct, necessary, and does
    exactly what it says: it proves this subject may edit reports.

    It cannot prove this subject may edit THIS report. Permissions name verbs,
    not objects — "report:write" contains no report — so the id in the URL goes
    completely unexamined. Every editor can edit everybody's reports:

        curl -u bob:bob123 -X POST -H 'Content-Type: application/json' \
             -d '{"title":"bob was here"}' \
             http://127.0.0.1:8000/broken/reports/2/edit

    Report 2 belongs to alice. bob is an editor, he passes @requires, and he
    rewrites her report. Now the correct twin, same decorator, four extra
    lines:

        curl -u bob:bob123 -X POST -H 'Content-Type: application/json' \
             -d '{"title":"bob was here"}' \
             http://127.0.0.1:8000/api/reports/2/edit
        → 403, "report 2 belongs to alice"

    This is IDOR — Insecure Direct Object Reference, or broken object-level
    authorisation — and it is number one in the OWASP API Security Top 10.
    Finding it is exactly the enumeration described in the privilege-escalation
    section of ../README.md: log in as the lowest-privileged account that can
    reach an endpoint at all, then walk the id in the URL and see what comes
    back. Sequential integer ids make that trivial; UUIDs make it slower and
    not one bit safer, because obscurity is not the control.

    Note what makes this one genuinely dangerous: it DOES appear in /audit, as
    an ALLOW. The check ran and honestly succeeded. Nothing looks wrong in the
    log, because from the reference monitor's point of view nothing was.
    """
    report = next((r for r in REPORTS if r["id"] == rid), None)
    if report is None:
        return jsonify(error="no such report"), 404

    # ── THE BUG IS THE ABSENCE OF THESE TWO LINES ────────────────────────────
    # if not may_modify(current_user(), report):
    #     return jsonify(error="not yours"), 403

    data = request.get_json(silent=True) or {}
    was = report["title"]
    report["title"] = data.get("title", report["title"])
    report["body"] = data.get("body", report["body"])
    print(f"  [BROKEN] {current_user().name} edited report {rid} owned by "
          f"{report['author']!r} — RBAC passed, ownership never checked",
          file=sys.stderr, flush=True)
    return jsonify(edited=rid, owner=report["author"], editor=current_user().name,
                   title_was=was, title_now=report["title"],
                   note="@requires proved the verb. Nothing proved the noun.")


# ═════════════════════════════════════════════════════════════════════════════
# 7. STARTUP
# ═════════════════════════════════════════════════════════════════════════════

def print_policy() -> None:
    """Print the whole policy to the console: permissions, roles (with what
    each one expands to), and the seed accounts.

    Shown at startup and available on its own via --policy. Being able to dump
    the effective policy without running the application is a genuinely useful
    property — it is the difference between "we think admin can do X" and
    knowing.
    """
    width = max(len(p) for p in PERMISSIONS) + 2
    print("\n  Permissions")
    for p, d in PERMISSIONS.items():
        print(f"    {p:<{width}} {d}")
    print("\n  Roles")
    for r, spec in ROLES.items():
        inh = f"  (inherits {', '.join(spec['inherits'])})" if spec["inherits"] else ""
        print(f"    {r:<10}{inh}")
        print(f"      grants   : {', '.join(spec['grants'])}")
        print(f"      effective: {', '.join(sorted(expand_role(r)))}")
    print("\n  Accounts")
    for n, (pw, roles) in SEED_USERS.items():
        print(f"    {n:<9} / {pw:<12} {', '.join(roles) or '(no roles — authenticated, unauthorised)'}")


def main() -> None:
    """Parse the command line and start the server."""
    global QUIET
    ap = argparse.ArgumentParser(description="A transparent RBAC web server.")
    ap.add_argument("--port", type=int, default=8000, help="default 8000")
    ap.add_argument("--host", default="127.0.0.1", help="default 127.0.0.1 (localhost only)")
    ap.add_argument("--policy", action="store_true", help="print the policy and exit")
    ap.add_argument("--quiet", action="store_true", help="do not print decision traces")
    ap.add_argument("--safe", action="store_true",
                    help="fix the section 6B bugs (escape output, block open "
                         "redirects) so you can compare the same payload")
    args = ap.parse_args()

    if args.policy:
        print_policy()
        return

    QUIET = args.quiet
    globals()["SAFE_OUTPUT"] = args.safe
    print(textwrap.dedent("""
        ┌──────────────────────────────────────────────────────────────────┐
        │  Week 7 — RBAC demo                                              │
        │                                                                  │
        │  subject ──assigned──▶ role ──grants──▶ permission ──▶ action    │
        │                                                                  │
        │  Routes are guarded by PERMISSION, never by username. Every      │
        │  decision is traced below and queryable at /audit.               │
        └──────────────────────────────────────────────────────────────────┘"""))
    if SAFE_OUTPUT:
        print("  Output encoding ON (--safe): the section 6B bugs are fixed.")
    else:
        print(textwrap.dedent("""
          ################################################################
          #  DELIBERATELY VULNERABLE — 7 planted bugs (see section 6).   #
          #  6A: three broken authorisation checks, under /broken/.      #
          #  6B: three XSS and an open redirect, live right now.         #
          #                                                              #
          #  A teaching target. localhost only. Never expose it, never   #
          #  copy these patterns. Re-run with --safe to fix 6B and try   #
          #  the same payloads against it.                               #
          ################################################################"""))
    print_policy()
    print(f"\n  Serving on http://{args.host}:{args.port}   (Ctrl-C to stop)")
    print("  Decision traces follow.\n")
    # 127.0.0.1 by default: reachable from this machine only. debug=False
    # because Flask's debugger exposes an interactive Python console to anyone
    # who can trigger an exception — a remote shell, handed out for free.
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
