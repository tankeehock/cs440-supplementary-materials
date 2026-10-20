# SQL injection lab

> ### ⚠ Deliberately vulnerable
> This server builds SQL by pasting your input into query strings — three live
> injection bugs by default. It is a teaching target in the spirit of DVWA or
> WebGoat. Run it on localhost, never expose it, and never copy these patterns
> into real code. `--safe` switches every query to a parameterised version so
> you can fire the same payloads at both.

One tiny Flask site over an in-memory SQLite database, three pages, the three
classic shapes of SQL injection:

| page | technique | what the input lands in | what it gets the attacker |
| --- | --- | --- | --- |
| `/login` | **auth bypass** | the `WHERE` of a login query | a session with no password |
| `/search` | **UNION-based** | the `WHERE` of a search query | rows from other tables, in-band |
| `/track` | **blind boolean** | a yes/no lookup | any value, inferred bit by bit |

All three are the same mistake in different clothes: **untrusted input is pasted
into a SQL statement as code instead of being passed as data.** The database
cannot tell the query the developer wrote from the fragment the attacker
supplied, so it parses and runs both.

Each page prints the exact statement it ran, so you can *see* your payload
change the query.

---

## Run it

```bash
uv run week-12/sqli-lab/app.py            # vulnerable, http://127.0.0.1:8000
uv run week-12/sqli-lab/app.py --safe     # the three bugs fixed
uv run week-12/sqli-lab/app.py --port 9000
```

Flask is declared in a [PEP 723](https://peps.python.org/pep-0723/) header
inside `app.py`, so uv builds a throwaway environment on first run — no
`uv sync`, no `pip install`. SQLite ships with Python, so there is no database
to install. The data lives in memory and is reseeded every start. It binds to
`127.0.0.1` only.

The seeded users (you are *not* told the admin password — you steal it):

| username | password | role |
| --- | --- | --- |
| alice | alicepassword | user |
| bob | hunter2 | user |
| admin | *(the prize)* | admin |

---

## 1. Auth bypass — `/login`

The login runs, roughly:

```sql
SELECT username, role FROM users WHERE username = '<you>' AND password = '<you>'
```

and logs you in if any row comes back. Because your input is pasted straight in,
you can end the string early and comment the rest away.

**Try it.** Username `admin' --`, password blank:

```
admin' --
```

The statement becomes `… WHERE username = 'admin' --' AND password = ''`. In SQL
`--` starts a comment, so the password check is gone and SQLite just finds the
user named `admin`. You are logged in as admin without a password. `' OR '1'='1'
--` works too: it makes the `WHERE` always true and returns the first user.

---

## 2. UNION-based — `/search`

Product search runs `SELECT name, description FROM products WHERE name LIKE
'%<you>%'` and prints the results. A `UNION SELECT` with the **same number of
columns** appends rows from any table you name.

**Try it.** Search for:

```
' UNION SELECT username, password FROM users --
```

The two selected columns line up with the two the search returns, so every
user's name and password come back rendered as if they were products — the admin
password included. Two things make UNION work: **matching the column count**
(here, 2) and **a place the output is shown**. If you guess the count wrong, the
page prints SQLite's error (`SELECTs … do not have the same number of result
columns`) — which *tells you the right number*. Leaking raw DB errors like that
is its own weakness, **error-based injection**.

---

## 3. Blind boolean — `/track`

Order tracking tells you only **"Order found"** or **"No such order"** — no data
is ever printed. That single bit is still enough. The lookup is injectable in a
numeric context (`… WHERE id = <you>`), so ride a yes/no question in on it:

```
1001 AND (SELECT substr(password,1,1) FROM users WHERE username='admin')='S'
```

"Found" means *yes, the admin password's first character is `S`*; "not found"
means no. Change the position and the letter and you read the password out one
character at a time, without it ever appearing on the page.

**Automate it.** This script extracts the whole admin password through the
found/not-found oracle alone (run it against the **vulnerable** server):

```bash
python3 - <<'PY'
import string, urllib.parse, urllib.request
BASE = "http://127.0.0.1:8000/track?order="
ALPHABET = string.ascii_letters + string.digits + string.punctuation
def found(cond):
    url = BASE + urllib.parse.quote(f"1001 AND {cond}")
    return b"Order found" in urllib.request.urlopen(url).read()
pw = ""
for i in range(1, 40):
    if not found(f"(SELECT length(password) FROM users WHERE username='admin')>={i}"):
        break
    for c in ALPHABET:
        # substr is 1-indexed; compare one character at a time
        if found(f"substr((SELECT password FROM users WHERE username='admin'),{i},1)=char({ord(c)})"):
            pw += c
            break
print("admin password:", pw)
PY
```

It asks the server a few hundred true/false questions and reconstructs
`S3cr3t_Admin_Pw!`. Blind injection is slower than UNION, but it needs no
visible output at all — only a response that differs between true and false.

---

## Then fix them, and try again

Restart with `--safe` and fire the exact same three payloads. Each one now fails
— the login is denied, the UNION returns zero products, the `track` oracle stops
flipping. One idea changes every query:

- **Parameterised queries.** Instead of building the SQL string, the safe code
  writes placeholders and hands the values to the driver separately:

  ```python
  # vulnerable: input becomes part of the statement
  cur.execute(f"... WHERE username = '{username}'")
  # safe: input is bound as a VALUE, never parsed as SQL
  cur.execute("... WHERE username = ?", (username,))
  ```

  With a placeholder, `admin' --` is looked up as a *username that literally
  contains a quote and two dashes* — no such user, login denied. The `UNION`
  becomes a product name to match; the boolean condition becomes part of an id
  string that matches no integer. The input can no longer be *syntax*, only
  *data*. The safe pages print the statement **and** its bound parameters so you
  can see the separation.

The lesson in one sentence: **keep data out of code — pass untrusted values as
bound parameters, never concatenate them into the query.**

---

## Remediation

In priority order — the first item is the fix, the rest are depth.

1. **Use parameterised queries / prepared statements for every value, without
   exception.** Placeholders (`?`, `%s`, `:name`) with the values passed
   separately to `execute()` is the remediation for all three bugs here. There is
   no input this does not cover — if a value reaches the query, it is bound.
2. **Prefer an ORM or query builder that parameterises by default** (SQLAlchemy,
   Django ORM, …). When you must drop to raw SQL, *still* bind parameters —
   `text("... WHERE id = :id")` with a params dict, never an f-string into
   `text()`.
3. **Allow-list dynamic identifiers.** Table names, column names, and
   `ORDER BY` / sort direction cannot be parameterised, so map user input through
   a fixed server-side dictionary of permitted values and reject anything else —
   never interpolate the raw string.
4. **Run the app on a least-privilege database account** — only the tables and
   operations it needs, no DDL. If `/search`'s account cannot read `users`, a
   UNION into it fails regardless of the injection.
5. **Validate input by type/format** (an id must parse as an integer, etc.) as a
   secondary narrowing — useful, but not a substitute for binding.
6. **Return generic errors to users and log the detail server-side.** The verbose
   SQLite error here handed over the column count; hiding it turns easy
   error-based injection back into slow blind work.

A WAF can detect and slow common payloads, but treat it as monitoring, not a
fix — the remediation is parameterisation in the code.

---

## Finding it in a code review (interview checklist)

Same method as hunting XSS, different sink: trace **untrusted input into a SQL
statement** and ask whether it arrives as a bound *parameter* or as part of the
query *string*. If the value is in the string, it's a finding.

**Sources:** `request.args` / `form` / `json`, headers, cookies, path segments —
and values read back from the database (**second-order** injection: stored now,
concatenated into a query later).

**Sinks — any SQL built from a string:**

| Kind | What to look for |
| --- | --- |
| string-built SQL | `execute(f"... {x} ...")`, `execute("..." % x)`, `execute("..." + x)`, `.format()`, JS template literals `` db.query(`... ${x}`) `` |
| ORM escape hatches | SQLAlchemy `text(f"...")` / `session.execute(text(...))`, Django `.raw()` / `.extra()` / `RawSQL`, Sequelize `sequelize.query`, Knex `.whereRaw` / `.raw` |
| dynamic **identifiers** | `ORDER BY {col}`, table/column names, `LIMIT`/`OFFSET`, `ASC`/`DESC` from input — these **cannot** be parameterised, so even otherwise-safe code is injectable here unless the value is checked against an allow-list |

**Safe shape vs unsafe shape** — the thing to pattern-match by eye:

```python
execute("... WHERE id = ?",  (id,))   # safe: ? is a VALUE slot
execute(f"... WHERE id = {id}")       # injectable: f-string
execute("... WHERE id = %s", (id,))   # safe: %s is a PLACEHOLDER (DB-API)...
execute("... WHERE id = %s" % id)     # injectable: ...but % id is formatting
```

The last two lines are the classic interview trap: the same `%s`, opposite
safety, decided entirely by whether the params go in `execute()`'s second
argument or get formatted into the string first. (The placeholder *style* is
driver-specific — this lab's `sqlite3` uses `?`, while psycopg2/MySQL use `%s` —
but the data-vs-string distinction is identical in every one.)

**Grep first:** `execute(` near `f"`, `%`, `.format`, or `+`; plus `text(`,
`.raw(`, `.extra(`, `RawSQL`, `whereRaw`, and `ORDER BY`.

**Then ask:** is *every* user value bound as a parameter? Is any SQL assembled by
concatenation? Are there dynamic identifiers / `ORDER BY` from input (and are they
allow-listed)? Is a field that "must be an integer" actually validated as one —
or just dropped in because it's "only a number"? (This lab's `/track` is
injectable precisely because the id is numeric and unquoted: no quote needed to
break out.)

**Don't trust the output channel to clear it.** A query that shows no rows can
still be a blind oracle (found/not-found, or timing), and a query whose errors
reach the user hands over column counts and table names for free.

In this lab the three findings share one root cause — a value concatenated where
a parameter belonged: the login `WHERE` built with an f-string (auth bypass), the
`LIKE` pattern built with an f-string (UNION), and the numeric `WHERE id =
{order}` (blind).

---

## Where SQL injection stops

Parameterised queries are the fix. These help in depth, but none replaces it:

- **Least privilege.** The app's database account should be able to do only what
  the app needs. If `/search` can't reach the `users` table at all, a UNION into
  it fails regardless. (Here everything is one SQLite file, so this doesn't
  apply — but it is the first thing to get right on a real server.)
- **Stored procedures / ORMs — only if they parameterise.** An ORM like
  SQLAlchemy or Django's ORM binds parameters for you, which is why it helps. An
  ORM method that still takes a raw string you built is just as injectable.
- **Allow-list input validation.** If an id must be an integer, reject anything
  that isn't one before it reaches the query. Useful, but secondary: validation
  narrows input, parameterisation makes injection impossible.
- **Don't leak database errors.** The verbose SQLite error on `/search` handed
  you the column count. Real apps should log the detail and show the user
  nothing — which turns easy error-based injection back into slow blind work.

> **On stacked queries:** payloads like `1; DROP TABLE users --` are famous, but
> Python's `sqlite3` `execute()` runs only one statement, so they fail here. Many
> drivers and ORMs block stacking the same way — which is why real-world SQLi
> usually reads data (as above) rather than running a second command. It is a
> driver setting, not a defence to rely on; parameterise anyway.
