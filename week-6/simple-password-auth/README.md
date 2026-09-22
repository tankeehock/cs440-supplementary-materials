# Password Storage & Login — build the thing that survives the leak

CS440 AY26T1 · Kee Hock · uv + Python, one file

You will register a user and log them in, with every intermediate value printed
to your terminal: the salt as it comes out of the OS random generator, the
Argon2id hash as it is derived, the exact record that gets stored, and — on the
next login — the parameters reloaded to reproduce that computation. Then you
will steal the store and see what an attacker actually gets.

Everything happens in one script, `password-systems.py`, on your own machine.
No database, no web server, no internet. The "store" is a Python dictionary
that dies when the process does.

This is the **defensive half** of week 6. Its companion,
[`../cracking/`](../cracking/README.md), is the attacker's half — run that one
first if you have not, because this lab is the answer to the question it asks.

### How to work through this

About **45 minutes** for sections 0-6, plus 30 for the extensions. Run `--demo`
once straight through, then go back and read each section of this sheet against
the corresponding block of the transcript. Finish in the interactive console
(`menu 1` → `menu 3`) so that the record you are looking at is one you made.

Where this sits in the course: week 4 (`hashes.py`) established what a hash is
and why it is one-way; the [companion lab](../cracking/README.md) established
what an attacker does with one; this lab builds the store that survives them;
and week 7 picks up one instant later, with what the system lets you *do* once
it believes who you are.

## Objective

**By the end you will be able to store a password the way the OWASP Password
Storage Cheat Sheet requires — a per-user CSPRNG salt, Argon2id with stated
parameters, a constant-time comparison — and explain what specific attack each
of those four decisions defeats.**

The lab reaches that objective by making the system **transparent**: nothing is
hidden behind a library call you take on faith. Every step prints what it did
and a `»` note saying *why*. Understanding is demonstrated by prediction — you
say what the next line will show, then read it.

### How each activity builds the objective

| Activity | Objective (what you do) | What it demonstrates (the learning value) |
|---|---|---|
| **1. Register** | Watch a password become a stored record | Storage is four decisions, not one: **discard plaintext, salt, slow-hash, store the parameters**. |
| **2. The salt collision test** | Register two users with the *same* password | Identical inputs, unrelated outputs. The salt is what breaks rainbow tables and hides shared passwords. |
| **3. Log in — accept and reject** | Verify a good password, then a wrong one | Verification is **re-derivation, not decryption**. One wrong character changes all 32 bytes. |
| **4. Read the store** | Print every record the system holds | You can hand this file to an attacker. There is no password in it. |
| **5. The leak** | Attack the store you just built | The only attack left is `guess → hash → compare` — and the weak password still falls. Hashing is not a password policy. |
| **6. Fast vs slow** | Time SHA-256 against Argon2id | ~60,000× on one CPU thread — and millions of times on a GPU. Speed is a **liability** here. |
| **7. After `GRANT`** | Name what the lab does *not* cover | Authentication is not authorisation, and the session becomes the credential — the handoff into week 7. |
| **8. Extensions** (optional) | Seven edits to the script | Turns the "Where this stops" list into working code, starting with the one real bug in the teaching version. |

### The seven ideas the activities make concrete

1. **Assume the store leaks.** Every design decision below is justified only
   under that assumption. If you trust your database never to leak, none of
   this is needed — and that is precisely the assumption every breached company
   was making. Design the store so that leaking it is *embarrassing*, not
   *fatal*.

2. **Never store the plaintext, and never store anything reversible.**
   Encryption is the wrong tool: encryption implies a key, the key lives on the
   same server, and an attacker who took the database usually took the key too.
   A password store must be **one-way**. The plaintext lives in RAM long enough
   to be hashed, and is then discarded (`step 1` of `register()`).

3. **A salt is per-user, random, and not secret.** It is stored in plain sight
   next to the hash. Its only job is to make every user's hash computation
   *different*, which (a) kills precomputed rainbow tables — a table built for
   one salt is worthless against the next user — and (b) hides the fact that two
   users chose the same password, which would otherwise be visible in the dump.
   It comes from `secrets.token_bytes()` (an OS CSPRNG), never from `random`,
   which is a deterministic Mersenne Twister and is predictable from its output.

4. **Use a slow, memory-hard KDF — Argon2id.** The parameters here are OWASP's
   baseline: `m = 19 MiB`, `t = 2`, `p = 1`. "Slow" is the feature. The defender
   pays the cost once per login; the attacker pays it once per *guess*, times
   the entire search space. Memory-hardness specifically targets GPUs, which
   have thousands of cores but little memory per core.

5. **Store the algorithm and its parameters beside the hash.** Not for
   decoration — verification must reproduce the *exact same computation* years
   later, and the cost must be raisable over time as hardware improves while
   old records still verify. (In production you would store the standard
   [PHC string](https://github.com/P-H-C/phc-winner-argon2) —
   `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>` — which is this same record
   serialised into one column.)

6. **Compare in constant time.** `secrets.compare_digest()`, never `==`. A
   normal comparison returns as soon as two bytes differ, so *how long it took
   to say no* leaks how many leading bytes were right — enough, over many
   attempts, to reconstruct the target byte by byte.

7. **Correct storage is necessary, not sufficient.** Activity 5 cracks a
   correctly-stored `password123` in five guesses. Storage defends the *offline*
   attack after a leak; you still need a password policy, a breached-password
   screen, rate limiting, and MFA for everything else.

## Code map: which activity lives where in `password-systems.py`

Every landmark below is a **literal, searchable string** in the source. Run
e.g. `grep -n "def verify" password-systems.py` to jump to it.

| Lab activity | Command | Search this tag | What you'll find |
|---|---|---|---|
| *the OWASP parameters* | — | `OWASP Argon2id parameters` | `MEMORY_KIB`, `TIME_COST`, `PARALLELISM`, `SALT_LEN`, `HASH_LEN` — the whole policy, five lines |
| *the one cryptographic call* | — | `def slow_hash` | the only place Argon2id is invoked; both register and login go through it |
| **1. Register** | menu `1`, or `--demo` | `REGISTRATION` banner → `def register` | steps 1-4, each printing its value and its `»` reason |
| **3. Log in** | menu `2`, or `--demo` | `VERIFICATION` banner → `def verify` | steps 1-4: load, re-derive, constant-time compare |
| **4. Read the store** | menu `3` | `def do_view` | prints `USERS` — the entire database |
| **5. The leak** | `--demo` | `def attackers_view` | a 6-word wordlist run against the stored hash |
| **6. Fast vs slow** | `--demo` | `def fast_vs_slow` | measures SHA-256/sec and Argon2id/sec on *your* machine |

The one thing to notice while reading: **`register()` and `verify()` call the
same `slow_hash()` with the same parameters.** Registration invents a salt;
login reloads one. That is the only difference between them. If you understand
why that single asymmetry is enough to build authentication, you have the lab.

### The two paths, side by side

Keep this picture next to the transcript. The left column runs once, at
sign-up; the right column runs on every login attempt. They are the *same
computation*, and the only thing that differs is where the salt and parameters
come from:

```
        REGISTER  (once, at sign-up)          LOGIN  (every attempt)
        ────────────────────────────          ──────────────────────
        password                              password'   (what was typed now)
            │                                     │
        salt   ← CSPRNG, 16 fresh bytes       salt   ← read back from the record
        m,t,p  ← current policy               m,t,p  ← read back from the record
            │                                     │
            ▼                                     ▼
        Argon2id(password, salt, m,t,p)       Argon2id(password', salt, m,t,p)
            │                                     │
            ▼                                     ▼
            h                                     h'
            │                                     │
            ▼                                     ▼
        store { alg, m, t, p, salt, h }       secrets.compare_digest(h', h)
        discard the plaintext                     │
                                                  ▼
                                            GRANT  /  REJECT
```

Three questions this picture answers before you run anything:

- **Why is the salt stored?** Because the right column cannot recompute `h'`
  without it. A salt the server could not read back would make login impossible.
  That is the structural reason a salt cannot be secret.
- **Why are `m`, `t`, `p` stored?** Same reason — and it is what lets you raise
  the cost next year without invalidating every existing account.
- **Where is the decryption step?** There isn't one. The arrow only ever points
  down. The server compares two *outputs*; it never recovers an input.

> **One honest caveat, which becomes answer-key question 3.** The diagram shows
> what a correct implementation does. This script reads the salt back from the
> record but takes `m`, `t`, `p` from module globals — so raising `MEMORY_KIB`
> would break existing records here. Fixing that is extension 8.1.

## 0. Setup

The only requirement is [uv](https://docs.astral.sh/uv/).
`password-systems.py` declares `argon2-cffi` in a
[PEP 723](https://peps.python.org/pep-0723/) header, so `uv run` fetches an
interpreter and builds a throwaway environment on the first run.

```bash
cd week-6/simple-password-auth
uv run password-systems.py            # interactive console (register / login / view)
uv run password-systems.py --demo     # scripted narrated walkthrough + the attack
uv run password-systems.py --brief    # same walkthrough, the "»" explanations off
```

Unfamiliar with a term — *KDF*, *pepper*, *CSPRNG*, *PHC string*? There is a
[glossary](#glossary) at the end of this sheet.

Start with `--demo` to see the whole story, then use the interactive console to
try your own passwords. Nothing is written to disk and the store is discarded
when you quit — **you can safely type a real password into it**, though there
is no reason to.

> Use `--brief` on a second pass, or on a projector. It prints the same values
> with the reasoning removed, which turns the transcript into a quiz.

---

## 1. Register — what actually happens at sign-up

- **Objective:** see a password turn into a record, in four named steps.
- **Concept tested:** discard the plaintext; salt; slow-hash; store the parameters.
- **Code:** `def register`.

```bash
uv run password-systems.py --demo
```

The first block registers `alice`. Read it step by step:

```
  [2] Generate a unique random salt
        salt       : a4102f40309a7a5197589ce704595eec  (16 bytes)
        source     : secrets.token_bytes() → OS CSPRNG (not the predictable random module)

  [3] Slow-hash the password
        function   : Argon2id(pwd, salt)  m=19456KiB t=2 p=1
        hash (h)   : 7106cf31886e4072dfb2e497187beea0a4b19aef5c089833ea1b9c7ebeee8a6c  (32 bytes)
        time       : 35 ms for this one hash (the slowness is deliberate)

  [4] Store algorithm + parameters + salt + hash

        This is the record now saved for 'alice':
        ----------------------------------------------------------
        algorithm       : argon2id
        memory (m)      : 19456 KiB (19 MiB)
        iterations (t)  : 2
        parallelism (p) : 1
        salt            : a4102f40309a7a5197589ce704595eec
        hash (h)        : 7106cf31886e4072dfb2e497187beea0a4b19aef5c089833ea1b9c7ebeee8a6c
        ----------------------------------------------------------
        the plaintext password is NOT stored — only salt, parameters, and hash
```

**Your values will not match the ones above, and that is the point.** The salt
comes from the OS random generator, so every run of this script produces a
different salt and therefore a different hash — for the same password, on the
same machine, a second later. Hold that thought until activity 2, and contrast
it with the companion lab, where the stored hash for `safe` is byte-identical on
every machine in the room.

Four observations to make out loud:

- **The salt is in the record, in the clear.** Students almost always expect it
  to be secret. It is not, and it does not need to be: its job is *uniqueness*,
  not *confidentiality*. A secret value added to the hash is a different thing
  — a **pepper** — and it belongs in a config file or HSM, not in the database.
  This lab does not implement one; see "Where this stops", below.
- **35 ms for one hash** is about 60,000 times slower than a SHA-256 call on the same
  machine (activity 6 measures it on yours). That is
  not a bug in the library, it is the product being bought.
- **The parameters travel with the hash.** Next year, when `m = 19 MiB` is too
  cheap, you raise the constant for new registrations and re-hash each user on
  their next successful login. Alice's old record still verifies in the
  meantime, because it carries its own `m`, `t` and `p`.
- **The plaintext is zeroed** (`pwd[i] = 0`) and deleted. In CPython this is
  mostly symbolic — the original `str` is immutable and may persist in memory
  until garbage collection — but it signals the intent, and in a language with
  real control over memory it is mandatory.

---

## 2. The salt collision test

- **Objective:** prove to yourself what the salt buys.
- **Concept tested:** rainbow tables, and shared-password disclosure.
- **Code:** the `register("alice", …)` / `register("bob", …)` pair in `demo()`.

The demo registers `bob` with **exactly the same password as alice** —
`correct horse battery staple` — and then prints both hashes side by side:

```
  Note: alice and bob chose the same password, but their stored
  hashes differ because each got a unique salt:
    alice: 7106cf31886e4072dfb2e497…
    bob  : 295b8dff415573a7d48a379a…
```

Same function, same password, unrelated output. Two consequences:

1. **A precomputed table is worthless.** A rainbow table maps `hash → password`
   for an *unsalted* function. With 16 random bytes of salt there are `2^128`
   variants of every entry, so the attacker would have to build a fresh table
   per user — which is the same work as just attacking that user directly. The
   salt does not make guessing harder; it makes **precomputation and
   amortisation across users impossible**.
2. **The dump tells the attacker nothing about who shares a password.** Without
   salting, a leaked table shows the 40,000 accounts that all used the same
   top-1000 password, and cracking it once opens all of them. That grouping is
   often the most valuable thing in a breach.

Contrast this directly with the companion lab: run
`uv run ../cracking/password-cracking.py` and look at Part 2's stored hash for
`safe`. It is the *same 64 hex characters on every machine in the room*, because
it is unsalted SHA-256. That is what you have just fixed.

---

## 3. Log in — accept, then reject

- **Objective:** understand verification as re-derivation.
- **Concept tested:** one-wayness, determinism, constant-time comparison.
- **Code:** `def verify`.

The demo logs alice in correctly, then tries `hunter2`. Both runs print all
four steps; the only line that differs is the computed hash:

```
  [3] Re-hash the submitted password with those parameters
        computed h': 7106cf31886e4072dfb2e497187beea0a4b19aef5c089833ea1b9c7ebeee8a6c
        stored h   : 7106cf31886e4072dfb2e497187beea0a4b19aef5c089833ea1b9c7ebeee8a6c
  [4] Compare the two hashes in constant time
        compare    : secrets.compare_digest(h', h) → True

  RESULT: GRANT  (passwords match)
```

```
  [3] Re-hash the submitted password with those parameters
        computed h': 911efd05227d2bcb5de2e594adfa13c89f3bb290765dfc4477d07e1514d3f353
        stored h   : 7106cf31886e4072dfb2e497187beea0a4b19aef5c089833ea1b9c7ebeee8a6c

  RESULT: REJECT  (no match)
```

**The server never learns the password and never recovers it.** It takes the
submitted string, reloads the *stored* salt and parameters, re-runs the
identical computation, and asks whether it landed on the same 32 bytes. That is
the whole of authentication. If a website can email you your existing password,
it is not doing this — it is storing something reversible, and you should
assume the worst about the rest of the system too.

Note the avalanche: `hunter2` and the real passphrase share *no* structure in
their outputs. There is no "close". A hash comparison is not a distance
measure, which is exactly why timing leakage matters so much — the timing is
the only signal an attacker could otherwise get, and step 4 removes it.

### The step that is deliberately wrong, for clarity

Log in as a user who does not exist and read the `»` note:

```
  » No such user. A real system would still run a dummy hash and return
    a generic 'invalid credentials', so it does not reveal which
    usernames exist. We stop early here only for clarity.
```

The lab returns immediately for an unknown user. A production system must not:
returning in 0.1 ms for "no such user" and 35 ms for "wrong password" is a
**username enumeration oracle**, and an attacker will use it to build a valid
account list before guessing a single password. The fix is to hash against a
dummy record anyway, and return the same message either way. Constant-time
thinking applies to the *control flow*, not just to `compare_digest`.

---

## 4. Read the store

- **Objective:** look at the database the way the attacker will.
- **Code:** `def do_view` (menu option `3`).

```bash
uv run password-systems.py
#  1) Register a new user      → make yourself an account
#  3) View the stored records  → look at what was kept
```

```
  The store holds 1 record(s). None contains a plaintext password:

        'carol'
        ----------------------------------------------------------
        algorithm       : argon2id
        memory (m)      : 19456 KiB (19 MiB)
        iterations (t)  : 2
        parallelism (p) : 1
        salt            : 905a9e0a3ec8c2f11985a6406e064cec
        hash (h)        : 06f8897df25eb20a8a72c85ec470c6da0646513b437a0805c7a79fba2b72f25a
        ----------------------------------------------------------
        plaintext password: not stored
```

**This is the whole breach.** Publish it on a forum and nobody's password is
revealed. Every field except the hash is a public parameter; the hash is the
output of a one-way function. The attacker's position is now identical to yours
before you typed the password — except that they can check a guess offline,
which is what activity 5 does.

The console also demonstrates two small, real habits:

- **The password is read with `getpass`**, so it is never echoed to the terminal
  and never lands in your shell history or a screen recording.
- **Weak passwords raise a warning** (`len(pw) < 8`, plus a tiny deny-list).
  The demo continues anyway and says so; a real system would reject, and would
  check against a breach corpus rather than four hard-coded strings.

---

## 5. The leak — attack the store you just built

- **Objective:** find the limit of what correct storage can do.
- **Code:** `def attackers_view`.

The demo registers `weakuser` with `password123` — stored correctly, with its
own salt and the same Argon2id parameters as everyone else — and then attacks
it:

```
   wordlist: ['123456', 'qwerty', 'letmein', 'football', 'password123', 'dragon']
   tried 5 guesses in 132 ms → cracked: 'password123'
```

**Correct storage did not save this password.** It cost the attacker 132
milliseconds instead of 132 nanoseconds, and that is the entire benefit.

Look closely at what the attack *had* to do, though. It could not reverse the
hash, could not use a rainbow table, and could not reuse any work against
alice's or bob's records — it had to take one candidate, hash it with
`weakuser`'s specific salt, and compare. Everything you built held. The
password was simply in a list of six.

Now scale it, using the companion lab's arithmetic:

| Password | Effective space | At ~40 guesses/sec (Argon2id) |
|---|---|---|
| `password123` | ~5 (position in any wordlist) | **0.1 seconds** |
| random 8 chars, `a-zA-Z0-9` | `62^8 ≈ 2.2e14` | ~170,000 years |
| 4 random dice words | `7776^4 ≈ 3.7e15` | ~3 million years |

The two levers are independent, and both are required. This lab is lever two.
Lever one — length and true randomness — is a *policy* decision the store cannot
make for you.

---

## 6. Fast vs slow — why a general-purpose hash is the wrong tool

- **Objective:** quantify the gap on your own hardware.
- **Code:** `def fast_vs_slow`.

```
   SHA-256  : ~2.2 million hashes/sec (one CPU thread)
   Argon2id : ~36 hashes/sec
   → SHA-256 is ~60,147x faster to attack (and real GPUs do billions/sec)
```

> **What is stable here and what is not.** The two absolute rates depend
> entirely on your hardware — expect anywhere from 1 to 5 million SHA-256/sec
> and 30 to 70 Argon2id/sec. The **ratio** is the invariant, because both sides
> scale with the same machine: it lands near 60,000× on almost anything. Quote
> the ratio, not the rates.

Sixty thousand times, on **one thread of your laptop**. A single modern GPU runs
SHA-256 at tens of billions per second, which puts the real-world gap nearer
`10^9`. Every one of those factors is a factor by which a leaked SHA-256
database is cheaper to crack than a leaked Argon2id one.

The line worth writing on the board: **being fast is a feature for checksums
and a liability for passwords.** SHA-256 and MD5 are *designed* to be fast,
because file integrity and Merkle trees need them to be. That design goal is in
direct opposition to what a password store needs. This is why OWASP rules out
fast hashes and reversible encryption for password storage, and why
"we hash the passwords with SHA-256" is a statement of a vulnerability, not of a
control.

Acceptable alternatives if Argon2id is unavailable, in OWASP's order of
preference: **Argon2id** → **scrypt** → **bcrypt** → **PBKDF2** (with a high
iteration count, only where FIPS compliance forces it).

---

## 7. What happens one instant after `GRANT`

The lab ends at `RESULT: GRANT`. A real system's interesting problems start
there, and it is worth naming them so you know what this lab is *not*.

**Authentication is not authorisation.** Verifying the password answers "who are
you?" It says nothing about "what may you do?" — which is week 7's subject, and
a completely separate mechanism.

**The password is checked once; the session is checked on every request.** After
`GRANT` the server issues a session cookie or token, and from then on *that* is
the credential. Which means the session identifier is now as valuable as the
password was — it must come from a CSPRNG (same `secrets` module, same reasoning
as the salt), be long enough not to be guessable, be transmitted only over TLS
(week 5), and be invalidated on logout and on password change.

**Stealing the session skips everything you just built.** Argon2id, the salt,
the constant-time compare — none of it is consulted again after login. An
attacker with a stolen cookie never meets any of it. That is exactly the point
week 7's RBAC demo makes from the other side, where an XSS payload running in
the victim's browser inherits the victim's session and roles without touching a
single permission check.

So the honest summary of week 6 is: **this lab protects the password at rest, in
the specific event that the database is stolen.** It is necessary, it is the
part most systems get wrong, and it is one control among several.

---

## 8. Extensions (optional)

Each item is a small, self-contained edit to `password-systems.py`. Together
they turn the "Where this stops" list above from reading into building. Ordered
by effort.

**8.1 — Make the parameters actually come from the record.** *(The one real bug
in the teaching code.)* `slow_hash()` reads the module globals, so `verify()`
honours the stored salt but ignores the stored `m`, `t`, `p`. Give `slow_hash()`
those three as arguments; have `register()` pass the policy constants and
`verify()` pass `rec["memory_kib"]`, `rec["time_cost"]`, `rec["parallelism"]`.
Then prove it: register a user, raise `MEMORY_KIB` to `64*1024`, and log that
user back in. Before the fix they are locked out; after it they get in.

**8.2 — Add transparent re-hashing on login.** Building on 8.1: after a
successful `verify()`, if the record's parameters are below current policy,
re-hash the password (you have the plaintext right there, for the only moment
you ever will) and overwrite the record. This is how every real system raises
its cost over time without a mass reset — and it is about six lines.

**8.3 — Close the username-enumeration oracle.** Make the unknown-user path in
`verify()` hash against a fixed dummy record anyway, and return the same generic
message and the same timing as a wrong password. Then time both paths and show
they match. *Why it matters:* answer key 7 — before the fix, the response time
alone hands an attacker a valid account list.

**8.4 — Serialise to a PHC string.** Replace the dictionary record with a single
string, `$argon2id$v=19$m=19456,t=2,p=1$<b64 salt>$<b64 hash>`, plus a parser
that reads it back. This is what actually goes in the database column, and
writing the parser is the fastest way to see that the "record" and the "string"
carry identical information.

**8.5 — Add a pepper.** Mix a secret value — read from an environment variable,
not stored in `USERS` — into every hash. Then simulate the two breach shapes:
leak `USERS` alone (hashes are now uncrackable, because the attacker is missing
an input) and leak `USERS` plus the environment (you are back to where the lab
started). Discuss which of those two an SQL-injection breach actually looks like.

**8.6 — Screen against a breach corpus.** In `do_register()`, replace the
four-entry deny-list with a check against a real list. Offline: point it at a
downloaded wordlist. Online: implement the Have I Been Pwned **k-anonymity**
lookup — SHA-1 the candidate, send only the first *five* hex characters, and
search the returned suffixes locally. Explain to yourself why that protocol
never reveals the password, or even its full hash, to the API. This is the
highest-value control in the whole "Where this stops" list, and it is ~15 lines.

**8.7 — Measure your own parameter budget.** Time `slow_hash()` at several
settings (`m` = 19, 47, 64 MiB; `t` = 2, 3, 4) and plot ms per hash. Then pick
the setting you would ship, given a target of *N* logins per second on one
server. There is no correct answer — there is a defensible one, and being able
to defend it is the actual professional skill.

---

## Where this stops (and what a real system adds)

This lab is a correct **password store**. It is not a complete authentication
system. In rough order of importance, production adds:

- **A breached-password screen at registration.** Check the candidate against a
  corpus (e.g. the Have I Been Pwned k-anonymity range API, which never sends
  the password or its full hash). This is the single highest-value control,
  because it directly attacks the failure in activity 5.
- **Rate limiting, lockout and MFA** for the *online* path. Nothing in this lab
  defends a login form being hammered, because this lab's threat model starts
  after the database has already left the building.
- **A pepper** — a secret value, kept outside the database (config, KMS, HSM),
  mixed into every hash. If the database alone leaks, the hashes are
  uncrackable; it costs nothing and defends the most common breach shape.
- **Generic errors and uniform timing** on every failure path, per answer 7.
- **Re-hash on successful login** when the stored parameters are below current
  policy — the upgrade path from answer 3.
- **Persistence and transactions.** `USERS` is a dictionary in RAM. A real store
  is a table with a unique index on the username and the record serialised as a
  single PHC string column.
- **Length limits and Unicode normalisation.** Cap the input (Argon2id will
  happily hash a 10 MB "password" and hand you a denial of service), and
  normalise to NFC so that the same passphrase typed on two keyboards matches.

Each of those is a fine extension exercise, and each of them is *less*
important than the four decisions this lab already gets right.

---

## Glossary

| Term | Meaning |
|---|---|
| **Hash (one-way function)** | A function that is cheap to compute forwards and infeasible to invert. The stored value. Not encryption — there is no key and no way back. |
| **KDF** | Key derivation function: a hash *deliberately* made slow and expensive, for storing passwords. Argon2id, scrypt, bcrypt, PBKDF2 — in OWASP's order of preference. |
| **Argon2id** | The current recommended KDF; winner of the Password Hashing Competition. The `id` variant blends Argon2i and Argon2d to resist both side-channel and GPU attacks. |
| **`m`, `t`, `p`** | Argon2's cost parameters: memory in KiB, iterations (time), and parallel lanes. OWASP's baseline here is `m=19 MiB, t=2, p=1`. |
| **Memory-hard** | A KDF that needs a large working buffer per evaluation, so an attacker's GPU cannot run thousands of them in parallel. Attacks the attacker's *parallelism*, not just their clock speed. |
| **Salt** | A unique, random, **non-secret** value hashed with each password so no two users' computations are identical. Stored beside the hash. Kills rainbow tables and hides shared passwords. |
| **Pepper** | A **secret** value, stored *outside* the database, mixed into every hash. Defends the database-only breach. Different job from a salt; you can use both. |
| **CSPRNG** | Cryptographically secure pseudo-random number generator. Python's `secrets` module. Unlike `random` (a Mersenne Twister), its output cannot be predicted from previous output. |
| **Rainbow table** | A precomputed `hash → password` table, amortised across many targets. Salting makes it worthless. |
| **Constant-time comparison** | `secrets.compare_digest()` — equality that always examines the full length, so the *duration* of a failure leaks nothing about how much matched. |
| **Timing side channel** | Any leak carried by *how long* an operation took rather than what it returned. Applies to control flow (activity 3's unknown-user path) as much as to byte comparison. |
| **Username enumeration** | Learning which accounts exist, from differences in response text, status code, or timing. A prerequisite for targeted guessing. Extension 8.3. |
| **PHC string** | The standard single-column serialisation of a password record: `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`. |
| **Offline attack** | Guessing against a stolen hash, on the attacker's own hardware, with no rate limit. **The threat model of this entire lab.** |
| **Credential stuffing** | Replaying a username/password pair leaked elsewhere. No cracking involved; defeated by uniqueness and MFA, not by storage. See the companion lab, Part 3(c). |
| **Bits of entropy** | `log₂` of the number of equally likely passwords. The companion lab's section 1 explains the arithmetic and the trap. |

---

## Predict before you run

Answer from the concepts, then check against the transcript.

| # | Question | Your prediction | Where to check |
|---|---|---|---|
| 1 | Register the *same* user twice with the *same* password. Same stored hash? | | menu `1` twice, then `3` |
| 2 | Is the salt secret? What breaks if an attacker learns it? | | Activity 2 |
| 3 | You change `MEMORY_KIB` to `64 * 1024` and restart. Do existing records still verify? | | `verify()` step 2 — and think hard |
| 4 | Login takes ~35 ms. Is that a bug to optimise away? | | Activity 1, step 3 |
| 5 | Why `secrets.compare_digest` and not `==`? | | `verify()` step 4 |
| 6 | The store leaks. Which users' passwords are in it? | | Activity 4 |
| 7 | Could this lab's `verify()` be used to enumerate valid usernames? | | Activity 3, last section |
| 8 | The whole `USERS` store leaks, *and* the attacker has your source code. What extra does the source give them? | | Activity 4 |
| 9 | A user's password is stolen by a keylogger. Which control in this lab helps? | | Section 7 |
| 10 | Why can a pepper be secret when a salt cannot? | | The two-paths diagram |

---

## Answer key (instructor)

1. **No** — different salt each time, so a different hash, even for the same
   username and password. This is the cleanest one-command demonstration of
   activity 2 and works well as a cold open.
2. **Not secret.** If the attacker learns the salt they lose nothing they did
   not already have — they took it from the same dump as the hash. What it costs
   them is *precomputation*: rainbow tables and any work shared across users.
   Students who answer "secret" have confused salt with **pepper**; that is the
   right moment to introduce the distinction.
3. **Yes, they still verify** — because each record stores its *own* `m`, `t`
   and `p`, and `verify()` reloads them from the record rather than reading the
   module constants. *But* this script's `slow_hash()` uses the globals, not the
   reloaded values, so a raised constant would in fact break old records here.
   That is a genuine gap in the teaching code and a good exercise: make
   `verify()` pass `rec["memory_kib"]`, `rec["time_cost"]`, `rec["parallelism"]`
   into the hash, then add a transparent re-hash-on-login upgrade path. It is
   about fifteen lines and it is exactly what production code does.
4. **No — it is the product.** 35 ms is invisible to the user (they just typed a
   password) and catastrophic to an attacker (multiply it by the search space).
   The usual follow-up is "but it's a cost on my server at scale": correct, and
   that is why the parameters are tunable, and why you tune them to the slowest
   value your login throughput can absorb, not the fastest one that works.
5. **Timing.** `==` short-circuits on the first differing byte, so the response
   time encodes how many leading bytes matched; repeated over a network an
   attacker recovers the target value byte by byte. `compare_digest` always
   examines the full length. Fair caveat for the sharp student: against a
   *hash* of an attacker-unknown input the practical attack is weak, but the
   habit is free and the same code path is often reused for API tokens and MAC
   tags, where it is decisive.
6. **None of them, directly.** The dump contains algorithm, parameters, salt and
   hash — no plaintext and nothing reversible. The honest completion is
   "…but every *guessable* password in it will be recovered", which is activity
   5, and why breach disclosure still requires a password reset.
7. **Yes.** It returns in microseconds for an unknown user and ~35 ms for a
   known one with a wrong password, and it says `unknown user` in the output.
   Both are oracles. The fix — hash a dummy record anyway, return one generic
   message — is stated in the script's own `»` note and is worth having students
   implement.

8. **Nothing of value.** The algorithm, the parameters and the salt were
   already in the dump, and Argon2id's security does not depend on the
   attacker's ignorance of any of it. This is **Kerckhoffs's principle** applied
   to password storage: the system must be secure with everything public except
   the secret itself. Contrast it with a scheme that "encrypts" passwords, where
   the source code leading to the key is exactly what the attacker wanted.
   Useful follow-up: *which* of the seven ideas would a source-code leak break?
   Only the pepper (extension 8.5) — because it is the one value that is
   supposed to be secret, which is why it does not belong in the repository.
9. **None of them.** The password was captured on the way *in*, in plaintext,
   before the server ever saw it — every control in this lab operates on data at
   rest after that point. What helps is MFA (the password alone stops being
   sufficient) and prompt session invalidation once the compromise is known.
   The pedagogical job of this question is to stop students treating "we hash
   properly" as a total answer; it defends one specific event, very well.
10. **Because of the arrow in the diagram.** The server must reproduce the hash
    at login, so every input it cannot ask the user for has to be stored
    somewhere the server can read — which for the salt means the database, the
    same place the attacker just looted. A pepper escapes that only because it
    is kept in a *different* place (env var, KMS, HSM) that a database-only
    breach does not reach. Salt and pepper differ by **location**, not by
    cryptography. Students who cannot answer this usually have not internalised
    that verification is re-derivation.

---

> **Scope note.** This script stores only the passwords you type into your own
> terminal, in your own process, and forgets them when it exits. The attack in
> activity 5 runs against a hash the script created seconds earlier. Nothing
> here touches a network. The techniques in the companion lab,
> [`../cracking/`](../cracking/README.md), carry an ethics note that applies to
> both halves of week 6.
