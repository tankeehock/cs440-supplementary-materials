# Week 6 — Passwords

CS440 AY26T1 · Kee Hock

Three pieces of material, three roles. You attack a password, then build the
store that survives the attack, then review somebody else's attempt at the same
job and find the thirteen places they got it wrong.

| | Material | You are the | Time |
|---|---|---|---|
| 1 | [`cracking/`](cracking/README.md) — *the search space, shown by cracking* | attacker | ~45 min |
| 2 | [`simple-password-auth/`](simple-password-auth/README.md) — *build the thing that survives the leak* | defender | ~45 min |
| 3 | [`password-system-challenge/`](password-system-challenge/README.md) — *SecureVault: a source code review* | reviewer | ~60 min |

Run them in that order — each one sets up the next. About **2.5 hours** for all
three, plus optional extensions.

```bash
uv run cracking/password-cracking.py                    # the guided lesson
uv run cracking/password-cracking.py --try abcd         # crack a password you pick

uv run simple-password-auth/password-systems.py --demo  # narrated walkthrough
uv run simple-password-auth/password-systems.py         # interactive console

uv run password-system-challenge/app.py                 # the review target, :8000
uv run password-system-challenge/app.py --seed-only     # list its seeded accounts
```

Everything runs with [uv](https://docs.astral.sh/uv/) — no virtualenv, no
`pip install`. Each script declares its own dependencies in a PEP 723 header, so
the first run of each takes a few extra seconds and the rest are instant.

## What each one is

**1. `cracking/` — the arithmetic, made concrete by doing it.** How big a search
space is, what moves it, and what it costs in time. It cracks a real SHA-256
hash in front of you, then shows that the arithmetic was optimistic all along
because real passwords are not random: `john1990` falls in five guesses, not
`62^8`. Ends with the defence — making each guess slow — and hands over to lab 2.
Standard library plus one Argon2id call; writes nothing, touches no network.

**2. `simple-password-auth/` — the store, built transparently.** Registration
and login following the OWASP Password Storage Cheat Sheet (Argon2id,
`m=19 MiB, t=2, p=1`, 16-byte CSPRNG salt, constant-time compare), printing
every intermediate value: the salt, the derived hash, the exact record stored,
and the parameters reloaded at login. Then it leaks its own store and attacks
it — and a *correctly stored* `password123` still falls in five guesses, which
is the point. In-memory only; writes nothing, touches no network.

**3. `password-system-challenge/` — the assessment.** "SecureVault", a small
Flask staff portal with **thirteen planted findings**: unsalted MD5 hashing,
plaintext passwords written to an application log that is served to anonymous
visitors, and a password reset flow broken four separate ways. Students read the
source, write a findings report, and mark themselves against the answer key.

Unlike the first two, this one **runs a web server on `127.0.0.1:8000` and
writes a log file (`app.log`, git-ignored) into its own directory.** It is
graded on the method, not on clicking around: the finding that best separates a
careful reviewer from a fast one is invisible in the browser entirely, and the
runner-up is one the interface actively lies about.

> **The challenge app is vulnerable by design**, in the same spirit as
> [`week-7/rbac-demo`](../week-7/rbac-demo/README.md), DVWA or WebGoat. Every
> account, password and email address in it is invented. Localhost only; never
> expose it, never copy a pattern from it, never type a real password into it.

> **Instructors:** the answer key is in the second half of that same
> `README.md`, under a `# Answer key` heading. If you are running the challenge
> as assessment, hand out only the part above that line, or require the findings
> report to be submitted before students scroll.

## Why this order

Labs 1 and 2 share one threat model, and it is stated once here because every
design decision in both depends on it:

> **Assume the password database has already leaked.** The attacker holds the
> hashes and guesses on their own hardware, at their own pace — no login form,
> no rate limit, no lockout, no logging. This is the *offline* attack.

Under that assumption exactly two defences survive, and the two labs take one
each:

| Lever | Whose job | Where it is taught |
|---|---|---|
| Make the search space large and **random** | the *user*, enabled by policy | `cracking/` — Parts 1 and 3 |
| Make each guess **slow and expensive** | the *operator* | `simple-password-auth/` — the whole lab |

Neither is sufficient alone, and the labs are built to make that concrete: the
storage lab stores `password123` perfectly correctly and still watches it fall
in five guesses. That moment is the point of the pairing, and it does not land
unless the cracking lab came first.

**The challenge then widens the threat model deliberately.** A real system is
not attacked only through its hash store, and SecureVault's thirteen findings are
spread across the whole surface: two of them are the storage mistakes labs 1 and
2 prepare you for, but the rest are online — a guessable reset token, a session
cookie you can simply write yourself, an admin page with no check on it at all.
Two of them chain into unauthenticated administrator takeover in two requests;
a third gets full administrator impersonation in one, with no password involved
at all. Not one of the three requires breaking any cryptography.

That is the last idea of the week, and it needs all three pieces to land:
**storing passwords correctly is one control among several, and it is the one
whose failure you cannot fix later.**

## What you should be able to do afterwards

1. Compute a password's search space and its entropy in bits, and price it in
   time against a stated guess rate.
2. Explain why length beats character-class complexity, in numbers.
3. Explain why the formula does **not** apply to a password a human invented —
   and what attackers do instead.
4. Store a password correctly: per-user CSPRNG salt, Argon2id with stated
   parameters, constant-time comparison, parameters stored alongside the hash.
5. Say what each of those four decisions defends against, individually.
6. State what password storage does *not* defend, and name the controls that do.
7. Review unfamiliar authentication code to a repeatable method, and write each
   finding up with its location, its impact, and a fix that works.
8. Rank findings by impact rather than by cleverness, and show how separately
   minor ones chain into a critical one.

## Where it sits in the course

- **Week 4** (`hashes.py`) — what a hash is, why it is one-way, and the first
  look at password storage. Week 6 is that idea taken seriously.
- **Week 5** (PKI, CT logs) — supplies the attacker's reconnaissance. The
  targeted attack in `cracking/` Part 3(b) is built from exactly the kind of
  personal and organisational detail week 5 taught you to harvest, and
  SecureVault's username convention (`t.chen`, `j.rivera`) is guessable from two
  examples for the same reason.
- **Week 7** (ACLs, RBAC) — picks up one instant after `RESULT: GRANT`.
  Authentication asks *who are you*; authorisation asks *what may you do*. They
  are separate mechanisms, and week 7 is the second one. Its
  [`rbac-demo`](../week-7/rbac-demo/README.md) is the same review exercise one
  layer up, with seven more planted bugs.

## Ethics

The two labs attack only hashes they generated themselves, seconds earlier, in
their own memory. The challenge app is a deliberately vulnerable target that
runs on `127.0.0.1` and is populated entirely with invented accounts. Nothing in
week 6 reaches a network beyond your own machine.

The techniques transfer to real systems; the permission does not. Cracking
passwords, reviewing systems, or testing accounts you do not own — or do not
have written authorisation to test — is an offence in Singapore under the
Computer Misuse Act, and in most other jurisdictions. You learn the attack so
that you can price the defence.
