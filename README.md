# CS440 Supplementary Materials

Runnable, self-explaining demos that accompany the CS440 lectures. Each script
is a *guided lesson*: it prints the theory, then shows every intermediate value
of the computation, so the console transcript can be read top to bottom.

Everything runs with [uv](https://docs.astral.sh/uv/) — no manual virtualenv or
`pip install` steps required.

---

## 1. Setting up uv

### Install

**macOS / Linux / WSL**

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

**Windows (PowerShell)**

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

**Alternatives**

```bash
brew install uv        # macOS (Homebrew)
pipx install uv        # if you already use pipx
```

Restart your shell, then confirm the install:

```bash
uv --version           # e.g. uv 0.12.5
```

### Get a Python interpreter

The project requires Python **3.11+**. uv can fetch one for you — you do not
need Python pre-installed:

```bash
uv python install 3.12
```

### Set up this repository

```bash
git clone <repo-url>
cd cs440-supplementary-materials
uv sync                # creates .venv/ and installs dependencies
```

`uv sync` reads `pyproject.toml`, resolves the dependencies (currently
`pycryptodome`), writes `uv.lock`, and builds `.venv/` in the project root.
Both `.venv/` and `uv.lock` are git-ignored.

### Running scripts

Always run through `uv run` — it activates the project environment for you, so
there is no `source .venv/bin/activate` step:

```bash
uv run week-2/aes_encryption.py
```

Some scripts (weeks 3, 4, 5 and 6) carry their own dependencies in a
[PEP 723](https://peps.python.org/pep-0723/) inline metadata header, e.g.:

```python
# /// script
# requires-python = ">=3.9"
# dependencies = ["argon2-cffi"]
# ///
```

For those, `uv run` builds a throwaway isolated environment on the fly and
installs what the header asks for. That means `week-6/password-systems.py`
works even though `argon2-cffi` is not in `pyproject.toml` — the first run just
takes a few extra seconds while uv downloads it.

### Useful uv commands

| Command | What it does |
| --- | --- |
| `uv sync` | Install/refresh the project environment from `pyproject.toml` |
| `uv run <script.py>` | Run a script in the right environment |
| `uv add <package>` | Add a dependency to `pyproject.toml` and install it |
| `uv remove <package>` | Drop a dependency |
| `uv lock --upgrade` | Re-resolve to the newest allowed versions |
| `uv python list` | Show the interpreters uv knows about |
| `uv self update` | Update uv itself |

---

## 2. Repository layout

```
.
├── pyproject.toml          # project metadata + shared dependencies
├── main.py                 # placeholder entry point
├── week-2/                 # classical ciphers, AES block modes
├── week-3/                 # RSA
├── week-4/                 # hashing, HMAC, length extension, RSA signatures
├── week-5/                 # PKI lab + certificate transparency OSINT
├── week-6/                 # password cracking & password storage
└── week-7/                 # access control lists (CLI lab) + an RBAC web server
```

---

## 3. Contents by week

### Week 2 — Classical ciphers & AES block modes

```bash
uv run week-2/cipher_table.py
uv run week-2/aes_encryption.py
uv run week-2/aes_encryption.py --no-pause   # print everything, no Enter prompts
```

- **`cipher_table.py`** — substitution vs transposition, showing the actual
  machinery: the full Caesar alphabet mapping table, and the columnar
  transposition grid before (written row-wise) and after (read column-wise),
  plus frequency analysis of the results.
- **`aes_encryption.py`** — a paced walkthrough of **ECB, CBC and CTR**.
  Definitions first, then each mode traced block by block with every
  intermediate value printed. Press Enter to advance, or pass `--no-pause`.
- **`secret-message.rar` / `secret-message.txt`** — the archive-cracking
  exercise. See [`week-2/README.md`](week-2/README.md) for the plaintext,
  password, and the `xxd` hex-dump / frequency-analysis walkthrough.

### Week 3 — RSA

```bash
uv run week-3/rsa_tutorial.py
```

Four parts: **(1)** textbook RSA built from scratch with tiny primes so every
number is verifiable by hand — including manual extended Euclid, modular
inverse and square-and-multiply; **(2)** why textbook RSA is insecure
(determinism, malleability, small-message attacks); **(3)** real-world 2048-bit
RSA with OAEP padding via `pycryptodome`; **(4)** encoding vs encryption — why
Base64/hex are *not* encryption.

### Week 4 — Hashing, HMAC & digital signatures

```bash
uv run week-4/hashes.py            # interactive: Enter=next, b=back, 1-5=jump, q=quit
uv run week-4/hashes.py | cat      # non-interactive: run all stages straight through
uv run week-4/rsa_signatures.py    # same navigation
```

- **`hashes.py`** — five stages: what a hash is → why MD5 is broken →
  integrity and password storage → a **from-scratch SHA-256 used to
  demonstrate the length-extension attack** → HMAC as the fix. Standard
  library only (`hashlib`, `hmac`). Stages 4 and 5 are the long ones and are
  broken into lettered parts: stage 4 builds the forgery from "a digest is a
  snapshot of the machine, not a summary of the message", and stage 5 shows
  *why* HMAC's outer hash defeats it — you really can still resume the tag,
  the extension just lands on the wrong side of the nesting.
- **`rsa_signatures.py`** — picks up exactly where HMAC runs out: a shared
  secret means whoever can check a tag can forge one. Six stages: signature
  vs MAC (and what non-repudiation buys) → sign/verify on a 12-bit toy key you
  can check by hand → why you sign the *hash*, and **exactly which bytes** get
  hashed in X.509, JWT, TLS and git → three forgeries against unpadded RSA
  (existential, multiplicative, blank-cheque) → real 2048-bit keys with
  PKCS#1 v1.5 and PSS, including the failure cases: tampered message, flipped
  bit, and verification against the wrong public key → **HMAC and signatures
  together**.

  That last stage answers a question students always ask — *do we sign an
  HMAC?* No: they are alternatives, chosen by who must verify, and signing a
  MAC re-introduces the shared secret a signature exists to remove. But both
  appear in one format, the JWT (`HS256` vs `RS256`), and the demo builds both
  tokens and then runs the **algorithm confusion attack**: take the server's
  *public* key, relabel the token `HS256`, and HMAC it using that public key
  as the shared secret. A verifier that reads `alg` from the token accepts it
  and a guest becomes admin — the same "trusted attacker-controlled input"
  bug as week 7's RBAC demo, wearing a cryptographic hat.

### Week 5 — PKI & certificate transparency

Two halves: build and break a certificate chain yourself, then go looking at
what real chains leak in public.

```bash
uv run week-5/pki-lab/pki_lab.py init          # build root + intermediate CA
uv run week-5/pki-lab/pki_lab.py run good      # serve + validate, step by step
uv run week-5/pki-lab/pki_lab.py run --all     # scoreboard of every variant
uv run week-5/pki-lab/pki_lab.py variants      # list the sabotage variants
```

**`pki-lab/`** — a three-tier CA hierarchy (root → intermediate → leaf), an
HTTPS server running on it, and a client that validates the chain in **seven
explicit steps**: hostname vs SAN, validity windows, path building to a trust
anchor, CA:TRUE + keyCertSign on every issuer, signatures, leaf EKU, key
strength. Then **eleven sabotage variants** — expired, wrong name, CN with no
SAN, missing intermediate, a leaf signed by another *leaf*, self-signed,
untrusted root, clientAuth-only EKU, RSA-1024, and one byte flipped after
signing — and for each you predict which step catches it before running it.

Every run prints three verdicts side by side: the seven manual steps, the
`cryptography` library's verifier, and OpenSSL via Python's `ssl` module.
Where they *disagree* is the lesson — `cn-only` is accepted by OpenSSL (CN
fallback) and rejected by the other two; `weak-key` is the reverse; and
trusting the intermediate instead of the root splits OpenSSL from both. A
valid certificate is a policy question, not just a maths one.

[`week-5/pki-lab/README.md`](week-5/pki-lab/README.md) is the ~90-minute
student lab sheet: a conceptual primer on the ideas behind PKI, then each
activity framed by what it means and why, a prediction table, and an
instructor answer key. `sample_run_good.txt` and `sample_run_rogue-leaf.txt`
are captured transcripts. The script writes its keys and certificates to a
`pki/` directory in whatever directory you run it from; delete it to start over.

**`osint-challenge-with-cert/`** — the other direction: what Certificate
Transparency tells an attacker about a target that never spoke to them.

```bash
uv run week-5/osint-challenge-with-cert/ct_osint.py --help
cd week-5/osint-challenge-with-cert
uv run ct_osint.py all smu.edu.sg          # steps 1-7 in sequence
uv run ct_osint.py naming tech.gov.sg      # or one step at a time
uv run ct_osint.py fetch <your-domain>     # the only command that uses the network
```

`ct_osint.py` is a standard-library-only CLI — no `jq`, no `curl`, nothing to
install — with one subcommand per step of the lab: `surface`, `naming`,
`nonprod`, `shared`, `timeline`, `revoked`, `wildcards`. Each prints an
explanation of what you are looking at, which `--brief` turns off.

[`osint-challenge-with-cert/README.md`](week-5/osint-challenge-with-cert/README.md)
is the lab sheet, in two halves: a **guided walkthrough of `smu.edu.sg`** with the answers
worked through, then the **same eight steps against `tech.gov.sg`** as an open
challenge with hints only, plus an instructor answer key. `smu.edu.sg.ct.logs`
and `tech.gov.sg.ct.logs` are captured API responses, so the whole thing runs
offline.

The findings are real: an environment ladder that lets you guess hosts you never
saw, a database admin console hidden behind a 31-character random hostname that
Certificate Transparency published anyway, a university library sharing one
private key with two dozen unrelated businesses via its WAF vendor, and a
government platform's tenant onboarding reconstructed date by date from
certificate reissues.

> **Ethics:** the OSINT half reads a public, append-only log — no packet ever
> reaches the target, which is exactly what makes CT worth understanding. Acting
> on what you find against a system you do not own is a different matter.

### Week 6 — Passwords

```bash
uv run week-6/password-cracking.py             # the full guided lesson
uv run week-6/password-cracking.py --try abcd  # brute-force a short password you pick

uv run week-6/password-systems.py              # interactive register / login / view store
uv run week-6/password-systems.py --demo       # scripted narrated walkthrough
uv run week-6/password-systems.py --brief      # same, explanations off
```

- **`password-cracking.py`** — the search-space arithmetic made concrete: how
  big the space is, a real brute-force against a fast hash, why real passwords
  are not random (dictionary attack), and the defence — shrinking the
  attacker's rate with a slow hash.
- **`password-systems.py`** — a transparent password store following the OWASP
  Password Storage Cheat Sheet (**Argon2id**, m=19 MiB, t=2, p=1, 16-byte
  CSPRNG salt). It prints the salt, the derived hash, the exact stored record,
  and the parameters reloaded at login.

> **Ethics:** `password-cracking.py` only cracks hashes it generates itself, for
> teaching. Cracking passwords, accounts or systems you do not own is illegal.
> The lesson is defensive.

### Week 7 — Access control & RBAC

```bash
uv run week-7/rbac-demo/app.py            # RBAC server on http://127.0.0.1:8000
uv run week-7/rbac-demo/app.py --policy   # print the policy matrix and exit
```

[`week-7/README.md`](week-7/README.md) is a hands-on
terminal lab you run on your own laptop, covering **Windows** (`icacls`,
`Get-Acl` / `Set-Acl`, SDDL, inheritance flags, ownership) and **macOS**
(`ls -le`, `chmod +a`, inheritance, POSIX bits, flags and extended attributes),
plus a side-by-side comparison of the two models and a short Linux/WSL
(`getfacl` / `setfacl`) appendix.

```powershell
icacls report.txt              # Windows
```

```bash
ls -le report.txt              # macOS
```

Worked demonstrations carry the key points: **deny beats allow** (an ACL entry
overrides the permission bits), and the two operating systems handle
**inheritance** in opposite ways — Windows re-propagates a parent's change to
every child, while macOS stamps a copy at creation and never revisits it.

A final section connects the lab to **privilege escalation in penetration
testing**: why most escalation is a misconfigured ACL rather than an exploit,
the enumeration commands that surface the classic findings (writable service
binaries, weak service and registry ACLs, unquoted paths, writable `PATH`
entries, over-privileged tokens on Windows; setuid binaries, writable
LaunchDaemons and `sudo` policy on macOS), and the same commands re-read as a
defensive hardening audit.

> **Ethics:** that section is enumeration of machines you own. Running it
> against systems you have no written authorisation to test is unlawful. The
> point is to find these misconfigurations before someone else does.

**`rbac-demo/`** then moves the same question up a layer, from the OS to an
application. It is a small Flask server built around
`subject → role → permission → action`, which prints every authorisation
decision it makes as a trace — the subject, its roles, what those roles expand
to, what the route demanded, and the verdict. Five accounts from `viewer` up to
`admin`, plus one that is authenticated and authorised for nothing. Routes are
guarded by *permission*, never by username, so granting a role at `/admin/users`
changes what a user may do with no restart and no code change.

It is also a **deliberately vulnerable target**, in the spirit of DVWA or
WebGoat, with seven planted bugs. Three break authorisation directly, each
paired with its correct twin: no check at all; a check that trusts a role the
caller asserts in a header; and a check that is correct but too coarse to stop
an editor rewriting someone else's report (IDOR). Two of those leave no trace in
the audit log — a clean log is not evidence that nothing happened. The other
four are three XSS and an open redirect, which bypass every permission check
without touching one, because an injected script runs with the victim's session
and roles. `--safe` fixes that family so students can fire the same payloads at
both. Localhost only; never expose it.
See [`week-7/rbac-demo/README.md`](week-7/rbac-demo/README.md).

> **Ethics:** `rbac-demo` is vulnerable by design, on purpose, for teaching. The
> techniques transfer; the permission does not. Use them only on systems you own
> or have written authorisation to test.

---

## 4. Troubleshooting

**`uv: command not found`** — the installer puts uv in `~/.local/bin`; restart
your shell, or add it to `PATH`.

**A script exits immediately instead of pausing** — the paced scripts detect a
TTY. When output is piped or redirected they run every stage without prompting.
That is intentional; run them directly in a terminal for the interactive flow.

**Rebuild the environment from scratch**

```bash
rm -rf .venv && uv sync
```
