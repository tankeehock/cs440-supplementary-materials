# PKI Lab — build it, break it, catch it

CS440 AY26T1 · Kee Hock · uv + Python, nothing else

You will build a certificate authority hierarchy, run an HTTPS server on it,
and validate the server's certificate chain by hand — the same seven checks a
browser performs before it shows a padlock. Then you will sabotage the chain
eleven different ways and, for each, predict which check catches it before
you run it.

Everything happens in one script, `pki_lab.py`, on your own machine. No
openssl command line, no Wireshark, no internet.

## What you'll learn

By the end you will be able to **validate a TLS certificate chain the way a
browser does — the seven checks — and explain what each check defends against.**
Everything rests on five facts; each activity makes one of them concrete, so read
these once and refer back.

1. **The problem PKI solves.** Your browser is handed a public key and told it
   belongs to `smu.edu.sg`. A man-in-the-middle can hand you *their* key instead
   — encryption alone would then just secure your channel *to the attacker*. PKI
   proves the key really belongs to the name.
2. **A certificate is a public, signed statement** — "this key belongs to this
   name", signed by a CA. It is *not* secret. The matching **private key** is.
3. **Trust is delegated down a chain.** A **root** CA signs an **intermediate**,
   which signs the **leaf** (the website). Verifying means walking that chain to
   a CA you already trust.
4. **Trust lives in the verifier, not the certificate.** A certificate is trusted
   only because *you* hold its root in your trust store — not because of anything
   in the certificate itself.
5. **Validation is a seven-point checklist and you are the browser:** right
   *name*, right *time*, chains to a *trusted* anchor, issued by a real *CA*,
   *signatures* verify, allowed to be a *server*, *strong* enough key.

The method is **build it, break it, catch it**: build a good chain (activity 1),
watch all seven checks pass (activity 2), see that trust is your decision
(activity 3), then sabotage the chain one way at a time and work out *which
check* catches each attack (activity 4).

## Code map: which activity lives where in `pki_lab.py`

The whole lab is one file, `pki_lab.py`, organised so you can jump straight to
the code behind whatever you are doing. Every landmark in the table below is a
**literal, searchable tag** written into the code as a comment — open the file
and search for the tag, or from a terminal run e.g. `grep -n "STEP 4"
pki_lab.py` to jump to the exact line.

Start by opening `pki_lab.py` and reading the comment block at the very top: it
is a map of the file that mirrors this table.

| Lab activity | Command | Search this tag in `pki_lab.py` | What you'll find |
|---|---|---|---|
| **1. Build the CA hierarchy** | `init` | `ACTIVITY 1` | `cmd_init()` — makes the root + intermediate |
| **2. The healthy case** (7 checks) | `run good` | `ACTIVITY 2`, then `STEP 1` … `STEP 7` | `cmd_verify()` — each check is one tagged block |
| **3. Trust is the client's decision** | `run good --trust …` | `ACTIVITY 3` / `STEP 3` (and `anchors`) | where the trust store decides the verdict |
| **4. Break it** (11 sabotages) | `run <variant>` | `ACTIVITY 4`, then `VARIANT: <name>` | `build_variant()` — one branch per sabotage |
| *the certificate builder (used by all)* | — | `SHARED: CERTIFICATE TOOLKIT` | `make_cert()` — the single builder every cert flows through |
| *the HTTPS server it connects to* | `serve` | `SHARED: HTTPS SERVER` | `start_server()` / `cmd_serve()` |

Two habits that make the code easy to follow:

- **Each of the seven checks is tagged `STEP n of 7`** and carries a comment
  saying what it asks and *which variants trip it*. So when activity 4 tells you
  `rogue-leaf` fails step 4, you can `grep "STEP 4"` to read exactly why.
- **Each sabotage is tagged `VARIANT: <name>`** in `build_variant()`, right next
  to the one line that breaks the chain and a note on which check should catch
  it. Reading a variant's branch tells you the attack in three lines.

## 0. Setup

The only requirement is [uv](https://docs.astral.sh/uv/). You do not need
Python installed and you do not need to install anything else — `pki_lab.py`
declares `cryptography` in a PEP 723 header, so `uv run` fetches an
interpreter and builds a throwaway environment on the first run.

```bash
cd week-5/pki-lab
uv run pki_lab.py variants
```

The first run takes a few seconds while uv downloads `cryptography`; after
that it is instant. The command is identical on Windows, macOS and Linux —
no `python` vs `python3`, no virtualenv to activate, no `pip install`.

The script works in the directory you run it from and creates a `pki/`
folder there. Delete `pki/` at any time to start over.

## 1. Build the CA hierarchy

- **You'll learn:** a certificate is a public document you can share freely, while
  its private key is the one secret; and that trust is *delegated* root →
  intermediate → leaf.
- **Concept tested:** the CA hierarchy, and public certificate vs secret key.
- **Code:** `ACTIVITY 1` → `cmd_init()`; each certificate is built by `make_cert()`
  (`SHARED: CERTIFICATE TOOLKIT`).

```bash
uv run pki_lab.py init
```

Read the output, then open `pki/root.pem` and `pki/intermediate.pem` in a
text editor. They are Base64 — you can't read them, but notice they are
plain text and could be emailed, printed, or pasted anywhere. Nothing in a
certificate is secret.

Now open `pki/root.key`. That one IS secret. In a real CA it lives in a
hardware security module and is used a handful of times in its life.

```
   ┌────────────────────┐
   │ CS440 Lab Root CA  │  self-signed · P-384 · 10 years
   │ pki/root.pem       │  the only thing a client will TRUST
   └─────────┬──────────┘
             │ root.key signs
   ┌─────────▼──────────┐
   │ Intermediate CA    │  CA:TRUE · P-256 · 5 years
   │ pki/intermediate   │  does the day-to-day signing
   └─────────┬──────────┘
             │ intermediate.key signs
   ┌─────────▼──────────┐
   │ leaf: localhost    │  CA:FALSE · 90 days · created by `serve`
   │ pki/served/leaf    │  what the HTTPS server presents
   └────────────────────┘
```

**Question 1.** Why two tiers instead of having the root sign the leaf
directly? Write one sentence before reading the script's answer.

## 2. The healthy case

- **You'll learn:** how a browser decides a certificate is trustworthy — the
  seven checks — and what each one is *for*.
- **Concept tested:** chain validation: name, time, path, CA, signature, usage,
  key strength.
- **Code:** `ACTIVITY 2` → `cmd_verify()`; the seven checks are tagged `STEP 1`
  through `STEP 7`, in the same order as the table below.

```bash
uv run pki_lab.py run good
```

`run` starts the HTTPS server, connects as a client, validates the chain, and
shuts down. (Two-terminal version: `serve good` in one, `verify --trust
pki/root.pem` in the other.)

**You should see** seven `[PASS]` lines and three `ACCEPT` verdicts — the same
result reached three ways (your manual steps, the `cryptography` library, and
OpenSSL). Read each step's detail line and answer:

| Step | What it checks | Question for you |
|---|---|---|
| 1 | hostname ∈ Subject Alternative Name | Why does the browser ignore the Subject CN? |
| 2 | validity window, every cert | Which cert would a clock set to 2040 reject first? |
| 3 | path from leaf to a trust anchor | Where did the client get the intermediate from? Where did it get the root from? |
| 4 | every issuer is CA:TRUE + keyCertSign | What would happen if this check were skipped? |
| 5 | each signature verifies with the parent's PUBLIC key | Whose private key was needed to run this check? |
| 6 | leaf may act as a TLS server | Which extension says so? |
| 7 | key strength | Why is 256-bit EC acceptable but 1024-bit RSA not? |

Now open `pki/served/chain.pem`. Count the `BEGIN CERTIFICATE` lines. That
file is exactly what the server sends in the handshake — the leaf and the
intermediate, but **not** the root. Question 2: why not the root?

## 3. Trust is the client's decision

- **You'll learn:** whether a certificate is "valid" depends on *the client's
  trust store*, not on the certificate. The exact same good chain from activity
  2 will be accepted or rejected purely by changing what the client trusts.
- **Concept tested:** the **trust anchor** — the root a verifier has decided, in
  advance, to believe. Validation is really the question "does this chain reach
  a root *I already trust*?"
- **Code:** `STEP 3` in `cmd_verify()`. The `--trust` file is loaded into the
  `anchors` list; the chain only validates if path-building reaches a certificate
  that is *in that list*.

**The experiment.** Run the identical healthy server from activity 2 three times.
Nothing about the certificate changes — only the client's trust store (`--trust`)
does:

```bash
uv run pki_lab.py run good --trust ""                    # (a) trust nothing
uv run pki_lab.py run good --trust pki/root.pem          # (b) trust our root
uv run pki_lab.py run good --trust pki/intermediate.pem  # (c) trust the intermediate
```

**What each run actually does.** Every run is the *same* machine you saw in
activity 2 — only one input changes:

1. **Serve.** The script builds the healthy `good` chain (leaf + intermediate,
   signed by our root) and serves it over TLS on `localhost:8443`. This is
   byte-for-byte identical in all three runs.
2. **Load the trust store.** It reads the `--trust` file into the `anchors` list.
   This is the *only* thing that differs between the runs: (a) an empty list,
   (b) our root, (c) our intermediate.
3. **Verify.** The client connects, pulls the served chain, and runs the seven
   checks plus the two reference verifiers against it — using `anchors` as the
   set of certificates it is willing to trust as an endpoint. `STEP 3` (path
   building) is the check that consults `anchors`: it walks leaf → issuer → … and
   succeeds only if it reaches a certificate that is *in that list*.

So the certificate, the server, and all seven checks are held fixed across the
three runs; the single variable is what you told the client to trust. That is
what makes the verdict change meaningful.

### What a trust store is, and how the code implements it

A **trust store** is nothing more than *the set of certificates a client has
decided, ahead of time, to trust as an endpoint* — the roots where a chain is
allowed to stop. It is not part of any certificate and it is not sent over the
network; it lives on the client. Your browser and OS ship one (~150 roots);
here, it is whatever `--trust` points at.

In `cmd_verify()` (search `ACTIVITY 3`), the `--trust` file is read once into a
plain list called `anchors`:

```python
anchors = read_certs(trust_path) if trust_path else []   # the trust store
```

That one list is then handed to all three verifiers — the same trust store,
expressed three ways, which is exactly why changing `--trust` moves every verdict
at once:

- **Manual (STEP 3).** `anchors` is a Python list; path-building stops the moment
  it reaches a certificate that is in it:
  ```python
  if any(cur == a for a in anchors):        # reached a trusted anchor -> done
  ```
- **Library.** The same list is wrapped in the `cryptography` package's `Store`:
  ```python
  store    = Store(anchors)
  verifier = PolicyBuilder().store(store).time(now).build_server_verifier(...)
  ```
- **OpenSSL.** The file itself is handed to OpenSSL as its CA file:
  ```python
  ctx = ssl.create_default_context(cafile=str(trust_path))
  ```

All three encode the same decision — "these are the roots I trust" — so an empty
store rejects everything (run a) and adding our root accepts the chain (run b).
The one place they *differ* is what counts as a valid stopping point when the
store holds only an intermediate (run c) — see below.

**What you should see** (look at the three `verdict` lines at the bottom of each):

| Trust store | Manual | Library | OpenSSL | Why |
|---|---|---|---|---|
| (a) nothing | REJECT | REJECT | REJECT | The chain reaches our root, but our root is in nobody's trust store, so there is no anchor to stop at. |
| (b) our root | **ACCEPT** | **ACCEPT** | **ACCEPT** | Same chain — but now the client trusts the root it ends at. |
| (c) the intermediate | ACCEPT | ACCEPT | **REJECT** | The three disagree on *what may be a trust anchor* — see below. |

Those three columns are **three independent verifiers the script actually runs**
on the same chain, not one answer printed three times:

- **Manual** — the seven checks you watched in activity 2, done by this script.
- **Library** — the `cryptography` package's own verifier (a separate engine).
- **OpenSSL (Python ssl)** — a *real TLS handshake* to `localhost:8443`, verified
  by the OpenSSL **library** through Python's `ssl` module. It is **not** the
  `openssl` command-line tool; the error strings (e.g. `unable to get issuer
  certificate`) come straight from libssl.

When all three agree, that is strong evidence. When they disagree (row c, and
`weak-key`/`cn-only` in activity 4), that gap is the lesson.

**The takeaway.** The certificate was byte-for-byte identical in all three runs.
The only thing that moved the verdict from REJECT to ACCEPT was the client's list
of trusted roots. That is the whole point: **trust is not something a certificate
carries — it is a decision the verifier makes** by choosing what goes in its
trust store. An attacker who can slip a root into your trust store (malware, a
corporate proxy, a tampered device) can make *any* certificate look valid to you.

**Why run (c) splits the three verifiers.** All three agree the chain is
cryptographically sound; they disagree only on whether a *mid-chain* certificate
is allowed to be the anchor you stop at:

- **Our verifier and the `cryptography` library** treat **anything in the trust
  store as a valid anchor.** You put the intermediate in the store, so reaching
  the intermediate *is* reaching a trusted anchor — done, ACCEPT. (In the code,
  `STEP 3` stops the moment `path[-1]` is in `anchors`, regardless of whether it
  is a root or an intermediate.)
- **OpenSSL, by default, requires the anchor to be a self-signed root.** It
  happily follows leaf → intermediate, but because the intermediate is *not*
  self-signed it does not treat it as a stopping point — it keeps going, looks
  for the intermediate's own issuer (the root), cannot find it (the root is
  neither sent nor trusted), and fails: `unable to get issuer certificate`.
  OpenSSL would accept a trusted intermediate only if explicitly told to allow a
  partial chain (its `X509_V_FLAG_PARTIAL_CHAIN` option, which is off here).

Neither is "wrong" — they draw the anchor line in different places, a choice RFC
5280 leaves to policy. **Browsers side with OpenSSL:** their trust is pinned to
root programs, so a certificate that chains only to a trusted intermediate, not a
trusted root, is rejected. This is exactly why real servers must send their
intermediates (activity 4's `no-intermediate`) rather than assume the client
trusts them.

> **Gotcha on run (a).** `--trust ""` empties the trust store for the manual
> steps and the library, but Python's `ssl` module (the OpenSSL line) silently
> falls back to your *operating system's* ~150 built-in roots when given no CA
> file. It still REJECTs — because our lab root is not one of those 150 — but for
> that reason, not because it trusts nothing. See for yourself:
> `uv run python -c "import ssl; print(ssl.create_default_context().cert_store_stats())"`.

**Question 3.** Given run (b): your OS ships with ~150 built-in roots. What does
that number tell you about *how many* organisations could issue a certificate
your browser would accept for `smu.edu.sg`?

## 4. Break it

- **You'll learn:** what each of the seven checks actually defends against, by
  breaking the chain and seeing which check catches it.
- **Concept tested:** mapping each real-world failure or attack to the one check
  that stops it — a check you have only seen pass, you do not yet understand.
- **Code:** `ACTIVITY 4` → `build_variant()`; search the specific `VARIANT: <name>`
  you run (each branch is the one change that breaks the chain). Read it *after*
  you predict, not before.

**The drill for every variant: predict which step fails, run it, then check.**
Some variants fail more than one step, and some are caught differently by
different verifiers.

List the sabotage variants:

```bash
uv run pki_lab.py variants
```

Run them one at a time, recording what actually failed:

```bash
uv run pki_lab.py run expired
uv run pki_lab.py run wrong-name
# ... and so on
```

Prediction sheet (fill the prediction column *before* you run each):

| Variant | Your prediction | Actual failed step(s) | OpenSSL's error text |
|---|---|---|---|
| expired | | | |
| not-yet-valid | | | |
| wrong-name | | | |
| cn-only | | | |
| no-intermediate | | | |
| rogue-leaf | | | |
| self-signed | | | |
| untrusted-ca | | | |
| bad-eku | | | |
| weak-key | | | |
| tampered | | | |

### Hints — one for every variant

Use these to *make* your prediction; each nudges you toward the check to suspect
without naming it outright. Fill in your sheet before you look at the answer key
at the end of this file.

| Variant | Hint |
|---|---|
| `expired` | Something about *time*. Which single check looks at dates? |
| `not-yet-valid` | A validity window has two edges, not one — this trips the same check as `expired`. |
| `wrong-name` | The certificate is honest, but it is for a *different* host than the one you connected to. Which check compares the two? |
| `cn-only` | The hostname is present, but only in the deprecated Common Name field, not the SAN. Watch the three verifiers *disagree* — that disagreement is the lesson. |
| `no-intermediate` | The server sent one fewer certificate than before. With the middle link gone, what can the client no longer do? Expect several checks to fall from one cause. |
| `rogue-leaf` | Every signature is valid and the chain reaches the trusted root, so the maths is fine. Look instead at what the *middle* certificate is *permitted* to be. |
| `self-signed` | The leaf is its own issuer. Follow the chain: where does it lead, and does it ever reach your trust store? |
| `untrusted-ca` | The chain is flawless in every internal way. The only thing wrong is *whose* root it ends at. Which check is the last line of defence? |
| `bad-eku` | The certificate is genuine but *labelled* for the wrong job. Which extension states what a certificate may be used for? |
| `weak-key` | Nothing is malformed; the key is simply too small. Which check cares about size — and notice which verifier does *not*. |
| `tampered` | One byte was flipped *after* signing. What exactly does a digital signature cover, and what breaks the instant a covered byte changes? |

Four of these repay extra thought once you have run them — they are the ones
that teach something beyond "a field was wrong":

- **cn-only** — the three verifiers disagree. Which one is being lenient,
  and would Chrome agree with it?
- **rogue-leaf** — the chain is three certificates long and every signature is
  mathematically valid. So what is wrong? This was a real browser bug class for
  years — any leaf could otherwise mint certificates for any site.
- **no-intermediate** — the most common real-world misconfiguration, famous for
  "works in Chrome, breaks in curl": some clients quietly repair the chain and
  others do not. Where could a client go to repair it by itself? (A real leaf
  carries an **Authority Information Access** extension with a URL for its
  issuer's certificate; our lab leaf has none — check with the dissector in
  section 5. Chrome and Windows also cache intermediates they have seen before,
  which is why the misconfiguration so often survives testing.)
- **untrusted-ca** — every check that examines the certificates *themselves*
  passes. The chain is internally perfect. Which check fails, and why is it the
  one that matters most?

When you have filled in the sheet, check yourself against the live tools:

```bash
uv run pki_lab.py run --all
```

The full answer — the failed step(s), OpenSSL's exact error, and *why* for
every variant — is in the **Answer key** at the end of this file. Read it only
after your prediction sheet is complete; predicting first, then checking, is
what turns the seven checks from a list you read into a model you own.

## 5. Extensions (optional)

- **You'll learn:** the seven checks are a teaching subset, not all of RFC 5280 —
  real verifiers close gaps this lab leaves open.
- **Concept tested:** certificate extensions, why a valid *signature* is not a
  *safe* signature algorithm (SHA-1), and `pathLenConstraint`.
- **Code:** `make_cert()` (`SHARED: CERTIFICATE TOOLKIT`) and the checks in
  `cmd_verify()` (`ACTIVITY 2`) are what you extend.

- **Dissect the chain.** Run any variant, then dump every extension the
  server actually sent:

  ```bash
  uv run --with "cryptography>=43" python -c "
  from cryptography import x509
  for c in x509.load_pem_x509_certificates(open('pki/served/chain.pem','rb').read()):
      print(c.subject.rfc4514_string())
      for e in c.extensions:
          print(f'   {\"CRIT\" if e.critical else \"    \"} {e.oid._name}: {e.value}')
  "
  ```

  Two things to find. First, the leaf's `authorityKeyIdentifier` is byte-for-byte
  the intermediate's `subjectKeyIdentifier` — that pair is how step 3 links a
  child to its parent when several certificates share a subject name. Second,
  there is no `authorityInfoAccess` anywhere, which is why `no-intermediate` is
  unrecoverable here but often survivable on the public internet.
- **Try to add a `sha1-signed` variant.** Sign the leaf with `hashes.SHA1()`
  instead of `hashes.SHA256()` in `make_cert` and run it. You will not get a
  certificate — `cryptography` raises `UnsupportedAlgorithm: Hash algorithm
  "sha1" not supported for signatures`. The library will not let you *mint* a
  SHA-1 certificate at all.

  Now the uncomfortable half. Make one outside the library and hand it to the
  script:

  ```bash
  openssl req -x509 -newkey rsa:2048 -keyout sha1.key -out sha1.pem \
      -days 30 -nodes -sha1 -subj "/CN=localhost"
  uv run --with "cryptography>=43" python -c "
  from cryptography import x509
  c = x509.load_pem_x509_certificate(open('sha1.pem','rb').read())
  print(c.signature_hash_algorithm.name)
  "
  ```

  The same library loads it without complaint, and `verify_signature` returns
  `True` for it. **Signing policy and verification policy are different
  things, and only one of them is where the attacker meets you.** Now add step
  8 to reject `cert.signature_hash_algorithm.name` in `{"md5", "sha1"}` across
  the whole path, not just the leaf.
- Add a `path-length` variant: give the intermediate `path_length=0`, then
  insert a second intermediate below it. Which step should catch it, and
  does the script's step 4 do so?
- Modify `verify` to fetch the intermediate from an AIA URL when the server
  omits it, so `no-intermediate` becomes recoverable.

---

## Answer key (instructor)

| Variant | Failed step(s) | OpenSSL error | Note |
|---|---|---|---|
| good | — | ACCEPT | |
| expired | 2 | certificate has expired | |
| not-yet-valid | 2 | certificate is not yet valid | |
| wrong-name | 1 | Hostname mismatch | |
| cn-only | 1 | **ACCEPT** | OpenSSL falls back to CN when SAN is absent; cryptography's verifier and all modern browsers reject. Lenient verifier = OpenSSL. |
| no-intermediate | 3, 4, 5 | unable to get local issuer certificate | Fix is server-side (send the chain) or client-side (AIA fetch). |
| rogue-leaf | 4 | invalid CA certificate | Signatures all valid; the middle cert is CA:FALSE. The check that stops any leaf from minting certs for any site. |
| self-signed | 3, 4, 5 | self-signed certificate | |
| untrusted-ca | 3 | self-signed certificate in certificate chain | Everything about the chain is internally correct. The only defence is the client's trust store. |
| bad-eku | 6 | unsuitable certificate purpose | |
| weak-key | 7 | EE certificate key too weak | cryptography's verifier ACCEPTS (it doesn't enforce key size); OpenSSL at default security level rejects. |
| tampered | 5 | certificate signature failure | The signature covers every byte of the TBS block, subject name included. |

### Section 2 — the seven step questions

1. **Why does the browser ignore the Subject CN?** CN is a free-text display
   field with no defined syntax and room for exactly one name. SAN is
   structured, typed (`dNSName`, `iPAddress`) and repeatable. The CA/Browser
   Forum has required SAN since 2017 and Chrome dropped CN fallback in v58.
   Watch this bite in the `cn-only` variant, where OpenSSL still falls back.
2. **Which cert would a clock set to 2040 reject first?** All three — and
   that is the point. The leaf dies in 90 days, the intermediate in 5 years,
   the root in 10. Root expiry is a genuine operational cliff, not a
   hypothetical: AddTrust's root expired in May 2020 and broke payment
   terminals and Roku devices worldwide.
3. **Where did the client get the intermediate? The root?** The intermediate
   arrived in the handshake, from the server (`pki/served/chain.pem`). The
   root came from the local trust store via `--trust`, and was never sent by
   anybody. This is the whole distinction the lab is built around.
4. **What if step 4 were skipped?** Anyone holding a valid leaf certificate
   for any domain becomes a CA for every domain. That is exactly the
   `rogue-leaf` variant: buy one cheap certificate, sign a leaf for your
   bank with it, and every signature in the chain checks out.
5. **Whose private key was needed to run this check?** Nobody's. Verification
   uses only public keys — which is why a client who has never met the CA,
   and the CA who is offline in a safe, can both be part of the same
   transaction. Contrast with HMAC in week 4.
6. **Which extension says so?** `extendedKeyUsage` containing `serverAuth`,
   backed by `keyUsage` with `digitalSignature` and `basicConstraints`
   CA:FALSE. The `bad-eku` variant flips the first of those.
7. **Why is 256-bit EC acceptable but 1024-bit RSA not?** Key length is not
   comparable across algorithms — what matters is the work factor. EC-256
   gives ~128-bit security; RSA-1024 gives ~80-bit and has been considered
   factorable by a well-resourced attacker for over a decade. Matching EC-256
   with RSA takes roughly a 3072-bit modulus.

### Questions 1–3 (from activities 1–3)

Q1: Root key exposure is catastrophic and unrevocable; an intermediate can
be revoked and replaced without touching every client's trust store.

Q2: The root is the trust anchor; the client must already hold it. A root
sent by the server proves nothing — anyone can send any root.

Q3: Any of ~150 organisations (and every intermediate they have delegated
to) can issue a certificate your browser will accept for any name. That is
why Certificate Transparency exists.

### Section 5 extensions — answers

**Dissect the chain.** Covered inline in section 5: the leaf's
`authorityKeyIdentifier` equals the intermediate's `subjectKeyIdentifier`
(that pair is how step 3 links child to parent), and no certificate carries an
`authorityInfoAccess` extension — confirmed by the dump.

**path-length.** First, the variant. `make_cert` needs to be able to set the
constraint, so add a `path_length` parameter and pass it into
`BasicConstraints`:

```python
def make_cert(..., path_length: int | None = None, ...):
    ...
    .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
```

Then build a three-CA path where the middle CA forbids any CA beneath it:

```python
elif variant == "path-length":
    root      = read_certs(PKI / "root.pem")[0]
    root_key  = read_key(PKI / "root.key")
    capped    = make_cert(name("CS440 Lab Intermediate CA (pathLen:0)"),
                          int_key.public_key(), root, root_key,
                          ca=True, days=1825, path_length=0)   # 0 = no sub-CAs
    sub_key   = ec.generate_private_key(ec.SECP256R1())
    sub       = make_cert(name("CS440 Lab Sub CA"), sub_key.public_key(),
                          capped, int_key, ca=True, days=365)  # ...but here is one
    issuer_cert, issuer_key = sub, sub_key
    chain_extra = [sub, capped]
```

Now the question: *does step 4 catch it?* **No — and that is the finding.** Run
it and all seven steps PASS while both libraries REJECT:

```
  [PASS] step 4: every issuer in the path is marked CA:TRUE + keyCertSign
  Manual verdict      : ACCEPT
  Library verdict     : REJECT  (path length constraint violated)
  OpenSSL (Python ssl): REJECT  (path length constraint exceeded)
```

Every issuer in the path genuinely *is* a CA with `keyCertSign`, so the check
as written is satisfied. It never reads `pathLenConstraint`, the field whose
whole job is to say *how many* CAs may sit below this one. `pathLen:0` means
"this CA may sign leaves, but no further CAs" — a real delegation control, used
when a company runs its own issuing CA under a public root but must not be able
to mint sub-CAs. This is the **third gap in the manual checks**, alongside SHA-1
(the `sha1-signed` exercise above) and the leniencies in `cn-only`/`weak-key`:
the seven steps are a teaching subset of RFC 5280, not the whole standard.

The fix folds into step 4 — it already walks the issuer chain, so count how many
CAs sit below each one and compare to its limit:

```python
for below, (child, parent) in enumerate(zip(path, path[1:])):
    bc = ext(parent, ExtensionOID.BASIC_CONSTRAINTS)
    ku = ext(parent, ExtensionOID.KEY_USAGE)
    limit  = bc.path_length if bc else None
    ok_len = limit is None or below <= limit      # `below` = intermediates beneath it
    is_ca  = bool(bc and bc.ca) and (ku is None or ku.key_cert_sign)
    link_ok &= is_ca and ok_len
```

**AIA fetch.** The `no-intermediate` variant fails because the server sent only
the leaf and the client cannot build the path. On the public internet a client
often repairs this itself: a real leaf carries an **Authority Information
Access** extension whose `caIssuers` field is a URL for the issuer's
certificate, so the client fetches the missing intermediate and continues. Our
lab leaf has no AIA (the dissector confirms it), which is exactly why
`no-intermediate` is unrecoverable here but survivable in the wild. To make it
recoverable: give the leaf an AIA extension in `make_cert`, stand up an HTTP
endpoint that serves `intermediate.pem`, and in `fetch_chain`/path-building,
when no issuer is found among the sent certificates, read the leaf's AIA URL and
fetch it. The security caveat worth stating to students: AIA fetching means the
client makes an attacker-influenceable outbound request during validation, so
browsers treat it cautiously (Chrome does it; Firefox historically did not).
