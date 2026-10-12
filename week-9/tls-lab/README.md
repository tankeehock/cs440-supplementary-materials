# TLS Lab — open the padlock

CS440 AY26T1 · Kee Hock · uv + Python, nothing else

Week 5 answered *"is this really the server's certificate?"* This week answers
everything else a browser does before it shows the padlock: how two strangers
agree a secret key in front of an eavesdropper, how that one secret becomes a
dozen keys, how the server proves it owns the certificate it sent, and how
either side notices if anyone touched a single byte.

You will run a **TLS 1.3 client written by hand in Python**. It builds the
ClientHello byte by byte, does the key exchange, walks the key schedule,
decrypts the server's reply and makes five checks. It completes a real handshake
with **OpenSSL**: the server is Python's own `ssl` module. Then you decrypt
an OpenSSL-to-OpenSSL session using only a key log file. Finally you put an
attacker on the wire seven ways and predict which check stops each one.

Everything happens in one script, `tls_lab.py`, on your own machine. You don't
need the network, Wireshark or the openssl command line (section 5 uses them
as an optional extension).

## Objective

**By the end you will be able to trace a TLS 1.3 handshake message by message,
say what each message proves and which secret protects it, and name the
library that does each piece of cryptography.**

| Activity | Objective (what you do) | What it demonstrates |
|---|---|---|
| **1. Meet the libraries** | Find out which code actually runs each primitive | A "TLS library" is two layers: a small amount of **protocol logic** and a set of **primitives**. Both run in your process, often from different libraries. |
| **2. The handshake by hand** | Run the hand-written client against OpenSSL; read every flight | One round trip delivers key exchange, server authentication and key confirmation. Every secret comes out of **one shared secret**, through **one key schedule**. |
| **3. The key log** | Decrypt OpenSSL↔OpenSSL traffic from a capture + key log | Your key schedule matches OpenSSL bit for bit. The server's private key **cannot** decrypt the traffic; the session secrets can. |
| **4. Attack the handshake** | 7 attacker variants: predict the check that catches each | Each of the five checks stops a specific attack. Some attacks still succeed, and you will see what makes that possible. |
| **5. Extensions** (optional) | Point real tools at real servers | The same messages, from `openssl s_client`, `curl` and Wireshark, against the live Internet. |

### Five ideas to hold onto

1. **TLS = key exchange + authentication + record protection.** Diffie-Hellman
   gives a shared secret, but not *with whom*. The certificate plus
   **CertificateVerify** says with whom. An **AEAD** cipher then protects every byte.
2. **Ephemeral keys give forward secrecy.** Both sides generate a fresh
   X25519 key pair for every connection and throw it away afterwards. Stealing
   the server's long-term private key later does not unlock past sessions.
3. **The transcript is bound into everything.** Every key and every MAC mixes in
   a hash of all handshake messages so far. Change one byte of any message and
   every later key is different.
4. **The certificate is public. The private key is not.** A certificate proves
   nothing on its own: anyone can copy it out of a handshake. The proof is a
   fresh **signature** over this handshake's transcript.
5. **Protocol logic vs primitives.** AES, X25519 and ECDSA are called through a
   library (here `cryptography`, which uses OpenSSL underneath). The *order* of
   messages and the *checks* are protocol logic. Historically that is where
   most TLS bugs were.

## Code map

Every landmark is a literal tag in `tls_lab.py`. Search it with
`grep -n "CHECK 4" tls_lab.py`. The comment block at the top of the file
mirrors this table.

| Lab activity | Command | Search this tag | What you'll find |
|---|---|---|---|
| **1. Libraries** | `libraries` | `ACTIVITY 1` | `cmd_libraries()` |
| **2. Handshake** | `handshake` | `ACTIVITY 2`, then `CHECK 1` … `CHECK 5` | `_client()`, the whole client, flight by flight |
| **3. Key log** | `keylog` | `ACTIVITY 3` | `cmd_keylog()` |
| **4. Attacks** | `handshake <variant>` | `ACTIVITY 4`, then `VARIANT: <name>` | `build_variant()`, one branch per attack |
| *bytes on the wire* | | `SHARED: WIRE FORMAT` | `build_client_hello()`, `Reader`, record framing |
| *the secret tree* | | `SHARED: KEY SCHEDULE` | `hkdf_extract`, `hkdf_expand_label`, `KeySchedule` |
| *encrypting records* | | `SHARED: RECORD PROTECTION` | `RecordProtection.seal/open` |
| *the other end* | | `SHARED: PEERS` | `OpenSSLServer`, `Tamperer`, `AttackerServer` |

## 0. Setup

```bash
cd week-9/tls-lab
uv run tls_lab.py init
```

`init` writes a `tls/` folder with **two** small PKIs. One is the lab's root CA
and a `localhost` certificate. The other is an attacker's root CA with *its
own*, equally valid, `localhost` certificate. (Week 5 builds a PKI properly;
here it is just scenery.) Every other command creates `tls/` automatically if
it is missing. Delete it to start over.

---

## 1. Meet the libraries

- **Objective:** know which code actually runs when "TLS" runs.
- **Code:** `ACTIVITY 1` → `cmd_libraries()`

```bash
uv run tls_lab.py libraries
```

Read the first block. Python's `ssl` module wraps the OpenSSL your Python was
built with. The `cryptography` package ships *its own* OpenSSL, statically
linked into its wheel and wrapped in Rust. On most machines the two are
**different versions in the same process**.

The middle table maps every primitive the hand-written client uses (section 2)
to the API it calls and the code that runs underneath. Two rows are *not*
OpenSSL: certificate parsing and chain validation run in `cryptography`'s own
Rust code.

### The TLS library landscape

You will meet all of these in the wild. The *protocol* is the same; the code,
defaults and bug history differ.

| Library | Language | Where you meet it |
|---|---|---|
| **OpenSSL** | C | Most Linux servers (nginx, Apache), Python `ssl`, Node.js, curl on Linux |
| **BoringSSL** | C/C++ | Google's fork of OpenSSL: Chrome, Android, Cloudflare. Apple's Network.framework is BoringSSL-based |
| **LibreSSL** | C | OpenBSD's fork after Heartbleed; the `openssl` command on macOS is actually LibreSSL |
| **AWS-LC** + **s2n-tls** | C | AWS's libcrypto (a BoringSSL fork) and TLS stack, behind AWS load balancers |
| **NSS** | C | Firefox, Thunderbird, some Red Hat tooling |
| **SChannel** | C | Windows itself: IIS, RDP, .NET on Windows, PowerShell |
| **Go `crypto/tls`** | Go | Every Go binary: Docker, Kubernetes, Caddy, Terraform |
| **rustls** | Rust | Memory-safe TLS; uses `aws-lc-rs` or `ring` for primitives |
| **JSSE** | Java | The JDK's built-in TLS (`javax.net.ssl`) |
| **mbedTLS**, **wolfSSL** | C | Embedded devices, IoT, routers. Small footprint |
| **`cryptography`** (Python) | Rust + OpenSSL | Primitives only, **no TLS**. Used by this lab's client |
| **PyCryptodome** (week 2) | C | Primitives only, **no TLS**; its own C code, not OpenSSL |

### Where TLS has actually broken

Notice which column the famous bugs fall in. Almost none were a broken cipher.

| Bug | Year | Library | What went wrong | Layer |
|---|---|---|---|---|
| Debian weak keys | 2008 | OpenSSL (Debian) | A patch removed the RNG's entropy; only 32,768 possible keys | randomness |
| goto fail | 2014 | Apple SecureTransport | A duplicated `goto` line skipped the ServerKeyExchange signature check | protocol logic |
| Heartbleed | 2014 | OpenSSL | Heartbeat length field trusted; read up to 64 KB of server memory | parsing |
| CCS injection | 2014 | OpenSSL | ChangeCipherSpec accepted too early, so keys were derived from known values | state machine |
| SKIP-TLS / SMACK | 2015 | JSSE, NSS, others | Clients let the server *skip* messages, including the signature | state machine |
| FREAK, Logjam | 2015 | many | Attacker downgraded to 512-bit "export" crypto, broke it in real time | negotiation |
| ROBOT | 2017 | many | Bleichenbacher's 1998 RSA padding oracle, still present | primitive *use* |

TLS 1.3 removed most of what these exploited. RSA key exchange, export suites,
CBC mode and renegotiation are gone; the signature now covers the whole
transcript. Activity 4 re-runs three of these bugs (key substitution, a skipped
message, a downgrade) against TLS 1.3.

> **Question 1.** The lab's client calls OpenSSL for every primitive, and its
> server *is* OpenSSL. Suppose a bug is found in OpenSSL's AES-GCM tomorrow.
> Which half of this lab is affected if you `pip install -U cryptography`
> but don't update Python? What does that tell you about patching
> "OpenSSL" on a real server?

<details><summary>Suggested answer</summary>

Updating `cryptography` replaces only *its* bundled OpenSSL, so only the
client's primitives are fixed. The server still uses the OpenSSL that Python
was linked against, which comes from the OS or from the Python build. A real
server may hold several OpenSSL copies at once: the system one, one
inside each Python or Node wheel, and one inside a static Go or Rust binary
that uses something else entirely. "We patched OpenSSL" is a claim about one
of them. You find the rest with an SBOM or by listing the libraries each
process has loaded (`lsof`, `ldd`, `pip show`).
</details>

> **Question 2.** Look at your speed numbers. Why does every secure protocol
> use public-key cryptography *once* and a symmetric cipher for everything else?
> On a phone without AES hardware, which TLS 1.3 suite would a server prefer?

<details><summary>Suggested answer</summary>

The AEADs run at gigabytes per second. Key agreement runs at thousands per
second, about six orders of magnitude slower per byte. So the expensive
operation is done once to agree a key, and the cheap one protects the data.
Without AES instructions, AES-GCM in software is slow and hard to make
constant-time, so `TLS_CHACHA20_POLY1305_SHA256` wins. Servers that honour the
client's order let a phone list ChaCha20 first. That is why the suite was added.
</details>

---

## 2. The handshake by hand

- **Objective:** follow one TLS 1.3 handshake flight by flight, and say for
  each message what it carries, which key protects it, and what it proves.
- **Code:** `ACTIVITY 2` → `_client()`. Each check is tagged `CHECK n of 5`.

```bash
uv run tls_lab.py handshake
```

The client and OpenSSL do not use sockets. They pass bytes to each other
through memory buffers (`ssl.MemoryBIO`), so every byte on the "wire" passes
through Python you can read. `sample_run_honest.txt` is a captured transcript.

### The shape of it

```
client                                                 server (OpenSSL)
  │  ClientHello  ─────────────────────────────────────────▶ │  plaintext
  │    + key_share (our X25519 public key)                   │
  │    + supported_versions, cipher suites, SNI ...          │
  │                                                          │
  │ ◀──────────────────────────────────────────  ServerHello │  plaintext
  │                        + key_share (server X25519 pub)   │
  │      ── both sides now compute the same shared secret ── │
  │      ── and derive the HANDSHAKE traffic keys ──         │
  │ ◀──────────────────────────────── {EncryptedExtensions}  │  encrypted with
  │ ◀──────────────────────────────────────── {Certificate}  │  server handshake
  │ ◀────────────────────────────────── {CertificateVerify}  │  key
  │ ◀─────────────────────────────────────────── {Finished}  │
  │      ── derive the APPLICATION traffic keys ──           │
  │  {Finished}  ──────────────────────────────────────────▶ │  client hs key
  │  [GET / HTTP/1.1]  ────────────────────────────────────▶ │  client app key
  │ ◀───────────────────────────── [NewSessionTicket] x2     │  server app key
  │ ◀───────────────────────────────── [HTTP/1.1 200 OK]     │
```

One round trip. TLS 1.2 needed two before any data flowed. TLS 1.3 saves the
second because **the client guesses**: it sends a key share in the ClientHello
before knowing what the server supports. (If the guess is wrong the server
sends a HelloRetryRequest and costs one more round trip. This lab doesn't
hit that case.)

### Walk through the output

Work down the transcript and answer as you go.

**FLIGHT 1 — ClientHello.** Find the X25519 private key (printed, never
sent) and the public key (sent in `key_share`). Find SNI.

> **Q2.1** The record header of the ClientHello begins `16 03 03`. `16` is
> "handshake". What is `03 03`, and where does the client actually say
> "TLS 1.3"? Why the indirection?

<details><summary>Suggested answer</summary>

`03 03` is the TLS 1.2 version number. TLS 1.3 is negotiated in the
`supported_versions` extension (`0x0304`). When TLS 1.3 was deployed, many
middleboxes (firewalls, load balancers) dropped connections showing a version
they didn't recognise. So TLS 1.3 *disguises itself as a TLS 1.2 session
resumption*: legacy version 0x0303, a random 32-byte `legacy_session_id`, and
a dummy ChangeCipherSpec record (you will see the server send one). This is
called "middlebox compatibility mode". It is the ugliest part of the spec and
was needed to deploy it.
</details>

> **Q2.2** SNI is sent in plaintext. What does a network observer (your ISP, a
> café Wi-Fi) learn from it even though everything after is encrypted?

<details><summary>Suggested answer</summary>

The hostname you are visiting, such as `localhost` here or `mybank.com` in real
life. Encryption hides *what* you do there, not *where* you go. Encrypted Client
Hello (ECH) encrypts the inner ClientHello to a key published in DNS. It is now
deployed by Cloudflare, Chrome and Firefox, but it is not yet universal.
</details>

**FLIGHT 2a — ServerHello and CHECK 1.** The server picked a version, a suite
and a group, and sent its own X25519 public key. CHECK 1 confirms it picked
only from what we offered.

**Key exchange.** `shared secret = X25519(our private, server public)`. The
server computes the same value from its private key and our public key.

> **Q2.3** An eavesdropper recorded both public keys. Why can't they compute the
> shared secret? Next year the server's *certificate private key* is stolen. Can
> the thief decrypt this recording?

<details><summary>Suggested answer</summary>

Computing X25519(a, B) from only A and B is the elliptic-curve Diffie-Hellman
problem, which is believed infeasible. Nobody ever sends a private scalar. The
certificate's private key is **not an input to key derivation at all**. It
only signs (CertificateVerify). Both ephemeral private keys were discarded
after the handshake, so nothing that still exists can recompute the shared
secret. That is **forward secrecy**. Compare TLS 1.2 with RSA key exchange: the
client encrypted the premaster secret *to the server's certificate key*, so a
stolen key decrypted every recorded session. TLS 1.3 removed RSA key exchange
for this reason.
</details>

**KEY SCHEDULE.** Read `SHARED: KEY SCHEDULE` in the code alongside the
output. Three `HKDF-Extract` calls make the early, handshake and master secrets.
`Derive-Secret` then mixes in a transcript hash to make each traffic secret.
Each traffic secret is expanded into a key and an IV.

> **Q2.4** Note the suite the server chose. If it is `TLS_AES_256_GCM_SHA384`,
> all secrets are 48 bytes; with `TLS_AES_128_GCM_SHA256`, 32. What does the
> `SHA384` in a suite name control, and what does it *not* control?

<details><summary>Suggested answer</summary>

It is the hash used by HKDF, the transcript hash and the Finished HMAC, so it
sets the secret size. It does **not** set the signature hash (negotiated
separately in `signature_algorithms`; here ECDSA with SHA-256) or the key
exchange group (negotiated in `supported_groups`). In TLS 1.2 a suite name like
`ECDHE-ECDSA-AES256-GCM-SHA384` bundled all four choices. TLS 1.3 split them, so
there are 5 suites instead of hundreds.
</details>

**FLIGHT 2b — the encrypted server flight.** Every record's *outer* type is
`application_data` (23); the *real* type is inside the encryption.

- **CHECK 2:** every record decrypts. The AEAD tag authenticates the
  ciphertext, the 5-byte header and implicitly the key and nonce.
- **CHECK 3:** the certificate chains to a root we trust and names `localhost`
  (week 5's seven checks, delegated to `cryptography`'s verifier).
- **CHECK 4:** CertificateVerify. The server signs
  `64 spaces ‖ "TLS 1.3, server CertificateVerify" ‖ 0x00 ‖ Transcript-Hash(ClientHello … Certificate)`.
- **CHECK 5:** Finished = HMAC over the transcript, under a key derived from
  the handshake secret.

> **Q2.5** CHECK 3 already proved the certificate is genuine. Why is CHECK 4
> needed at all?

<details><summary>Suggested answer</summary>

A certificate is a public document. Anyone who has ever connected to the server
has a copy, so presenting one proves nothing. CHECK 4 proves the sender holds
the **private key** matching the certificate. Because the signature covers the
transcript, which includes *our* fresh random and *our* fresh key share, it
cannot be replayed from any earlier handshake. Activity 4's `mitm-stolen-cert`
is this attack.
</details>

> **Q2.6** The signed content starts with 64 space characters and a context
> string. Why not just sign the transcript hash?

<details><summary>Suggested answer</summary>

Domain separation. The context string makes a server-handshake signature
useless anywhere else. It can't pass as a *client* CertificateVerify (a
different string) or as a signature in another protocol that uses the same key.
The 64-byte fixed prefix means the signed input never *starts* with bytes an
attacker controls. In TLS 1.2 the signed data began with the two hello
randoms, which an attacker can partly choose, and some hash-collision attacks
need exactly that kind of control over the start of the input.
</details>

**FLIGHT 3 and 4.** The client sends its own Finished (the *server* checks
it) and an HTTP request under the client application key. The server sends two
NewSessionTickets (for resuming later without a full handshake) and the response.

> **Q2.7** Which key encrypts the client's Finished, and which key encrypts the
> HTTP request right after it? Why do the two directions use *different* keys?

<details><summary>Suggested answer</summary>

The Finished uses the *client handshake* traffic key; the request uses the
*client application* traffic key. Each direction has its own key and its own
sequence number. With one shared key, a record sent by the client could be
reflected back to the client as if the server had sent it (a reflection
attack), and two counters starting at 0 would reuse the same nonce under the
same key. With AES-GCM, nonce reuse leaks the authentication key and the XOR of
the plaintexts.
</details>

---

## 3. The key log

- **Objective:** confirm your key schedule matches OpenSSL's, and see what does
  and does not let someone decrypt TLS.
- **Code:** `ACTIVITY 3` → `cmd_keylog()`

```bash
uv run tls_lab.py keylog
```

This time *both* ends are OpenSSL; our code is not involved in the handshake.
The script captures every byte. It also sets `keylog_filename` on the client.
This is the hook behind the `SSLKEYLOGFILE` environment variable that Chrome,
Firefox and curl honour. OpenSSL writes its traffic secrets to that file. The
script then decrypts the capture with `RecordProtection` and
`hkdf_expand_label()` from activity 2.

Read part 1 (what a passive observer sees), part 2 (the key log) and part 3
(the decryption).

> **Q3.1** Every record decrypted. What does that prove about the code in
> `SHARED: KEY SCHEDULE` and `SHARED: RECORD PROTECTION`?

<details><summary>Suggested answer</summary>

Our `HKDF-Expand-Label` (the `"tls13 "` prefix, the length encoding, the
`"key"`/`"iv"` labels), the nonce construction (IV XOR sequence number), the
AAD (record header) and the inner-plaintext layout (content ‖ type ‖ padding)
all match OpenSSL exactly. An AEAD tag fails if any one bit is wrong. Activity 2
proves the *rest* of the schedule, from the shared secret through HKDF-Extract:
OpenSSL accepted our Finished and our request, which needs every secret
in the tree to be right.
</details>

> **Q3.2** The decryption never used the server's private key (`tls/lab/leaf.key`).
> In TLS 1.2 with RSA key exchange, Wireshark could decrypt traffic given only
> the server's private key. Why can't it in TLS 1.3, and what does a company
> that "needs to inspect TLS" have to do instead?

<details><summary>Suggested answer</summary>

In TLS 1.3 the private key only *signs*; session keys come from the ephemeral
ECDHE secret, which the private key never touches (forward secrecy again). A
passive appliance holding the server key sees nothing. Inspection needs the
session secrets. Either the endpoint exports them (key logging, for debugging),
or the inspector becomes an active **man-in-the-middle** with its own CA
installed on every client. That second option is activity 4's `mitm-trusted-ca`.
</details>

> **Q3.3** Part 1 shows only lengths: `[applicati 534B]` and so on. Without any
> keys, what could an observer still infer from these?

<details><summary>Suggested answer</summary>

Quite a lot. The ~530-byte record is a certificate chain, and its size often
identifies the site. The request and response sizes, their timing and their
count fingerprint pages: which Wikipedia article, which video quality, sometimes
the words typed into a search box with autocomplete. TLS 1.3 lets senders add
padding inside the encryption (the zeros stripped in `RecordProtection.open`),
but almost no one uses it. This is traffic analysis, and encryption alone does
not stop it.
</details>

> **Security note:** a key log file is the session. Anyone holding it and a
> capture reads everything. Never leave `SSLKEYLOGFILE` set on a machine you use
> for real browsing, and treat the file like a password.

---

## 4. Attack the handshake

- **Objective:** match each attack to the check that stops it, and see what
  happens when a check is missing or the trust store is compromised.
- **Code:** `ACTIVITY 4` → `build_variant()`. Each attack is tagged `VARIANT: <name>`.
  Read it **after** you predict.

```bash
uv run tls_lab.py variants
```

There are two kinds of attacker:

- **On-path tamperer** (`Tamperer`): sits between our client and the *real*
  OpenSSL server and edits bytes in flight. It never learns any key.
- **Impersonator** (`AttackerServer`): answers the client itself with a
  complete, correct TLS 1.3 server implementation. It lacks only whatever
  credential its certificate and key can't supply.

**For each variant: read its one-line description, predict which CHECK fails
(or that none does), then run it.**

```bash
uv run tls_lab.py handshake flip-record
uv run tls_lab.py handshake swap-keyshare
# ... and so on
```

| Variant | Your prediction | Actual failing check | Did the attacker read the request? |
|---|---|---|---|
| flip-record | | | |
| swap-keyshare | | | |
| downgrade-hello | | | |
| mitm-stolen-cert | | | |
| mitm-own-cert | | | |
| skip-certverify | | | |
| skip-certverify `--naive` | | | |
| mitm-trusted-ca | | | |

Then compare with the scoreboard:

```bash
uv run tls_lab.py handshake --all
```

### Hints

| Variant | Hint |
|---|---|
| flip-record | The attacker can't read the record, but can it change it without anyone noticing? |
| swap-keyshare | The ServerHello is plaintext and parses fine after the swap. Whose shared secret does the client compute? Whose did the server use to encrypt? |
| downgrade-hello | The server picks AES-128 honestly; the client offered it, so CHECK 1 is happy. But what goes into `Derive-Secret` besides the shared secret? |
| mitm-stolen-cert | Certificates are public. What is the one thing in the server flight that a certificate can't produce? |
| mitm-own-cert | Everything about this certificate is valid, except for one property that only the *client* decides. |
| skip-certverify | What does the client do when the next message is not the one it expects? |
| skip-certverify `--naive` | Read the CHECK 5 line. Why does Finished pass? Who computed it? |
| mitm-trusted-ca | Week 5, activity 3. |

### What to take away

<details><summary>Suggested answers (open after you have run them all)</summary>

| Variant | Fails | Attacker reads? | Why |
|---|---|---|---|
| flip-record | **CHECK 2** | no | AEAD: one flipped bit and the tag fails. Encryption without integrity would have let this through. |
| swap-keyshare | **CHECK 2** | no | The client's shared secret is now X25519(client, *attacker*) and the server's is X25519(*server*, client). The keys differ, so the server's first encrypted record won't open. The attacker shares a secret with the client but can't produce what the server would: a valid certificate *signature*. |
| downgrade-hello | **CHECK 2** | no | The server's transcript contains the *edited* ClientHello; ours contains the original. Transcript hashes differ → handshake traffic secrets differ → AEAD fails. In TLS 1.3 an edit to *any* earlier message changes every later key. (FREAK/Logjam beat TLS ≤1.2 because only Finished guarded the transcript, and the attacker could forge it after breaking the weak export key.) |
| mitm-stolen-cert | **CHECK 4** | no | The real certificate passes CHECK 3. The attacker can't sign the transcript with the real private key. **This is the reason CertificateVerify exists.** |
| mitm-own-cert | **CHECK 3** | no | A perfectly valid certificate from an untrusted root. Same as week 5's `untrusted-ca`. |
| skip-certverify | **CHECK 4** | no | The client enforces message order: after Certificate it expects CertificateVerify, nothing else. |
| skip-certverify `--naive` | none | **yes** | Without that order check, nothing else catches it. Finished is an HMAC under keys from the ECDHE secret, which the **attacker** shares with the client, so the attacker computes a valid Finished. This is SKIP-TLS (2015), found in real clients. |
| mitm-trusted-ca | none | **yes** | Every check passes because the client trusts the attacker's root. TLS did exactly what it promises: an authenticated channel to whoever holds a cert from a CA you trust. Corporate TLS inspection, some antivirus, and stalkerware all work this way. |

**Discussion: why does CHECK 5 never fail first?** In TLS 1.2 the Finished MAC
was the *only* thing protecting the negotiation. In TLS 1.3 the transcript feeds
the key derivation and is signed in CertificateVerify, so tampering is caught
earlier: by AEAD (wrong keys) or by the signature. Finished remains as **key
confirmation**. It is also the only thing the *server* checks to authenticate
the client's view of the handshake. And it backs up the other checks: try
commenting out CHECK 4 and running `mitm-stolen-cert`. Which check catches it
then? (Answer: none. The attacker computes Finished from the ECDHE secret it
shares with the client. Every check has its own job.)
</details>

---

## 5. Extensions (optional, uses the network)

**Watch a real handshake.** OpenSSL's command-line client prints every message:

```bash
openssl s_client -connect www.smu.edu.sg:443 -tls1_3 -msg -brief </dev/null
openssl s_client -connect www.google.com:443 -tls1_3 -groups X25519MLKEM768 -brief </dev/null
```

The `-msg` output shows the same ClientHello, ServerHello and encrypted records
you built by hand. (On macOS the default `openssl` is LibreSSL. Use
`brew install openssl` for these flags; `-groups X25519MLKEM768` needs
OpenSSL 3.5 or later.) The second line asks for
**X25519MLKEM768**, a hybrid of X25519 and the post-quantum ML-KEM. Chrome,
Firefox and OpenSSL 3.5+ now send it by default. Its key share is about 1.2 KB
instead of 32 bytes. Why combine the two instead of switching to ML-KEM alone?

**Decrypt your own browser.** Set `SSLKEYLOGFILE=$HOME/keys.txt`, start
Chrome or Firefox from that shell, and capture with Wireshark. Then set
*Preferences → Protocols → TLS → (Pre)-Master-Secret log filename*. The HTTP/2
frames appear in plaintext. Compare the labels in `keys.txt` with activity 3.
Delete the file afterwards.

**`curl -v`** prints the negotiated version, suite and certificate chain in
one line each: `curl -v https://www.smu.edu.sg -o /dev/null`.

**Things this lab deliberately leaves out.** HelloRetryRequest (the server
rejects our key-share guess); PSK resumption with the NewSessionTickets you
received; **0-RTT** early data, which can be *replayed*, which is why it is
only safe for idempotent requests; client certificates (mutual TLS); KeyUpdate;
and Encrypted Client Hello. Each fits on top of the key schedule you already
have. All but ECH are in RFC 8446; ECH has its own specification.

---

## Answer key (instructor)

Verified with `uv run tls_lab.py handshake --all`:

```
  variant                    C1   C2   C3   C4   C5   outcome
  ------------------------- ---- ---- ---- ---- ---- ------------------
  honest                     ok   ok   ok   ok   ok   secure
  flip-record                ok   FAIL  -    -    -   refused
  swap-keyshare              ok   FAIL  -    -    -   refused
  downgrade-hello            ok   FAIL  -    -    -   refused
  mitm-stolen-cert           ok   ok   ok   FAIL  -   refused
  mitm-own-cert              ok   ok   FAIL  -    -   refused
  skip-certverify            ok   ok   ok   FAIL  -   refused
  skip-certverify --naive    ok   ok   ok    -   ok   ATTACKER READS
  mitm-trusted-ca            ok   ok   ok   ok   ok   ATTACKER READS
```

Teaching notes:

- **Three variants all fail CHECK 2**, for three different reasons: integrity of
  the ciphertext, a mismatched shared secret, and a mismatched transcript. The
  AEAD tag can't tell which. Ask students to say *which input to the key*
  differed in each.
- The two **ATTACKER READS** rows make the lab's main points. A missing check
  in the protocol logic (`--naive`) defeats perfect cryptography. A trusted CA
  you didn't choose (`mitm-trusted-ca`) defeats a perfect implementation.
- The honest run normally selects `TLS_AES_256_GCM_SHA384`. OpenSSL's server
  prefers it, and Python sets server cipher preference. The impersonator always
  picks `TLS_AES_128_GCM_SHA256`. Sharp students notice the suite change in
  the transcript; it doesn't affect any result.
- Inline answers above cover Q1–Q2, Q2.1–Q2.7 and Q3.1–Q3.3. Extension
  question: hybrid key exchange stays secure as long as *either* component is
  unbroken. ML-KEM is new and its implementations are young, while X25519 is
  well studied but falls to a future quantum computer. A "harvest now, decrypt
  later" adversary recording traffic today is the reason to deploy it before
  quantum computers exist.
