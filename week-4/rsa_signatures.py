# /// script
# requires-python = ">=3.10"
# dependencies = ["pycryptodome"]
# ///
"""
RSA digital signatures — a short, stage-by-stage tutorial.

Run:  uv run week-4/rsa_signatures.py       (Enter=next, b=back, 1-6=jump, q=quit)
      uv run week-4/rsa_signatures.py | cat (runs every stage, no pauses)

This is the sequel to hashes.py, which ends by saying: HMAC needs a SHARED
secret, so anyone who can CHECK a tag can also FORGE one. A signature removes
that limitation — verifying uses a different key from signing.

    hashes.py       tag = HMAC(shared_key, m)      check needs the same secret
    this file       sig = Sign(private_key, m)     check needs only the PUBLIC key

Stages 2-4 use tiny numbers so every value can be checked on paper. Stage 5
uses real 2048-bit keys via pycryptodome. Stage 6 puts HMAC and signatures in
the same room — JWTs — and shows the attack that comes from confusing them.
Nothing here is a black box.

Week 3's rsa_tutorial.py covers RSA *encryption*; this file is only about
signing, and assumes nothing from it.
"""

import sys
import json
import hmac
import base64
import hashlib

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15, pss


# --- tiny output helpers (same conventions as hashes.py) ----------------------

def p(text: str = "") -> None:
    """Print a line, indented two spaces."""
    print(f"  {text}" if text else "")


def diagram(block: str) -> None:
    """Print a multi-line ASCII diagram, preserving its internal spacing."""
    for line in block.strip("\n").splitlines():
        p(line)
    p()


def head(n: int, total: int, title: str) -> None:
    bar = "-" * 54
    print("\n")
    p(bar)
    p(f"STAGE {n} of {total}   |   {title}")
    p(bar)
    print()


def step(title: str) -> None:
    """A labelled sub-section inside a stage.

    Long titles wrap onto their own line rather than losing the rule, so the
    sub-headings stay scannable at any length.
    """
    p()
    if len(title) <= 46:
        p(f"--- {title} " + "-" * (50 - len(title)))
    else:
        p("-" * 54)
        p(f"    {title}")
        p("-" * 54)
    p()


def nav(i: int, total: int):
    """Ask where to go after a stage. Returns 'next', 'prev', 'quit', or a
    zero-based stage index. Auto-advances when output is piped."""
    if not sys.stdin.isatty():
        return "next"
    while True:
        try:
            raw = input(
                f"\n  stage {i + 1}/{total}  >  Enter=next  b=back  "
                f"1-{total}=jump  q=quit : "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            return "quit"
        print()
        if raw == "":
            return "next"
        if raw == "b":
            return "prev"
        if raw == "q":
            return "quit"
        if raw.isdigit() and 1 <= int(raw) <= total:
            return int(raw) - 1
        p("  (press Enter, or b, or a stage number, or q)")


# --- the toy key pair, used in stages 2-4 -------------------------------------
#
# The textbook RSA numbers everyone meets first. They are far too small to be
# secure — that is exactly why they are useful: every line of arithmetic below
# can be checked with a calculator.
#
#   p, q  two primes            61, 53
#   n     modulus = p*q         3233   <- public
#   phi   (p-1)*(q-1)           3120   <- secret (knowing it reveals d)
#   e     public exponent       17     <- public
#   d     private exponent      2753   <- SECRET, e*d = 1 (mod phi)
#
TOY_P, TOY_Q = 61, 53
TOY_N = TOY_P * TOY_Q                       # 3233
TOY_PHI = (TOY_P - 1) * (TOY_Q - 1)         # 3120
TOY_E = 17
TOY_D = pow(TOY_E, -1, TOY_PHI)             # 2753


def toy_sign(value: int) -> int:
    """The private operation: raise to d. Only the key holder can do this."""
    return pow(value, TOY_D, TOY_N)


def toy_verify(signature: int) -> int:
    """The public operation: raise to e. Recovers whatever was signed."""
    return pow(signature, TOY_E, TOY_N)


def toy_hash(message: bytes) -> int:
    """A stand-in hash that fits inside our tiny modulus.

    Real signatures hash with SHA-256 and get a 256-bit value; our modulus is
    only 12 bits, so we take SHA-256 and reduce it mod n. It behaves like a
    hash for teaching purposes — same input gives same output, and you cannot
    steer the output — while staying small enough to print. Reducing mod n
    destroys its collision resistance, of course; that is fine here because
    nothing in this file attacks the hash itself.
    """
    return int.from_bytes(hashlib.sha256(message).digest(), "big") % TOY_N


def b64u(raw: bytes) -> bytes:
    """base64url, no padding — the encoding JWTs use for every segment."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def b64u_decode(seg: bytes) -> bytes:
    """Undo b64u. The '==' is harmless over-padding; Python ignores extra."""
    return base64.urlsafe_b64decode(seg + b"==")


def jwt_parts(claims: dict, alg: str) -> tuple[bytes, bytes, bytes]:
    """Build a JWT's header and payload segments, and the bytes that get
    signed. A JWT is just: base64url(header).base64url(payload).signature
    — and the signature covers exactly the first two segments joined by a dot.
    """
    header = b64u(json.dumps({"alg": alg, "typ": "JWT"},
                             separators=(",", ":")).encode())
    payload = b64u(json.dumps(claims, separators=(",", ":")).encode())
    return header, payload, header + b"." + payload


_DIAG_MIRROR = r"""
ENCRYPTION                            SIGNING
(week 3)                              (this file)

  anyone --[ public key ]--> lock       owner --[ PRIVATE key ]--> sign
  owner  --[ PRIVATE key ]-> unlock     anyone --[ public key ]--> verify

  secrecy: many can send,               authenticity: one can sign,
           one can read                              many can check
"""

_DIAG_PIPELINE = r"""
SIGNING (private key holder)          VERIFYING (anyone, public key)

   message                               message + signature
      |                                       |          |
      v                                       v          |
   SHA-256  --> digest                     SHA-256       |
      |                                       |          v
      v                                       |     s^e mod n
   padding  --> encoded                       |          |
      |                                       v          v
      v                                    padded digest ==? recovered
   m^d mod n --> signature                          |
                                                    v
                                            same -> genuine
                                            differ -> rejected
"""


# --- STAGE 1 — what a signature is, and why HMAC was not enough ---------------

def stage1() -> None:
    head(1, 6, "Signature vs MAC: why a second key changes everything")
    p("hashes.py finished with HMAC, which proves a message is genuine")
    p("using a secret both sides share. That works, and it has a limit")
    p("that is easy to miss:")
    p()
    p("    to CHECK an HMAC tag you need the same key used to MAKE it")
    p()
    p("So anyone who can verify can also forge. Fine between two parties")
    p("who already trust each other. Useless the moment you want the")
    p("whole world to be able to check, or you need to prove to a third")
    p("party WHO produced something.")
    p()
    p("A digital signature splits that one key into two:")
    p()
    diagram(_DIAG_MIRROR)
    p("Sign with the key only you hold; verify with the key everyone has.")
    p("Three properties fall out, and the third is the new one:")
    p()
    p("  authenticity   it really came from the key holder")
    p("  integrity      it has not been altered since")
    p("  NON-REPUDIATION  the signer cannot later deny it, because nobody")
    p("                 else COULD have produced the signature")
    p()
    p("HMAC gives you the first two and cannot give you the third: with a")
    p("shared key, either party could have made the tag, so neither can")
    p("prove the other did.")
    p()
    step("Which one should I use?")
    p("  HMAC                        Signature")
    p("  ----                        ---------")
    p("  one shared secret           private key + public key")
    p("  verifier can also forge     verifier can only verify")
    p("  no non-repudiation          non-repudiation")
    p("  ~microseconds               ~milliseconds (1000x slower)")
    p("  32-byte tag                 256-byte signature (2048-bit RSA)")
    p()
    p("  Use HMAC between two systems that already share a secret:")
    p("  session cookies, API request signing, internal messages.")
    p()
    p("  Use signatures when the verifier is untrusted, numerous or")
    p("  unknown: software updates, certificates (week 5!), JWTs issued")
    p("  to third parties, code signing, legal documents.")
    p()
    p("Neither one gives you FRESHNESS. A signature says 'the key holder")
    p("approved this', never 'they approved it just now' — a captured")
    p("signed message stays valid forever unless you add a timestamp or")
    p("a nonce. Stage 5 comes back to this.")


# --- STAGE 2 — the core operation, on numbers you can check -------------------

def stage2() -> None:
    head(2, 6, "The core operation, in numbers you can check by hand")
    p("RSA has exactly two operations, and they undo each other:")
    p()
    p("    private:  s = m^d mod n      (only the key holder can do this)")
    p("    public:   m = s^e mod n      (anyone can do this)")
    p()
    p("Encryption runs them public-first. Signing runs them PRIVATE-first.")
    p("That is the entire difference at this level.")
    p()
    step("The toy key pair")
    p(f"    p   = {TOY_P}          two small primes, kept secret")
    p(f"    q   = {TOY_Q}")
    p(f"    n   = p*q = {TOY_N}     the modulus            <- PUBLIC")
    p(f"    phi = (p-1)(q-1) = {TOY_PHI}  <- secret")
    p(f"    e   = {TOY_E}          public exponent        <- PUBLIC")
    p(f"    d   = {TOY_D}        private exponent       <- SECRET")
    p()
    p(f"    check: e*d mod phi = {TOY_E}*{TOY_D} mod {TOY_PHI} = "
      f"{(TOY_E * TOY_D) % TOY_PHI}")
    p("    That '1' is why the two operations cancel out:")
    p("        (m^d)^e = m^(d*e) = m^1 = m   (mod n)")
    p()
    p("    Public key  = (n, e) = "
      f"({TOY_N}, {TOY_E})       -> published")
    p("    Private key = (n, d) = "
      f"({TOY_N}, {TOY_D})     -> never leaves the signer")
    p()
    step("Sign a number")
    value = 42
    signature = toy_sign(value)
    p(f"    value to sign  m = {value}")
    p(f"    signature      s = m^d mod n = {value}^{TOY_D} mod {TOY_N} "
      f"= {signature}")
    p()
    step("Verify it")
    recovered = toy_verify(signature)
    p(f"    recovered      = s^e mod n = {signature}^{TOY_E} mod {TOY_N} "
      f"= {recovered}")
    p(f"    equals m ({value})?  {'YES — signature valid' if recovered == value else 'no'}")
    p()
    p("    Notice what verification actually did: it did not 'check' the")
    p("    signature against anything. It RECOVERED a number and we")
    p("    compared it to what we expected. Hold on to that — stage 4")
    p("    turns it into an attack.")
    p()
    step("Now tamper with it")
    for bad in (signature + 1, signature - 1):
        p(f"    s = {bad:<6} -> recovers {toy_verify(bad):<6} "
          f"(expected {value}) -> REJECTED")
    p()
    p("    One step away from the right signature and the recovered value")
    p("    is nowhere near 42. There is no 'close'; you either have d or")
    p("    you do not.")
    p()
    p("    And to GET d, an attacker must factor n back into p and q.")
    p(f"    For n={TOY_N} that is instant. For a real 2048-bit n it is the")
    p("    reason RSA still stands.")


# --- STAGE 3 — sign the hash, not the message ---------------------------------

def stage3() -> None:
    head(3, 6, "Sign the hash, not the message")
    p("Stage 2 signed the number 42. Real messages are not numbers, and")
    p("they are big. Two problems appear immediately.")
    p()
    step("Problem 1: the message must be smaller than n")
    p(f"    Our modulus n = {TOY_N} holds values 0..{TOY_N - 1}. That is "
      f"{TOY_N.bit_length()} bits.")
    p("    A 2048-bit key does better — 256 bytes — but a contract, an")
    p("    email or a software release is far larger than that.")
    p()
    p("    Splitting the message into blocks and signing each one is a")
    p("    trap: an attacker can then DELETE, REORDER or REPLAY individual")
    p("    blocks, and every one still verifies. The signature has to")
    p("    cover the whole message at once.")
    p()
    step("Problem 2: signing is slow")
    p("    m^d mod n on a 2048-bit key is heavy. You want to do it exactly")
    p("    once, on something small, whatever the message size.")
    p()
    step("The fix: hash first")
    p("    A hash turns any message into a short, fixed-size fingerprint")
    p("    (week 4, stages 1-3). Sign THAT.")
    p()
    p("        signature = Sign(private, H(message))")
    p()
    p("    Constant cost, always fits, and the whole message is covered —")
    p("    change one byte anywhere and H changes completely.")
    p()
    diagram(_DIAG_PIPELINE)
    step("Watch it work")
    message = b"transfer 100 to alice"
    digest = toy_hash(message)
    signature = toy_sign(digest)
    p(f'    message   = "{message.decode()}"')
    p(f"    H(message)= {digest}   (SHA-256 reduced into our tiny n)")
    p(f"    signature = H^d mod n = {signature}")
    p()
    p("    A verifier who has only the public key and the message:")
    p(f"      1. hashes the message themselves      -> {toy_hash(message)}")
    p(f"      2. recovers the signed value          -> {toy_verify(signature)}")
    p(f"      3. equal?  {'YES — genuine' if toy_hash(message) == toy_verify(signature) else 'no'}")
    p()
    step("Change one character")
    tampered = b"transfer 900 to alice"
    p(f'    message   = "{tampered.decode()}"     (100 -> 900)')
    p(f"      1. verifier hashes it                 -> {toy_hash(tampered)}")
    p(f"      2. recovers the signed value          -> {toy_verify(signature)}")
    p(f"      3. equal?  {'yes' if toy_hash(tampered) == toy_verify(signature) else 'NO — rejected'}")
    p()
    p("    The signature is bound to the fingerprint, so it is bound to")
    p("    every byte of the message.")
    p()
    p("    This is also where week 4's earlier stages start to matter. If")
    p("    the hash is not collision resistant, an attacker who finds two")
    p("    messages with the SAME fingerprint gets a signature on one and")
    p("    reuses it on the other. That is not theory: it is exactly how")
    p("    forged MD5 certificates were built. A signature is only as")
    p("    strong as its hash.")

    step("So what exactly gets hashed?")
    p("'Sign the message' is too loose to implement. What you actually")
    p("sign is a precisely defined byte string — often called the SIGNING")
    p("INPUT or the to-be-signed data — and every real format specifies")
    p("it exactly, because signer and verifier must rebuild the identical")
    p("bytes or the hash will not match.")
    p()
    p("    X.509 certificate   the TBSCertificate: the DER encoding of")
    p("                        subject, public key, validity and")
    p("                        extensions. NOT the whole certificate —")
    p("                        that contains the signature itself.")
    p()
    p("    JWT / JWS           the ASCII bytes")
    p("                          base64url(header) + '.' + base64url(payload)")
    p("                        Note the header is INSIDE the signature, so")
    p("                        the declared algorithm is covered too")
    p("                        (stage 6 shows why that is not sufficient).")
    p()
    p("    TLS 1.3             a context string plus a hash of the whole")
    p("                        handshake transcript so far, so the")
    p("                        signature is bound to that one connection.")
    p()
    p("    code signing        the digest of the file, or of a manifest")
    p("                        listing the digests of many files.")
    p()
    p("    git commit          the raw bytes of the commit object.")
    p()
    p("Two rules follow, and most signature bugs are a violation of one:")
    p()
    p("  1. THE ENCODING MUST BE CANONICAL. If the same logical content")
    p("     can be written two ways — key order, whitespace, optional")
    p("     fields — signer and verifier can disagree. Never re-serialise")
    p("     a parsed object and hash the result; hash the bytes exactly")
    p("     as they arrived. This is why webhook verification insists on")
    p("     the RAW request body rather than the JSON you parsed from it.")
    p()
    p("  2. SIGN WHAT YOU VERIFY, VERIFY WHAT YOU USE. The data your")
    p("     program acts on must be the data the signature covered. If")
    p("     you verify one copy and then read fields from another, the")
    p("     signature is decoration. XML signature wrapping is the")
    p("     classic version: the signature legitimately covers an element")
    p("     the application never looks at, while it reads an unsigned")
    p("     one the attacker added.")


# --- STAGE 4 — three forgeries against textbook signatures --------------------

def stage4() -> None:
    head(4, 6, "Why 'hash then m^d' is still not enough")
    p("Stage 3 looks finished: hash, then raise to d. Real RSA signatures")
    p("do one more thing — PADDING — and this stage is why. Three attacks,")
    p("each defeated by a different part of what padding adds.")
    p()

    step("Attack 1: existential forgery — sign nothing, get a valid pair")
    p("    Verification RECOVERS a value (stage 2). So work backwards:")
    p("    pick any signature you like, and see what it happens to sign.")
    p()
    forged_sig = 1234
    implied = toy_verify(forged_sig)
    p(f"    pick a signature at random   s = {forged_sig}")
    p(f"    what does it 'sign'?         m = s^e mod n = {implied}")
    p(f"    is (m={implied}, s={forged_sig}) a valid pair?  "
      f"{'YES' if toy_verify(forged_sig) == implied else 'no'}")
    p()
    p("    No private key was used. The attacker cannot CHOOSE the message")
    p("    — they get whatever falls out — which is why it is called")
    p("    'existential' forgery: a valid signature exists on SOME message.")
    p()
    p("    Harmless if the message must be readable English. Dangerous the")
    p("    moment a system signs raw values: keys, tokens, random")
    p("    challenges, nonces. Hashing helps here already: the attacker")
    p(f"    would need a message whose hash equals {implied}, and finding")
    p("    one is a preimage attack.")
    p()

    step("Attack 2: multiplicative forgery — combine two signatures")
    p("    RSA is multiplicative, which is elegant and, unpadded, fatal:")
    p()
    p("        sig(a) * sig(b) = (a^d)(b^d) = (a*b)^d = sig(a*b)   mod n")
    p()
    a, b = 7, 11
    sig_a, sig_b = toy_sign(a), toy_sign(b)
    combined = (sig_a * sig_b) % TOY_N
    product = (a * b) % TOY_N
    sig_product = toy_sign(product)
    p(f"    the signer signs two harmless values:")
    p(f"        sig({a})  = {sig_a}")
    p(f"        sig({b}) = {sig_b}")
    p(f"    the attacker just multiplies them:")
    p(f"        {sig_a} * {sig_b} mod {TOY_N} = {combined}")
    p(f"    and that is a genuine signature on {a}*{b} = {product}:")
    p(f"        sig({product}) computed with the real private key = {sig_product}")
    p(f"        equal?  {'YES — forged without the key' if combined == sig_product else 'no'}")
    p()
    p("    The attacker produced a signature on a message the signer never")
    p("    saw, from two they did sign. Hashing breaks this one too: to")
    p("    use it you would need a real message m3 with H(m3) = H(m1)*H(m2)")
    p("    mod n, and you cannot steer a hash to a chosen value.")
    p()

    step("Attack 3: the blank cheque — no hash at all")
    p("    If a system signs the raw message rather than its hash, and an")
    p("    attacker can get ANY value signed, they can often get the value")
    p("    they actually want signed. 'Sign this random challenge to prove")
    p("    you are you' becomes 'sign this transfer instruction'.")
    p()
    p("    Never sign something you have not looked at, and never reuse a")
    p("    signing key across two purposes. Sign a hash, and hash a")
    p("    structure that says what the message IS.")
    p()

    step("What padding adds")
    p("    Real RSA signatures do not sign H(m). They sign a PADDED")
    p("    encoding of it, which fills the modulus with structure:")
    p()
    p("      PKCS#1 v1.5   0x00 01 FF FF ... FF 00 || algorithm-id || H(m)")
    p("                    deterministic; the FF run and the algorithm id")
    p("                    make random or multiplied values fail to decode")
    p()
    p("      PSS           adds a random salt and a mask; the same message")
    p("                    signed twice gives two different signatures,")
    p("                    both valid. Has a security proof. Preferred.")
    p()
    p("    Both defeat all three attacks above, for the same reason: a")
    p("    forged or combined value is overwhelmingly unlikely to decode")
    p("    into the exact required structure. Verification stops being")
    p("    'recover a number and compare' and becomes 'recover a number,")
    p("    check its SHAPE, then compare'.")
    p()
    p("    Stage 5 uses both, with real keys.")


# --- STAGE 5 — real signatures ------------------------------------------------

def stage5() -> None:
    head(5, 6, "Real signatures: 2048-bit keys, PKCS#1 v1.5 and PSS")
    p(f"Everything above used a {TOY_N.bit_length()}-bit modulus so the "
      f"numbers would fit on")
    p("the screen. Now the real thing, via pycryptodome.")
    p()
    step("Generate a key pair")
    p("    (a moment — it is searching for two 1024-bit primes)")
    key = RSA.generate(2048)
    pub = key.publickey()
    p(f"    modulus n  : {key.n.bit_length()} bits")
    p(f"    public  e  : {key.e}")
    p(f"    private d  : {key.d.bit_length()} bits (never leaves the signer)")
    p()
    p("    The public half is what you hand out:")
    pem = pub.export_key().decode().splitlines()
    p(f"      {pem[0]}")
    p(f"      {pem[1][:44]}...")
    p(f"      {pem[-1]}")
    p()

    message = b"transfer 100 to alice"
    digest = SHA256.new(message)
    p(f'    message      = "{message.decode()}"')
    p(f"    SHA-256      = {digest.hexdigest()[:48]}...")
    p()

    step("PKCS#1 v1.5 — deterministic")
    sig1 = pkcs1_15.new(key).sign(digest)
    sig2 = pkcs1_15.new(key).sign(SHA256.new(message))
    p(f"    signature    = {sig1.hex()[:48]}...")
    p(f"    length       = {len(sig1)} bytes = the modulus size, always")
    p(f"    sign twice, same signature?  "
      f"{'YES — deterministic' if sig1 == sig2 else 'no'}")
    p()
    p("    Verify with the PUBLIC key only:")
    try:
        pkcs1_15.new(pub).verify(SHA256.new(message), sig1)
        p("        verify(message, sig)          -> VALID")
    except (ValueError, TypeError):
        p("        verify(message, sig)          -> rejected")
    p()

    step("Does it actually reject bad input?")
    p("    A verifier that says yes to everything passes every happy-path")
    p("    test ever written. So test the failures.")
    p()
    tampered = b"transfer 900 to alice"
    try:
        pkcs1_15.new(pub).verify(SHA256.new(tampered), sig1)
        p("      1. tampered message           -> ACCEPTED (bad!)")
    except (ValueError, TypeError):
        p("      1. tampered message           -> rejected")
    bad_sig = bytearray(sig1)
    bad_sig[-1] ^= 0x01
    try:
        pkcs1_15.new(pub).verify(SHA256.new(message), bytes(bad_sig))
        p("      2. signature, one bit flipped -> ACCEPTED (bad!)")
    except (ValueError, TypeError):
        p("      2. signature, one bit flipped -> rejected")
    other = RSA.generate(2048)
    try:
        pkcs1_15.new(other.publickey()).verify(SHA256.new(message), sig1)
        p("      3. checked against another key-> ACCEPTED (bad!)")
    except (ValueError, TypeError):
        p("      3. checked against another key-> rejected")
    p()
    p("    Number 3 is the one people forget. A signature only means")
    p("    something if you check it against the key you EXPECTED. Verify")
    p("    against whatever key came with the message and an attacker")
    p("    simply sends their own key and their own signature.")
    p()

    step("PSS — randomised, and preferred")
    pss1 = pss.new(key).sign(SHA256.new(message))
    pss2 = pss.new(key).sign(SHA256.new(message))
    p(f"    signature #1 = {pss1.hex()[:48]}...")
    p(f"    signature #2 = {pss2.hex()[:48]}...")
    p(f"    same message, same key, identical signatures?  "
      f"{'yes' if pss1 == pss2 else 'NO — a fresh random salt each time'}")
    ok = []
    for s in (pss1, pss2):
        try:
            pss.new(pub).verify(SHA256.new(message), s)
            ok.append(True)
        except (ValueError, TypeError):
            ok.append(False)
    p(f"    do both verify?  {'YES — both are genuine' if all(ok) else 'no'}")
    p()
    p("    Two different valid signatures on one message is not a bug. It")
    p("    is the randomised padding doing its job, and PSS has a security")
    p("    proof that PKCS#1 v1.5 lacks. Choose PSS for anything new; v1.5")
    p("    persists because certificates and protocols already specify it.")
    p()

    step("What a signature still does not give you")
    p("    A signature says: the holder of this private key approved these")
    p("    exact bytes. It does not say WHEN, and it does not say ONCE.")
    p()
    p("      replay      a captured signed message stays valid forever.")
    p("                  Include a timestamp or nonce INSIDE the signed")
    p("                  data — outside it, an attacker just edits it.")
    p("      revocation  a stolen key signs things that verify perfectly.")
    p("                  This is what certificate revocation is for.")
    p("      trust       a valid signature from an unknown key proves")
    p("                  nothing. Binding a key to an identity is what")
    p("                  certificates do — see week 5.")
    p()
    p("    And in practice: use a library. Every attack in stage 4 is a")
    p("    solved problem, and every one of them has been re-introduced by")
    p("    somebody implementing RSA signatures themselves.")


# --- STAGE 6 — HMAC and signatures together ----------------------------------

def stage6() -> None:
    head(6, 6, "HMAC and signatures together: JWTs, and the confusion attack")
    p("A natural question after stage 1: do we ever SIGN an HMAC?")

    step("A. The short answer: no")
    p("Signing an HMAC tag is not a thing, and it is worth being clear")
    p("about why, because the reason is the whole design:")
    p()
    p("    sig = Sign(private, HMAC(k, m))")
    p()
    p("To check that, a verifier needs the public key AND k, because")
    p("without k they cannot recompute the HMAC and see if the signed")
    p("value is right. But needing a shared secret is precisely the")
    p("limitation the signature was there to remove. You have paid for a")
    p("signature and kept HMAC's constraint.")
    p()
    p("It adds no security either. The signature already covers whatever")
    p("you feed it, so signing H(m) — stage 3 — is strictly better: same")
    p("cost, no shared secret, anyone can verify.")
    p()
    p("    sign a HASH   yes, always. That is the standard construction.")
    p("    sign a MAC    no. Redundant, and it re-introduces the secret.")
    p()
    p("HMAC and signatures are ALTERNATIVES to each other, chosen by who")
    p("needs to verify. They are not layers.")

    step("B. But they do meet: same token, two algorithms")
    p("The place students actually meet both is the JSON Web Token. A JWT")
    p("is three base64url segments:")
    p()
    p("    base64url(header) . base64url(payload) . signature")
    p()
    p("The signature covers the FIRST TWO segments joined by a dot —")
    p("header and payload together, exactly as they appear on the wire:")
    p()
    p("    signing input = base64url(header) + '.' + base64url(payload)")
    p()
    p("So the header, including its algorithm field, is inside the")
    p("signature. That sounds like it should prevent tampering with the")
    p("algorithm. Part C is why it does not.")
    p()
    p("The SAME token format is used with either primitive:")
    p()
    p("    HS256   signature = HMAC-SHA256(shared_secret, h + '.' + p)")
    p("    RS256   signature = RSA-PKCS#1v1.5( SHA256(h + '.' + p) )")
    p()
    claims = {"user": "guest", "role": "viewer"}
    shared = b"a-shared-secret-both-sides-hold"
    key = RSA.generate(2048)
    pub_pem = key.publickey().export_key()

    h1, p1, signing_input1 = jwt_parts(claims, "HS256")
    hs_sig = b64u(hmac.new(shared, signing_input1, hashlib.sha256).digest())
    hs_token = signing_input1 + b"." + hs_sig

    h2, p2, signing_input2 = jwt_parts(claims, "RS256")
    rs_sig = b64u(pkcs1_15.new(key).sign(SHA256.new(signing_input2)))
    rs_token = signing_input2 + b"." + rs_sig

    p(f"    claims = {claims}")
    p()
    p(f"    HS256 token ({len(hs_token)} bytes)")
    p(f"      {hs_token[:56].decode()}...")
    p(f"      verified by: anyone holding the shared secret")
    p(f"                   (so anyone who can verify can also issue)")
    p()
    p(f"    RS256 token ({len(rs_token)} bytes)")
    p(f"      {rs_token[:56].decode()}...")
    p(f"      verified by: anyone at all, using the public key")
    p(f"                   (only the issuer can create one)")
    p()
    p("    Note the size difference: the RSA signature is 256 bytes before")
    p("    encoding, the HMAC tag 32. That is the price of public")
    p("    verifiability, and it is usually worth paying at an API edge.")
    p()
    p("    Choose by asking WHO VERIFIES. One service checking its own")
    p("    session cookies -> HS256. An identity provider issuing tokens")
    p("    that dozens of unrelated services must check -> RS256, so the")
    p("    signing key never leaves the issuer.")

    step("C. Mixing them up: the algorithm confusion attack")
    p("Because one field selects between the two, a verifier can be")
    p("tricked into using the wrong one. This is a real and recurring CVE")
    p("class, and the bug is a single line:")
    p()
    diagram("""
      def verify(token, key):
          alg = json.loads(header)["alg"]     <-- THE BUG
          if alg == "RS256": ...RSA verify with key...
          if alg == "HS256": ...HMAC verify with key...""")
    p("The algorithm is read from the token. The token is supplied by the")
    p("attacker. So the attacker chooses which branch runs.")
    p()
    p("Now watch what that allows. The server issues RS256 and publishes")
    p("its public key — it is public, that is the point. The attacker:")
    p()
    p("   1. takes the PUBLIC key bytes")
    p("   2. builds a token whose header says HS256")
    p("   3. HMACs it, using the public key AS THE SHARED SECRET")
    p()
    p("The naive server sees alg=HS256, and HMACs with its `key` variable")
    p("— which holds the public key. Both sides used the same value, so")
    p("the tag matches.")
    p()

    def naive_verify(token: bytes, key_material: bytes) -> bool:
        """Vulnerable: trusts the token's own 'alg' field."""
        h, pl, sig = token.split(b".")
        alg = json.loads(b64u_decode(h))["alg"]
        if alg == "RS256":
            try:
                pkcs1_15.new(RSA.import_key(key_material)).verify(
                    SHA256.new(h + b"." + pl), b64u_decode(sig))
                return True
            except (ValueError, TypeError):
                return False
        if alg == "HS256":
            expect = b64u(hmac.new(key_material, h + b"." + pl,
                                   hashlib.sha256).digest())
            return hmac.compare_digest(expect, sig)
        return False

    def safe_verify(token: bytes, public_key: bytes) -> bool:
        """Fixed: the algorithm is decided by the SERVER, not the token."""
        h, pl, sig = token.split(b".")
        if json.loads(b64u_decode(h)).get("alg") != "RS256":
            return False                      # pinned, before any crypto runs
        try:
            pkcs1_15.new(RSA.import_key(public_key)).verify(
                SHA256.new(h + b"." + pl), b64u_decode(sig))
            return True
        except (ValueError, TypeError):
            return False

    p(f"    the genuine RS256 token verifies?  "
      f"{'YES' if naive_verify(rs_token, pub_pem) else 'no'}")
    p()
    ah, ap, asigning = jwt_parts({"user": "guest", "role": "admin"}, "HS256")
    asig = b64u(hmac.new(pub_pem, asigning, hashlib.sha256).digest())
    evil_token = asigning + b"." + asig
    p(f"    attacker's forged token, claims = "
      "{'user': 'guest', 'role': 'admin'}")
    p(f"      {evil_token[:56].decode()}...")
    p(f"      secret used = the server's own PUBLIC key")
    p()
    p(f"    naive verifier accepts it?  "
      f"{'YES — guest is now admin' if naive_verify(evil_token, pub_pem) else 'no'}")
    p(f"    fixed verifier accepts it?  "
      f"{'yes' if safe_verify(evil_token, pub_pem) else 'NO — rejected'}")
    p(f"    fixed verifier still accepts the real one?  "
      f"{'YES' if safe_verify(rs_token, pub_pem) else 'no'}")
    p()
    p("    The RSA maths was never broken. The attacker never factored")
    p("    anything. They just got the verifier to run a different")
    p("    algorithm — one whose 'secret' was published on purpose.")
    p()
    p("    THE FIX: the verifier decides the algorithm, from its own")
    p("    configuration, before any cryptography runs. Never read it out")
    p("    of the thing you are checking. If you support several, bind")
    p("    each KEY to exactly one algorithm.")
    p()
    p("    This is the same bug as week 7's RBAC demo, where a route read")
    p("    the caller's role out of a request header: an input the")
    p("    attacker controls was used to make a security decision. Here")
    p("    the input happens to be a crypto algorithm name.")

    step("D. The even simpler version: alg=none")
    none_h, none_p, _ = jwt_parts({"user": "guest", "role": "admin"}, "none")
    p("    The JWT spec has an 'unsecured' mode, alg=none, with an empty")
    p("    signature. A verifier that honours it accepts anything:")
    p()
    p(f"      {(none_h + b'.' + none_p + b'.').decode()[:56]}...")
    p()
    p(f"    naive verifier (rejects unknown alg)?  "
      f"{'accepted' if naive_verify(none_h + b'.' + none_p + b'.', pub_pem) else 'rejected'}")
    p("    Ours happens to reject it by falling through, but libraries")
    p("    that implemented the spec faithfully did not — hence a long")
    p("    string of advisories. Pinning the algorithm fixes this one too.")

    step("E. Where both genuinely coexist")
    p("So they are alternatives — but a real protocol often uses both, in")
    p("different roles, and that is not a contradiction:")
    p()
    p("  TLS      the handshake uses a SIGNATURE, once, to prove the")
    p("           server owns its certificate's key. Every record after")
    p("           that is protected by a symmetric MAC/AEAD, because")
    p("           there is now a shared secret and MACs are ~1000x faster.")
    p("           Signature for identity; MAC for bulk traffic.")
    p()
    p("  HKDF     key derivation built ON TOP of HMAC. The shared secret")
    p("           TLS just negotiated is expanded into per-direction keys")
    p("           by repeated HMAC calls.")
    p()
    p("  JWT/JWS  as above: one format, either primitive, chosen by who")
    p("           must verify.")
    p()
    p("A last piece of vocabulary, because it causes real confusion:")
    p("plenty of things called 'signatures' in the wild are HMACs.")
    p("AWS Signature V4 is a chain of HMAC-SHA256. Stripe and GitHub")
    p("webhook 'signatures' are HMACs. They need a shared secret and give")
    p("no non-repudiation — the name is marketing, not mathematics. When")
    p("you read 'signature' in a protocol, check which one it means.")


# --- recap + runner -----------------------------------------------------------

def recap() -> None:
    print("\n")
    p("-" * 54)
    p("RECAP")
    p("-" * 54)
    print()
    p("1. Sign with the private key, verify with the public one — the")
    p("   mirror of encryption.")
    p("2. HMAC proves authenticity to someone who shares your secret; a")
    p("   signature proves it to everyone, and adds non-repudiation.")
    p("3. Always sign the HASH: it fits, it is fast, it covers everything.")
    p("4. Raw 'hash then m^d' is forgeable (existential, multiplicative).")
    p("   Padding is not optional. Prefer PSS; PKCS#1 v1.5 is legacy.")
    p("5. Verify against the key you EXPECTED, and put freshness inside")
    p("   the signed data. A signature has no opinion about time.")
    p("6. You do not sign an HMAC - they are alternatives, chosen by who")
    p("   must verify. Where both appear (JWT), pin the algorithm in the")
    p("   VERIFIER; reading it from the token is how RS256 becomes HS256")
    p("   keyed with your own public key.")
    print()


def main() -> None:
    print("\n  RSA DIGITAL SIGNATURES - a 6-stage tutorial")
    if sys.stdin.isatty():
        p("Move with: Enter=next, b=back, a stage number to jump, q=quit.")

    stages = [stage1, stage2, stage3, stage4, stage5, stage6]
    i = 0
    while 0 <= i < len(stages):
        stages[i]()
        action = nav(i, len(stages))
        if action == "quit":
            print("  bye")
            return
        elif action == "next":
            i += 1
        elif action == "prev":
            i = max(0, i - 1)
        else:
            i = action
    recap()


if __name__ == "__main__":
    main()
