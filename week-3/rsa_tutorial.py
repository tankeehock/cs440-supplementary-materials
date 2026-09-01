# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "pycryptodome",
# ]
# ///
"""
================================================================================
RSA ENCRYPTION & DECRYPTION — A STEP-BY-STEP TUTORIAL
================================================================================

Run with:   uv run rsa_tutorial.py
      or:   pip install pycryptodome && python rsa_tutorial.py

This script teaches RSA in three parts:

  PART 1 — "Textbook RSA" built from scratch with tiny primes, so every
           number in the calculation is small enough to verify by hand.

  PART 2 — Why textbook RSA is INSECURE in practice (determinism,
           malleability, small-message attacks).

  PART 3 — Real-world RSA using pycryptodome with OAEP padding, the way
           RSA is actually deployed.

  PART 4 — ENCODING vs ENCRYPTION: why Base64/hex are NOT encryption,
           and how encoding is used to transport binary ciphertext
           safely over text-only channels (email, JSON, PEM files).

Pedagogical design choices:
  * All explanations are printed to the console, so the output itself
    is the tutorial. Students can read the transcript top-to-bottom.
  * Every math step shows the formula first, then the substituted
    values, then the result.
  * Helper functions (extended Euclidean algorithm, modular inverse,
    square-and-multiply) are implemented manually before we "cheat"
    with Python's built-ins, so nothing is a black box.
================================================================================
"""

import base64

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256


# ------------------------------------------------------------------------------
# Pretty-printing helpers — these exist only to make the console output
# readable. They contain no cryptographic logic.
# ------------------------------------------------------------------------------

def banner(title: str) -> None:
    """Print a large section banner."""
    print()
    print("=" * 78)
    print(f"  {title}")
    print("=" * 78)


def section(title: str) -> None:
    """Print a smaller sub-section header."""
    print()
    print(f"--- {title} " + "-" * max(0, 72 - len(title)))
    print()


def explain(text: str) -> None:
    """Print an indented explanation paragraph."""
    for line in text.strip().splitlines():
        print(f"    {line}")
    print()


# ------------------------------------------------------------------------------
# PART 1 SUPPORT FUNCTIONS — number theory from scratch
# ------------------------------------------------------------------------------

def gcd_verbose(a: int, b: int) -> int:
    """
    Euclidean algorithm for the greatest common divisor, printing each step.

    The idea: gcd(a, b) == gcd(b, a mod b). We repeat until the remainder
    is 0; the last non-zero remainder is the gcd.
    """
    print(f"    Computing gcd({a}, {b}) with the Euclidean algorithm:")
    while b != 0:
        q, r = divmod(a, b)
        print(f"      {a} = {b} x {q} + {r}")
        a, b = b, r
    print(f"    => gcd = {a}")
    print()
    return a


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Extended Euclidean algorithm.

    Returns (g, x, y) such that:  a*x + b*y = g = gcd(a, b)

    We need this to compute the modular inverse: if gcd(e, phi) == 1,
    then x (the coefficient of e) is the inverse of e modulo phi.
    """
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    # Back-substitution step: unwind the recursion.
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y


def mod_inverse_verbose(e: int, phi: int) -> int:
    """
    Find d such that (d * e) mod phi == 1, showing the reasoning.

    d is the PRIVATE exponent — the heart of the private key.
    """
    g, x, _ = extended_gcd(e, phi)
    if g != 1:
        raise ValueError("e and phi(n) are not coprime — pick a different e")
    d = x % phi  # normalize into the range [0, phi)
    print(f"    Extended Euclidean algorithm gives us x = {x} such that")
    print(f"      {e} * ({x}) + {phi} * (...) = 1")
    print(f"    Normalizing x into the range [0, {phi}):")
    print(f"      d = {x} mod {phi} = {d}")
    print()
    print(f"    VERIFY: (d * e) mod phi = ({d} * {e}) mod {phi} "
          f"= {(d * e) % phi}   (must be 1) ✓")
    print()
    return d


def power_mod_verbose(base: int, exp: int, mod: int, label: str) -> int:
    """
    Square-and-multiply modular exponentiation, printing each iteration.

    Computing base^exp directly would produce astronomically large numbers.
    Instead we process the exponent bit-by-bit, squaring as we go and
    reducing mod n at every step. This is exactly what real crypto
    libraries do (with constant-time hardening added).
    """
    print(f"    Computing {label} = {base}^{exp} mod {mod} "
          f"using square-and-multiply:")
    print(f"      exponent {exp} in binary = {bin(exp)[2:]}")
    result = 1
    b = base % mod
    e = exp
    step = 1
    while e > 0:
        if e & 1:
            result = (result * b) % mod
            print(f"      step {step}: bit=1 -> multiply: result = {result}")
        else:
            print(f"      step {step}: bit=0 -> skip multiply "
                  f"(result stays {result})")
        b = (b * b) % mod
        e >>= 1
        step += 1
    print(f"    => {label} = {result}")
    print()
    return result


# ------------------------------------------------------------------------------
# PART 1 — TEXTBOOK RSA WITH TINY PRIMES
# ------------------------------------------------------------------------------

def part1_textbook_rsa() -> None:
    banner("PART 1: TEXTBOOK RSA WITH TINY PRIMES (all math verifiable by hand)")

    explain("""
RSA is an ASYMMETRIC cipher: the key used to encrypt (public key) is
different from the key used to decrypt (private key). Anyone may know
the public key; only the owner knows the private key.

Security rests on a mathematical asymmetry:
  * Multiplying two primes p and q to get n is EASY.
  * Recovering p and q from n (factoring) is HARD when n is large.

We will now build a full keypair using tiny primes so that every
intermediate value fits on one line.
""")

    # ---- STEP 1: choose two primes -----------------------------------------
    section("STEP 1: Choose two distinct primes, p and q")
    p, q = 61, 53
    print(f"    p = {p}")
    print(f"    q = {q}")
    explain("""
In real RSA, p and q are randomly generated primes of ~1024+ bits each.
Here we use tiny primes purely for teaching. Keeping p and q SECRET is
essential — anyone who learns them can derive the private key instantly.
""")

    # ---- STEP 2: compute the modulus n --------------------------------------
    section("STEP 2: Compute the modulus n = p x q")
    n = p * q
    print(f"    n = {p} x {q} = {n}")
    explain("""
n is public. It is the 'modulus' — all encryption and decryption
arithmetic happens modulo n. Its bit-length is what people mean by
'RSA-2048': an n that is 2048 bits long.
""")

    # ---- STEP 3: compute Euler's totient ------------------------------------
    section("STEP 3: Compute Euler's totient phi(n) = (p-1) x (q-1)")
    phi = (p - 1) * (q - 1)
    print(f"    phi(n) = ({p}-1) x ({q}-1) = {p-1} x {q-1} = {phi}")
    explain("""
phi(n) counts the integers below n that are coprime to n. It is the
group order that makes the RSA identity work:

    m^(k*phi(n) + 1)  ≡  m   (mod n)      [Euler's theorem]

phi(n) must be kept SECRET: computing it requires knowing p and q, and
knowing phi(n) lets an attacker compute the private exponent d.
""")

    # ---- STEP 4: choose the public exponent e -------------------------------
    section("STEP 4: Choose the public exponent e")
    e = 17
    print(f"    Candidate e = {e}")
    print(f"    Requirement: 1 < e < phi(n) and gcd(e, phi(n)) = 1")
    print()
    gcd_verbose(e, phi)
    explain(f"""
gcd(e, phi) = 1, so e = {e} is valid. In the real world e = 65537
(0x10001) is the standard choice: it is prime, and its binary form
10000000000000001 has only two 1-bits, making encryption fast.
""")

    # ---- STEP 5: compute the private exponent d -----------------------------
    section("STEP 5: Compute the private exponent d = e^(-1) mod phi(n)")
    explain(f"""
We need d such that:  (d x e) mod phi(n) = 1
i.e. d is the MODULAR MULTIPLICATIVE INVERSE of e = {e} modulo phi = {phi}.
The extended Euclidean algorithm finds it efficiently.
""")
    d = mod_inverse_verbose(e, phi)

    # ---- STEP 6: state the keypair ------------------------------------------
    section("STEP 6: The keypair")
    print(f"    PUBLIC KEY  (share freely):   (n = {n}, e = {e})")
    print(f"    PRIVATE KEY (never share):    (n = {n}, d = {d})")
    explain("""
Discard-or-protect list: p, q, phi(n), and d must all remain secret.
Leaking ANY of them breaks the key.
""")

    # ---- STEP 7: encrypt ----------------------------------------------------
    section("STEP 7: Encrypt a message   c = m^e mod n")
    m = 65  # ASCII 'A'
    print(f"    Plaintext: the letter 'A', encoded as its ASCII value m = {m}")
    print(f"    (RSA operates on NUMBERS — text must first be encoded, and")
    print(f"     m must satisfy 0 <= m < n = {n})")
    print()
    c = power_mod_verbose(m, e, n, "ciphertext c")
    print(f"    ENCRYPTED: 'A' ({m}) --> ciphertext {c}")
    print()

    # ---- STEP 8: decrypt ----------------------------------------------------
    section("STEP 8: Decrypt   m = c^d mod n")
    explain(f"""
Decryption raises the ciphertext to the PRIVATE exponent d = {d}.
Why does this undo encryption? Because e*d ≡ 1 (mod phi), so:

    c^d = (m^e)^d = m^(e*d) = m^(k*phi + 1) ≡ m   (mod n)

That final step is Euler's theorem — the entire correctness of RSA
compresses into that one congruence.
""")
    recovered = power_mod_verbose(c, d, n, "recovered m")
    ch = chr(recovered)
    print(f"    DECRYPTED: {c} --> {recovered} --> '{ch}'")
    status = "SUCCESS ✓" if recovered == m else "FAILURE ✗"
    print(f"    Round-trip check: {status}")
    print()

    # ---- STEP 9: encrypt a full string, char by char ------------------------
    section("STEP 9: Encrypt a whole word (character by character)")
    word = "RSA"
    print(f"    Plaintext word: '{word}'")
    print()
    ciphertexts = []
    print(f"    {'char':>6} {'ASCII m':>8} {'m^e mod n':>12}")
    print(f"    {'-'*6:>6} {'-'*8:>8} {'-'*12:>12}")
    for chx in word:
        mi = ord(chx)
        ci = pow(mi, e, n)  # Python's built-in 3-arg pow = fast modexp
        ciphertexts.append(ci)
        print(f"    {chx!r:>6} {mi:>8} {ci:>12}")
    print()
    print(f"    Ciphertext sequence: {ciphertexts}")
    print()
    decrypted = "".join(chr(pow(ci, d, n)) for ci in ciphertexts)
    print(f"    Decrypting each value with pow(c, d, n): '{decrypted}'")
    status = "SUCCESS ✓" if decrypted == word else "FAILURE ✗"
    print(f"    Round-trip check: {status}")
    explain("""
NOTE: encrypting character-by-character is done here ONLY to make the
math visible. It is catastrophically insecure — see Part 2.
""")


# ------------------------------------------------------------------------------
# PART 2 — WHY TEXTBOOK RSA IS INSECURE
# ------------------------------------------------------------------------------

def part2_why_textbook_rsa_is_broken() -> None:
    banner("PART 2: WHY TEXTBOOK ('RAW') RSA IS INSECURE")

    p, q, e = 61, 53, 17
    n = p * q

    # ---- Weakness 1: determinism -------------------------------------------
    section("Weakness 1: Determinism enables dictionary attacks")
    explain("""
Raw RSA has no randomness: the same plaintext ALWAYS produces the same
ciphertext. An attacker who knows the public key can pre-encrypt every
likely message and simply look up intercepted ciphertexts.
""")
    print(f"    Attacker builds a lookup table using ONLY the public key "
          f"(n={n}, e={e}):")
    print()
    table = {}
    for chx in "YESNO":
        table[pow(ord(chx), e, n)] = chx
    for ci, chx in table.items():
        print(f"      Enc({chx!r}) = {ci}")
    print()
    intercepted = pow(ord("Y"), e, n)
    print(f"    Intercepted ciphertext: {intercepted}")
    print(f"    Table lookup instantly reveals plaintext: "
          f"{table[intercepted]!r}  — no private key needed!")
    print()

    # ---- Weakness 2: malleability -------------------------------------------
    section("Weakness 2: Malleability (multiplicative homomorphism)")
    explain("""
Raw RSA ciphertexts can be tampered with meaningfully:

    Enc(m1) x Enc(m2) mod n  =  Enc(m1 x m2)

An attacker can transform a ciphertext WITHOUT decrypting it.
Classic example: doubling an encrypted bank-transfer amount.
""")
    amount = 100
    c_amount = pow(amount, e, n)
    print(f"    Victim encrypts amount m = {amount}:  c = {c_amount}")
    c_double = (c_amount * pow(2, e, n)) % n
    print(f"    Attacker computes c' = c x Enc(2) mod n = {c_double}")
    d = pow(e, -1, (p - 1) * (q - 1))  # (attacker doesn't need this;
    #                                     we decrypt only to demonstrate)
    print(f"    Receiver decrypts c' and obtains: {pow(c_double, d, n)}  "
          f"(the amount was doubled in transit!)")
    print()

    # ---- Weakness 3: small message space ------------------------------------
    section("Weakness 3: Tiny keys are factorable in milliseconds")
    explain(f"""
Our toy n = {n} can be factored by trial division instantly, revealing
p and q, hence phi(n), hence d — a total break. Real deployments use
n of 2048–4096 bits, far beyond any known factoring capability.
""")
    for cand in range(2, n):
        if n % cand == 0:
            print(f"    Trial division: n = {n} = {cand} x {n // cand}   "
                  f"— factored, key fully broken.")
            break
    print()

    explain("""
CONCLUSION: real systems never use raw RSA on messages. They use
randomized PADDING (OAEP for encryption, PSS for signatures), and they
typically encrypt only a symmetric session key with RSA, then encrypt
the bulk data with AES — a 'hybrid' scheme. That is Part 3.
""")


# ------------------------------------------------------------------------------
# PART 3 — REAL-WORLD RSA WITH OAEP (pycryptodome)
# ------------------------------------------------------------------------------

def part3_real_world_rsa() -> RSA.RsaKey:
    banner("PART 3: REAL-WORLD RSA — 2048-BIT KEYS + OAEP PADDING")

    # ---- Key generation -----------------------------------------------------
    section("STEP 1: Generate a 2048-bit keypair")
    explain("""
pycryptodome generates two random ~1024-bit primes, multiplies them
into a 2048-bit n, uses e = 65537, and derives d — exactly the Part 1
procedure, just with numbers ~600 digits long.
""")
    key = RSA.generate(2048)
    pub = key.publickey()
    print(f"    Modulus n bit length : {key.n.bit_length()} bits")
    print(f"    Public exponent e    : {key.e}")
    print(f"    First 60 digits of n : {str(key.n)[:60]}...")
    print(f"    First 60 digits of d : {str(key.d)[:60]}...")
    print()
    print("    Public key in PEM format (what you'd actually share):")
    print()
    for line in pub.export_key().decode().splitlines():
        print(f"      {line}")
    print()

    # ---- OAEP encryption ----------------------------------------------------
    section("STEP 2: Encrypt with OAEP padding")
    explain("""
OAEP (Optimal Asymmetric Encryption Padding) fixes Part 2's weaknesses:

  * It mixes the message with a fresh RANDOM seed before the RSA
    operation -> the same plaintext encrypts differently every time.
  * Its structure detects tampering -> malleability attacks fail
    at unpadding.

We use OAEP with SHA-256 as the internal hash.
""")
    message = b"Attack at dawn"
    print(f"    Plaintext: {message!r}")
    print()
    cipher_enc = PKCS1_OAEP.new(pub, hashAlgo=SHA256)
    ct1 = cipher_enc.encrypt(message)
    # A fresh cipher object per encryption (OAEP objects are single-use
    # in spirit; new() also re-reads fresh randomness).
    ct2 = PKCS1_OAEP.new(pub, hashAlgo=SHA256).encrypt(message)
    print(f"    Ciphertext #1 (hex, first 48 chars): {ct1.hex()[:48]}...")
    print(f"    Ciphertext #2 (hex, first 48 chars): {ct2.hex()[:48]}...")
    print(f"    Same plaintext, same key — identical ciphertexts? "
          f"{ct1 == ct2}   <-- randomness defeats dictionary attacks")
    print(f"    Ciphertext length: {len(ct1)} bytes "
          f"(= key size: 2048 bits / 8)")
    print()

    # ---- OAEP decryption ----------------------------------------------------
    section("STEP 3: Decrypt with the private key")
    cipher_dec = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    pt = cipher_dec.decrypt(ct1)
    print(f"    Decrypted: {pt!r}")
    status = "SUCCESS ✓" if pt == message else "FAILURE ✗"
    print(f"    Round-trip check: {status}")
    print()

    # ---- Tamper detection ---------------------------------------------------
    section("STEP 4: Tampering is now DETECTED")
    explain("""
Flip a single bit of the ciphertext. With raw RSA this would silently
decrypt to a different (attacker-influenced) value. With OAEP the
unpadding check fails and decryption raises an error.
""")
    tampered = bytearray(ct1)
    tampered[10] ^= 0x01  # flip one bit
    try:
        PKCS1_OAEP.new(key, hashAlgo=SHA256).decrypt(bytes(tampered))
        print("    Decryption unexpectedly succeeded (should not happen).")
    except ValueError as err:
        print(f"    Decryption REJECTED tampered ciphertext -> "
              f"ValueError: {err}")
    print()

    # ---- Message size limit & hybrid encryption ------------------------------
    section("STEP 5: RSA's size limit --> hybrid encryption in practice")
    max_len = 2048 // 8 - 2 * SHA256.digest_size - 2
    explain(f"""
OAEP with SHA-256 on a 2048-bit key can encrypt at most:

    256 - 2*32 - 2 = {max_len} bytes

RSA is also ~1000x slower than AES. So real protocols (TLS, PGP, ...)
use RSA only to protect a small SYMMETRIC key, then AES encrypts the
actual data:

    1. Generate random 256-bit AES session key
    2. RSA-OAEP encrypt the AES key with the recipient's public key
    3. AES-GCM encrypt the message with the session key
    4. Send both ciphertexts

This 'hybrid' design gets RSA's key-distribution benefits with AES's
speed and unlimited message size.
""")

    too_big = b"X" * (max_len + 1)
    print(f"    Attempting to OAEP-encrypt {len(too_big)} bytes "
          f"(1 over the limit):")
    try:
        PKCS1_OAEP.new(pub, hashAlgo=SHA256).encrypt(too_big)
    except ValueError as err:
        print(f"      -> ValueError: {err}")
    print()

    # Hand the keypair to Part 4 so it can demonstrate ciphertext transport
    # without generating a second key.
    return key


# ------------------------------------------------------------------------------
# PART 4 — ENCODING vs ENCRYPTION
# ------------------------------------------------------------------------------

def part4_encoding_vs_encryption(key: RSA.RsaKey) -> None:
    banner("PART 4: ENCODING vs ENCRYPTION — RELATED-LOOKING, TOTALLY DIFFERENT")

    explain("""
Beginners often confuse these because both 'transform data into
unreadable gibberish'. The distinction is WHAT protects the data:

    ENCODING     transforms data for COMPATIBILITY.
                 Reversible by ANYONE — the 'recipe' (Base64, hex,
                 URL-encoding, ASCII/UTF-8...) is public and there is
                 NO KEY. It provides ZERO confidentiality.

    ENCRYPTION   transforms data for CONFIDENTIALITY.
                 Reversible ONLY with the correct secret key.
                 The algorithm is public (Kerckhoffs's principle);
                 the KEY is what protects the data.

A useful one-liner for teaching:
    Encoding answers  'HOW do I represent these bytes?'
    Encryption answers 'WHO is allowed to read them?'
""")

    # ---- Demo 1: Base64 is trivially reversible ------------------------------
    section("Demo 1: Base64 'protects' nothing — no key required to reverse")
    secret = b"Transfer $5000 to account 12345"
    encoded = base64.b64encode(secret)
    print(f"    Original message : {secret.decode()}")
    print(f"    Base64 encoded   : {encoded.decode()}")
    print()
    print("    It LOOKS scrambled. But an attacker who intercepts it simply")
    print("    runs the public, keyless reverse transformation:")
    print()
    print(f"    base64.b64decode(...) -> {base64.b64decode(encoded).decode()}")
    explain("""
No key. No secret. No security. Anyone who has ever put a Base64 blob
in front of a security analyst knows it gets decoded within seconds
(CyberChef's 'magic' mode does this automatically). Treating encoding
as protection is a real-world vulnerability class: hardcoded 'obfuscated'
credentials in apps and scripts are routinely just Base64.
""")

    # ---- Demo 2: how each transformation maps bytes --------------------------
    section("Demo 2: Same input, three representations vs one encryption")
    msg = b"Hi!"
    b64 = base64.b64encode(msg).decode()
    hx = msg.hex()
    ct = PKCS1_OAEP.new(key.publickey(), hashAlgo=SHA256).encrypt(msg)
    print(f"    Input bytes            : {msg}  = {list(msg)}")
    print()
    print(f"    Hex ENCODING           : {hx}")
    print(f"      (each byte -> 2 hex digits; 72 -> '48', 105 -> '69', ...)")
    print(f"    Base64 ENCODING        : {b64}")
    print(f"      (every 3 bytes -> 4 chars from a public 64-char alphabet)")
    print(f"    RSA-OAEP ENCRYPTION    : {ct.hex()[:48]}... ({len(ct)} bytes)")
    print()
    explain("""
Spot the differences:
  * The encodings are DETERMINISTIC and length-proportional — you can
    read the structure of the input straight through them.
  * The encryption output is key-dependent, randomized (OAEP seed),
    and fixed at the key size (256 bytes) regardless of input length.
  * Reversing the encodings needs a lookup table. Reversing the
    encryption needs the private key.
""")

    # ---- Demo 3: anatomy of raw ciphertext — the bytes that break things -----
    section("Demo 3: Anatomy of raw ciphertext — null bytes & special chars")
    explain("""
Good encryption output is INDISTINGUISHABLE FROM RANDOM BYTES — every
value 0x00–0xFF appears with equal probability (~1/256 each). That is
exactly what makes it strong ciphertext, and exactly what makes it
hostile to text channels. In a 256-byte ciphertext you should EXPECT:

  * ~1 null byte (0x00)          -> string terminators
  * ~1 newline (0x0A) and ~1 CR (0x0D) -> line-ending rewriting
  * ~1 double-quote (0x22), ~1 backslash (0x5C) -> breaks JSON/CSV/SQL
  * ~128 bytes >= 0x80           -> invalid as ASCII, often invalid UTF-8

Below we generate a real OAEP ciphertext and dissect it. (We re-encrypt
until the sample contains both a null and a newline so every failure
can be demonstrated live — the fact that each attempt yields different
bytes is itself proof of OAEP's randomization.)
""")
    probe = b"same plaintext every time"
    for _attempt in range(500):
        ct_raw = PKCS1_OAEP.new(key.publickey(),
                                hashAlgo=SHA256).encrypt(probe)
        if b"\x00" in ct_raw and b"\x0a" in ct_raw:
            break
    print(f"    Sample ciphertext: {len(ct_raw)} bytes "
          f"(found after {_attempt + 1} encryption(s) of the SAME plaintext)")
    print()

    # -- Byte-class census -----------------------------------------------------
    printable = sum(1 for b in ct_raw if 0x20 <= b <= 0x7E)
    control = sum(1 for b in ct_raw if b < 0x20 or b == 0x7F)
    extended = sum(1 for b in ct_raw if b >= 0x80)
    print(f"    Byte-class census of this ciphertext:")
    print(f"      printable ASCII (0x20-0x7E) : {printable:>3} bytes "
          f"({printable * 100 // len(ct_raw)}%)")
    print(f"      control chars   (<0x20,0x7F): {control:>3} bytes "
          f"({control * 100 // len(ct_raw)}%)")
    print(f"      extended        (>=0x80)    : {extended:>3} bytes "
          f"({extended * 100 // len(ct_raw)}%)")
    print(f"    Only ~37% of random bytes are 'safe' text. The rest are")
    print(f"    landmines for any system that treats the data as a string.")
    print()

    # -- Where the dangerous bytes sit ----------------------------------------
    troublemakers = {
        0x00: "NUL  — string terminator in C/C++",
        0x0A: "LF   — 'newline' to text protocols",
        0x0D: "CR   — half of Windows CRLF",
        0x22: '"    — closes JSON/CSV string fields',
        0x5C: "\\    — escape char in JSON/SQL/regex",
        0x27: "'    — closes SQL string literals",
    }
    print(f"    Dangerous bytes present in THIS ciphertext (position: meaning):")
    found_any = False
    for value, meaning in troublemakers.items():
        positions = [i for i, b in enumerate(ct_raw) if b == value][:4]
        if positions:
            found_any = True
            print(f"      0x{value:02x} at offset(s) {positions} : {meaning}")
    if not found_any:
        print("      (none in this sample — rerun and the dice will differ)")
    print()

    # -- Failure 1: it is not valid text at all --------------------------------
    print(f"    FAILURE 1 — Treating ciphertext as UTF-8 text:")
    try:
        ct_raw.decode("utf-8")
        print(f"      (unusually, this sample decoded — rerun to see the error)")
    except UnicodeDecodeError as err:
        print(f"      ct.decode('utf-8') -> UnicodeDecodeError: {err}")
    print(f"      Random high bytes rarely form valid UTF-8 sequences, so")
    print(f"      any layer that decodes the payload as text will throw —")
    print(f"      or worse, silently replace bytes with U+FFFD '\\ufffd',")
    print(f"      destroying the ciphertext irrecoverably.")
    print()

    # -- Failure 2: null-byte truncation ---------------------------------------
    nul_at = ct_raw.index(b"\x00")
    print(f"    FAILURE 2 — Null-byte truncation (C-style strings):")
    print(f"      First 0x00 sits at offset {nul_at}.")
    print(f"      A null-terminated consumer (C strlen/strcpy, some legacy")
    print(f"      APIs, older DB text columns) sees only {nul_at} of "
          f"{len(ct_raw)} bytes.")
    truncated = ct_raw.split(b"\x00")[0]
    try:
        PKCS1_OAEP.new(key, hashAlgo=SHA256).decrypt(
            truncated.ljust(len(ct_raw), b"\x00"))
        print(f"      Decryption unexpectedly succeeded (should not happen).")
    except ValueError as err:
        print(f"      Decrypting what survives -> ValueError: {err}")
    print()

    # -- Failure 3: line-ending rewriting --------------------------------------
    print(f"    FAILURE 3 — Line-ending rewriting corrupts bytes in place:")
    lf_count = ct_raw.count(b"\x0a")
    print(f"      This ciphertext contains {lf_count} LF (0x0a) byte(s).")
    print(f"      Text-mode transfers (FTP ASCII mode, Windows text-mode")
    print(f"      file writes, some email gateways) rewrite LF -> CRLF:")
    mangled = ct_raw.replace(b"\x0a", b"\x0d\x0a")
    print(f"      Length changes {len(ct_raw)} -> {len(mangled)} bytes; "
          f"RSA needs exactly {len(ct_raw)}.")
    try:
        PKCS1_OAEP.new(key, hashAlgo=SHA256).decrypt(mangled)
        print(f"      Decryption unexpectedly succeeded (should not happen).")
    except ValueError as err:
        print(f"      Decrypting the mangled bytes -> ValueError: {err}")
    print()

    explain("""
One flipped, dropped, or inserted byte anywhere = total decryption
failure (with OAEP) or silent garbage (with raw RSA). Ciphertext has
ZERO redundancy to recover from transport damage — unlike human text,
where 'M33t at daw n' is still readable.

Base64 sidesteps every failure above by construction: its output
alphabet is only  A-Z a-z 0-9 + / =  — 65 characters chosen because
they survive EVERY common text channel unchanged. No nulls, no control
characters, no quotes, no backslashes, nothing above 0x7F. That is the
entire design goal of the encoding.
""")

    # ---- Demo 4: the REAL job of encoding — safe ciphertext transport --------
    section("Demo 4: Encoding's real job — moving binary ciphertext safely")
    explain("""
So why do encoding and encryption constantly appear TOGETHER?

Ciphertext is raw binary: bytes 0x00–0xFF in arbitrary order. Many
channels are text-only and will corrupt or reject raw binary:

  * Email bodies (SMTP was designed for 7-bit ASCII)
  * JSON / XML / YAML fields (control bytes break parsers)
  * URLs and HTTP headers
  * Copy-paste, log files, chat messages, QR codes

The standard pattern is therefore:

    encrypt -> ENCODE -> transmit -> DECODE -> decrypt

Encoding wraps the ciphertext in a 'text-safe envelope'. It adds no
security — the security was already provided by the encryption. It
adds SAFE PASSAGE.
""")

    message = b"Meet at the usual place, 0900"
    print(f"    Sender's plaintext        : {message.decode()}")
    print()

    # Step A: encrypt (confidentiality)
    ct = PKCS1_OAEP.new(key.publickey(), hashAlgo=SHA256).encrypt(message)
    print(f"    [1] ENCRYPT (RSA-OAEP)    : {len(ct)} raw binary bytes")
    print(f"        First 16 bytes as ints: {list(ct[:16])}")
    print(f"        Contains unprintable / non-ASCII bytes -> unsafe to paste")
    print(f"        into an email or JSON field as-is.")
    print()

    # Step B: encode (transport safety)
    ct_b64 = base64.b64encode(ct).decode()
    print(f"    [2] ENCODE (Base64)       : {len(ct_b64)} printable chars")
    print(f"        {ct_b64[:64]}")
    print(f"        {ct_b64[64:128]}")
    print(f"        ... safe for email/JSON/logs. Note the ~33% size overhead")
    print(f"        ({len(ct)} bytes -> {len(ct_b64)} chars): every 3 bytes")
    print(f"        become 4 characters.")
    print()

    # Step C: transmit (simulated), then decode + decrypt on the other side
    print(f"    [3] TRANSMIT the Base64 string over any text channel...")
    print()
    received_ct = base64.b64decode(ct_b64)
    print(f"    [4] DECODE (Base64)       : back to {len(received_ct)} binary "
          f"bytes (identical: {received_ct == ct})")
    pt = PKCS1_OAEP.new(key, hashAlgo=SHA256).decrypt(received_ct)
    print(f"    [5] DECRYPT (private key) : {pt.decode()}")
    status = "SUCCESS ✓" if pt == message else "FAILURE ✗"
    print(f"        Round-trip check: {status}")
    print()

    # ---- Demo 5: you have already seen this pattern — PEM ---------------------
    section("Demo 5: You've already seen this pattern — PEM keys ARE Base64")
    explain("""
Look back at the public key printed in Part 3. The block between
'-----BEGIN PUBLIC KEY-----' and '-----END PUBLIC KEY-----' is
Base64-encoded binary (DER-serialized key material). Same reason:
keys are binary, but they must survive config files, email, and
copy-paste. Decoding the PEM body proves it:
""")
    pem_lines = key.publickey().export_key().decode().splitlines()
    body = "".join(pem_lines[1:-1])           # strip BEGIN/END armor lines
    der = base64.b64decode(body)
    print(f"    PEM body (Base64 chars)   : {len(body)}")
    print(f"    Decoded DER bytes         : {len(der)}")
    print(f"    First DER bytes (hex)     : {der[:8].hex()}")
    print(f"      (0x3082... is the ASN.1 'SEQUENCE' header — binary")
    print(f"       structure, not text. Base64 is just the envelope.)")
    print()

    explain("""
SUMMARY TABLE

    Property            ENCODING (Base64/hex)   ENCRYPTION (RSA/AES)
    ----------------    --------------------    ---------------------
    Purpose             compatibility           confidentiality
    Needs a key?        no                      yes
    Reversible by...    anyone                  key holder only
    Randomized?         no (deterministic)      yes (with proper padding)
    Typical role        transport envelope      protect the content

    Rule of thumb: if you can undo it with CyberChef and no key,
    it was never encryption.
""")


# ------------------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------------------

def main() -> None:
    banner("RSA TUTORIAL — FROM TEXTBOOK MATH TO REAL-WORLD PRACTICE")
    explain("""
Reading guide:
  Part 1 = the math (small numbers, every step shown)
  Part 2 = the attacks (why the math alone is not a cryptosystem)
  Part 3 = the practice (padding, hybrid encryption)
  Part 4 = encoding vs encryption (Base64's real role: safe transport)
""")
    part1_textbook_rsa()
    part2_why_textbook_rsa_is_broken()
    key = part3_real_world_rsa()
    part4_encoding_vs_encryption(key)

    banner("KEY TAKEAWAYS")
    explain("""
1. RSA keypair: n = p*q public; p, q, phi(n), d secret.
2. Encrypt: c = m^e mod n.  Decrypt: m = c^d mod n.
   Correctness comes from e*d ≡ 1 (mod phi(n)) + Euler's theorem.
3. Security assumption: factoring n is infeasible at 2048+ bits.
4. Raw RSA is deterministic and malleable — never use it directly.
5. Real systems: RSA-OAEP (encryption) / RSA-PSS (signatures),
   almost always in a hybrid scheme with AES for bulk data.
6. Encoding != encryption. Base64/hex need no key and give no
   confidentiality — they exist for compatibility.
7. The two combine as: encrypt -> encode -> transmit -> decode ->
   decrypt. Encryption protects the content; encoding lets the
   binary ciphertext travel safely over text-only channels.
""")


if __name__ == "__main__":
    main()