"""
AES block modes — a GUIDED WALKTHROUGH of ECB, CBC and CTR.

Runs as a self-paced lesson: definitions first, then each mode is
introduced, traced block by block (every intermediate value shown),
and summarized with what to notice. Press Enter to advance.

Requires:  pip install pycryptodome
Run:       python aes_modes_guided.py             (paced, press Enter)
           python aes_modes_guided.py --no-pause  (print everything)
"""

import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

BLOCK = 16
PAUSE = '--no-pause' not in sys.argv and sys.stdout.isatty()


def pause() -> None:
    if PAUSE:
        input("\n  --- press Enter to continue ---")
    else:
        print()


def h(data: bytes) -> str:
    s = data.hex()
    return ' '.join(s[i:i + 8] for i in range(0, len(s), 8))


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def split_blocks(data: bytes) -> list[bytes]:
    return [data[i:i + BLOCK] for i in range(0, len(data), BLOCK)]


def banner(title: str) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


# ---------------------------------------------------------------
# STEP 0 — Definitions
# ---------------------------------------------------------------
banner("STEP 0 — DEFINITIONS")
print("""
  BLOCK CIPHER
    An algorithm (here AES) that encrypts exactly one fixed-size
    block (128 bits / 16 bytes) under a secret key K. With the key
    fixed, it is a bijection: every input block maps to exactly one
    output block, which is what makes decryption possible.

  MODE OF OPERATION
    The recipe for applying that single-block cipher to a message
    longer than one block. The mode — not AES itself — decides the
    security properties: pattern hiding, parallelism, padding,
    and what happens when randomness (IV/nonce) is misused.

  THE THREE MODES IN THIS WALKTHROUGH
    ECB (Electronic Codebook) : each block encrypted independently
                                C_i = E(K, P_i)
    CBC (Cipher Block Chain)  : each block XORed with the previous
                                ciphertext before encryption
                                C_i = E(K, P_i XOR C_(i-1)), C_0 = IV
    CTR (Counter)             : the cipher encrypts a COUNTER to make
                                a keystream; plaintext only meets XOR
                                C_i = P_i XOR E(K, nonce||i)

  SUPPORTING TERMS
    IV (initialization vector): random block that randomizes CBC's
        first block; sent in the clear; must be unpredictable.
    Nonce ('number used once') : per-message unique value forming the
        top half of CTR's counter; sent in the clear; must NEVER
        repeat under the same key.
    Keystream: the pseudorandom bytes CTR generates and XORs with
        the plaintext — a manufactured one-time pad.
""")
pause()

# ---------------------------------------------------------------
# STEP 1 — The setup
# ---------------------------------------------------------------
banner("STEP 1 — SETUP: one key, one deliberately repetitive message")

KEY = get_random_bytes(16)
raw_aes = AES.new(KEY, AES.MODE_ECB)   # used only as E(K, single block)

def E(block: bytes) -> bytes:
    """The block cipher primitive: encrypt exactly one 16-byte block."""
    return raw_aes.encrypt(block)

PLAINTEXT = b"ATTACK AT DAWN!!" + b"HOLD THE GATE..." + b"ATTACK AT DAWN!!"
P = split_blocks(pad(PLAINTEXT, BLOCK))

print(f"""
  We generate one random 128-bit key, used for all three modes:

    KEY = {h(KEY)}

  And craft a plaintext whose block 1 and block 3 are IDENTICAL —
  a trap that will expose how each mode handles repetition:
""")
for i, p in enumerate(P, 1):
    marker = "   <-- same as block 1" if i == 3 else ""
    note = "   (PKCS#7 padding block)" if i == 4 else ""
    print(f"    P{i} = {h(p)}  {p!r}{marker}{note}")
print("""
  ABOUT THAT 4th BLOCK — PADDING
    Our real message is 48 bytes = exactly 3 blocks. So why is
    there a P4? Because ECB and CBC push the plaintext THROUGH
    AES, which only accepts whole 16-byte blocks — the message
    must be padded to a block boundary.

    PKCS#7 padding: append N bytes, each with value N, where N is
    the number of bytes needed to reach the boundary. If the
    message already ends exactly on a boundary (like ours), a FULL
    block of 16 bytes of 0x10 is added — that's P4. Why pad even
    then? So the receiver can always unpad unambiguously: read the
    last byte (0x10 = 16), strip that many bytes. Without the rule,
    a message genuinely ending in 0x01 would be indistinguishable
    from padding.

    Watch how the modes differ here: ECB and CBC will encrypt all
    4 blocks (data + padding); CTR will encrypt only the 3 real
    ones, because it never puts the plaintext through AES at all.

  Everything below is built from ONE primitive: E(block), a raw
  single-block AES encryption. The modes differ only in WHAT they
  feed into it. Watch the 'enters AES' line in each trace.""")
pause()

# ---------------------------------------------------------------
# STEP 2 — ECB
# ---------------------------------------------------------------
banner("STEP 2 — ECB (Electronic Codebook)")
print("""
  DEFINITION
    The naive mode: chop the message into blocks and encrypt each
    one independently with the same key. No randomness, no memory.

  HOW IT WORKS
    for each block i:   C_i = E(K, P_i)

  Now watch it run — pay attention to blocks 1 and 3:""")

ecb_ct = []
for i, p in enumerate(P, 1):
    c = E(p)
    ecb_ct.append(c)
    print(f"\n  block {i}:")
    print(f"    enters AES (P{i})  : {h(p)}")
    print(f"    AES(K, P{i}) = C{i}  : {h(c)}")

print(f"""
  WHAT TO NOTICE
    C1 == C3?  {ecb_ct[0] == ecb_ct[2]}
    Identical plaintext blocks produced identical ciphertext blocks,
    because the AES input IS the plaintext and nothing else varies.
    Any structure in the message survives encryption — encrypt a
    bitmap this way and you can still see the image (the famous
    'ECB penguin'). This is why ECB is never used for real data.

    PADDING: 4 blocks encrypted (3 data + 1 padding). The plaintext
    goes through AES, so it had to be padded to a block boundary —
    the ciphertext is 64 bytes for a 48-byte message.""")
pause()

# ---------------------------------------------------------------
# STEP 3 — CBC
# ---------------------------------------------------------------
banner("STEP 3 — CBC (Cipher Block Chaining)")
print("""
  DEFINITION
    Fixes ECB by chaining: each plaintext block is XORed with the
    PREVIOUS ciphertext block before entering AES. A random IV
    stands in as 'block zero' so even the first block is randomized.

  HOW IT WORKS
    X_i = P_i XOR C_(i-1)     (C_0 = IV)
    C_i = E(K, X_i)

  The XOR line is where the pattern dies — watch X1 vs X3:""")

IV = get_random_bytes(16)
print(f"\n    IV = {h(IV)}   (random, sent in clear)")

cbc_ct = []
prev = IV
for i, p in enumerate(P, 1):
    x = xor(p, prev)
    c = E(x)
    cbc_ct.append(c)
    chain = "IV" if i == 1 else f"C{i-1}"
    print(f"\n  block {i}:")
    print(f"    P{i}               : {h(p)}")
    print(f"    XOR {chain:<4}         : {h(prev)}")
    print(f"    enters AES (X{i})  : {h(x)}")
    print(f"    AES(K, X{i}) = C{i}  : {h(c)}")
    prev = c

print(f"""
  WHAT TO NOTICE
    C1 == C3?  {cbc_ct[0] == cbc_ct[2]}
    P1 and P3 are identical, but X1 = P1 XOR IV while X3 = P3 XOR C2
    — different AES inputs, so unrelated outputs. The chain means
    every ciphertext block depends on ALL blocks before it.
    Consequences: patterns destroyed and re-encryption with a fresh
    IV yields a new ciphertext, BUT encryption is sequential (block
    i needs C_(i-1) first) and full blocks require padding.

    PADDING: 4 blocks again (3 data + 1 padding), same as ECB and
    for the same reason — P XOR C_(i-1) must be a full 16-byte
    block before it can enter AES. Historically, mishandling this
    padding at decryption time is what enabled padding oracle
    attacks against CBC.""")
pause()

# ---------------------------------------------------------------
# STEP 4 — CTR
# ---------------------------------------------------------------
banner("STEP 4 — CTR (Counter mode)")
print("""
  DEFINITION
    Turns the block cipher into a stream cipher. AES never sees the
    plaintext at all — it encrypts a counter (nonce||1, nonce||2...)
    to manufacture a keystream, which is XORed with the plaintext.
    This is the Vernam/one-time-pad construction with a pad built
    by AES instead of true randomness.

  HOW IT WORKS
    KS_i = E(K, nonce||i)      (the keystream block)
    C_i  = P_i XOR KS_i

  Watch what enters AES now — just counters ticking up. And note:
  only 3 blocks this time — the padding block P4 is NOT encrypted,
  because CTR doesn't need it (explained below):""")

NONCE = get_random_bytes(8)
print(f"\n    nonce = {(NONCE).hex()}   (8 bytes, sent in clear)")

ctr_ct = []
for i, p in enumerate(P[:3], 1):
    counter_block = NONCE + i.to_bytes(8, 'big')
    ks = E(counter_block)
    c = xor(p, ks)
    ctr_ct.append(c)
    print(f"\n  block {i}:")
    print(f"    enters AES (nonce||{i}): {h(counter_block)}")
    print(f"    AES(K) = KS{i}          : {h(ks)}   (keystream)")
    print(f"    P{i}                    : {h(p)}")
    print(f"    P{i} XOR KS{i} = C{i}      : {h(c)}")

print(f"""
  WHAT TO NOTICE
    C1 == C3?  {ctr_ct[0] == ctr_ct[2]}
    Identical plaintexts still encrypt differently, because the AES
    inputs (nonce||1 vs nonce||3) differ. The plaintext NEVER
    entered AES — only counters did. Consequences: every block is
    independent (fully parallel, random access), no padding needed,
    and the one fatal rule: never reuse a nonce under the same key,
    or two messages share a keystream (two-time pad).

    PADDING: only 3 blocks encrypted — no padding block! The
    plaintext never enters AES (only counters do), so there's no
    block-boundary requirement on the data. XOR works byte by
    byte: for a partial final block you'd use just the keystream
    bytes you need and discard the rest. Ciphertext length equals
    plaintext length exactly — 48 bytes for a 48-byte message,
    vs 64 bytes for ECB/CBC. This also removes the padding oracle
    attack surface entirely: no padding, nothing to mis-handle.""")
pause()

# ---------------------------------------------------------------
# STEP 5 — CTR decryption
# ---------------------------------------------------------------
banner("STEP 5 — CTR DECRYPTION: the same operation, run again")
print("""
  DEFINITION
    CTR decryption is not a reverse operation. The receiver rebuilds
    the same counters, regenerates the same keystream with AES
    running FORWARD, and XORs it off (XOR is self-inverse:
    C XOR KS = (P XOR KS) XOR KS = P). AES's decryption function is
    never used — unlike ECB/CBC, where ciphertext enters the cipher
    and must be pushed back through in reverse.

  Watch the receiver recover block 1:""")

counter_block = NONCE + (1).to_bytes(8, 'big')
ks = E(counter_block)                     # AES FORWARD again
p_rec = xor(ctr_ct[0], ks)
print(f"""
    rebuild counter    : {h(counter_block)}
    AES(K) = KS1       : {h(ks)}   <-- identical keystream
    C1 XOR KS1         : {h(p_rec)}
    recovered          : {p_rec!r}""")
pause()

# ---------------------------------------------------------------
# STEP 6 — Verification and summary
# ---------------------------------------------------------------
banner("STEP 6 — VERIFY AGAINST THE REAL LIBRARY, THEN SUMMARY")

lib_ecb = AES.new(KEY, AES.MODE_ECB).encrypt(pad(PLAINTEXT, BLOCK))
assert b''.join(ecb_ct) == lib_ecb
print("\n  manual ECB == pycryptodome ECB : OK")

lib_cbc = AES.new(KEY, AES.MODE_CBC, iv=IV).encrypt(pad(PLAINTEXT, BLOCK))
assert b''.join(cbc_ct) == lib_cbc
print("  manual CBC == pycryptodome CBC : OK")

lib_ctr = AES.new(KEY, AES.MODE_CTR, nonce=NONCE, initial_value=1)
assert b''.join(ctr_ct) == lib_ctr.encrypt(PLAINTEXT)
print("  manual CTR == pycryptodome CTR : OK")

print("""
  (Our hand-rolled traces are the real algorithms, bit for bit —
   not simplified approximations.)

  SUMMARY — the one line that generates everything:
    what enters AES?
      ECB : the plaintext itself      -> patterns leak
      CBC : plaintext XOR prev cipher -> randomized, but sequential
      CTR : just a counter            -> parallel, stream-like,
                                         nonce must never repeat

  FINAL CAUTION
    None of these modes authenticate. All are malleable — an
    attacker can flip ciphertext bits (CTR: surgically). Real
    systems use AEAD, e.g. AES-GCM = CTR + authentication tag.
""")