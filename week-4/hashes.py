# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""
Hashing & HMAC — a short, stage-by-stage tutorial.

Run:  uv run week-4/hashes.py            (Enter=next, b=back, 1-5=jump, q=quit)
      uv run week-4/hashes.py | cat     (runs all stages, no pauses)

Stage 5 hands off to rsa_signatures.py in this folder, which solves the same
authenticity problem with a key pair instead of a shared secret.

Only the standard library is used (hashlib, hmac). The from-scratch SHA-256
in Stage 4 is for teaching the length-extension attack; use hashlib in real
code.
"""

import hashlib
import hmac
import math
import os
import struct
import sys


# --- tiny output helpers ------------------------------------------------------

def p(text: str = "") -> None:
    """Print a line, indented two spaces."""
    print(f"  {text}" if text else "")


def diagram(block: str) -> None:
    """Print a multi-line ASCII diagram, preserving its internal spacing."""
    for line in block.strip("\n").splitlines():
        p(line)
    p()


def step(title: str) -> None:
    """A labelled sub-section inside a stage, so long stages stay navigable."""
    p()
    if len(title) <= 46:
        p(f"--- {title} " + "-" * (50 - len(title)))
    else:
        p("-" * 54)
        p(f"    {title}")
        p("-" * 54)
    p()


def head(n: int, total: int, title: str) -> None:
    bar = "-" * 54
    print("\n")
    p(bar)
    p(f"STAGE {n} of {total}   |   {title}")
    p(bar)
    print()


def nav(i: int, total: int):
    """Ask where to go after a stage. Returns 'next', 'prev', 'quit', or a
    zero-based stage index to jump to. Auto-advances when not interactive."""
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
        if raw in ("", "n"):
            return "next"
        if raw == "b":
            return "prev"
        if raw == "q":
            return "quit"
        if raw.isdigit() and 1 <= int(raw) <= total:
            return int(raw) - 1
        print("  (please type Enter, b, q, or a stage number)")


def sha(data: bytes, n: int = 24) -> str:
    """Short SHA-256 hex, truncated for readable side-by-side comparison."""
    return hashlib.sha256(data).hexdigest()[:n] + "..."


def hex_rows(msg: bytes, diffs, color: bool):
    """Return (offset, hexline) rows, 16 bytes each, with the bytes at the
    `diffs` positions highlighted (red on a terminal, [bracketed] if piped)."""
    RED, OFF = "\033[1;31m", "\033[0m"
    diffset = set(diffs)
    rows = []
    for start in range(0, len(msg), 16):
        chunk = ""
        for j in range(start, min(start + 16, len(msg))):
            bb = f"{msg[j]:02x}"
            if j in diffset:
                bb = f"{RED}{bb}{OFF}" if color else f"[{bb}]"
            chunk += bb
        rows.append((start, chunk))
    return rows


# --- STAGE 1 — what a hash is -------------------------------------------------

def _show_hashes(data: bytes) -> None:
    shown = data.decode("utf-8", "replace")
    p(f'  "{shown}"  ({len(data)} bytes in):')
    p(f"    md5    : {hashlib.md5(data).hexdigest()}")
    p(f"    sha1   : {hashlib.sha1(data).hexdigest()}")
    p(f"    sha256 : {hashlib.sha256(data).hexdigest()}")


def _try_hashes() -> None:
    """Let the user hash their own text (in a terminal); otherwise show
    a few sample hashes so piped runs still demonstrate the idea."""
    if sys.stdin.isatty():
        p("  (type text and press Enter; blank line moves on)")
        while True:
            try:
                s = input("    hash> ")
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if s == "":
                return
            _show_hashes(s.encode("utf-8"))
    else:
        p("  (interactive in a terminal; sample runs shown here)")
        for w in (b"hello", b"hello", b"hellp"):
            _show_hashes(w)


def stage1() -> None:
    head(1, 5, "What a hash is")
    p("A hash turns any data into a short, fixed-size fingerprint.")
    p("No key, and no way back. Try it yourself below.")
    p()
    p("Things to notice as you type:")
    p("  - the same text twice     -> identical hash (deterministic)")
    p("  - short text vs long text -> same length out (fixed size)")
    p("  - change one letter       -> the whole hash changes")
    p("  - md5/sha1/sha256         -> each a fixed, different length")
    p()
    _try_hashes()
    p()
    p("One-way: reversing a sha256 means guessing ~2^256 inputs - more")
    p("than the atoms in the universe. So it cannot be undone.")


# --- STAGE 2 — why MD5 is broken ----------------------------------------------

# Two different 128-byte messages with the SAME MD5 (Wang et al., 2004).
_M1 = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b"
    "d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70"
)
_M2 = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b"
    "d8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70"
)


def stage2() -> None:
    head(2, 5, "Collisions: why MD5 is broken")
    p("A COLLISION is two different inputs with the SAME fingerprint.")
    p("Good hashes make these infeasible to find. Two demos:")
    p()
    p("(a) Watch one happen. But first: why we have to SHRINK the hash")
    p("    before a collision is something you can see in a lecture.")
    p()
    p("    An n-bit hash has 2^n possible outputs. Inputs are unlimited,")
    p("    so by the PIGEONHOLE PRINCIPLE collisions must exist. The")
    p("    security question is never 'do they exist' - it is 'how long")
    p("    would you have to search to find one?'")
    p()
    p("    The BIRTHDAY BOUND answers that: you expect a collision after")
    p("    about 2^(n/2) random inputs, not 2^n. Each new fingerprint is")
    p("    checked against EVERY fingerprint already seen, so after k")
    p("    tries you have k*(k-1)/2 pairs - the pairs grow quadratically,")
    p("    so k only needs to reach the SQUARE ROOT of the output space.")
    p("    Collision resistance is therefore only HALF the output bits.")
    p()
    diagram("""
      output size       distinct outputs   expected tries   can we demo it?
      ---------------   ----------------   --------------   ----------------
       32 bits (here)    4.3 x 10^9         ~2^16 = 65,000   yes, instantly
       64 bits           1.8 x 10^19        ~2^32 = 4.3e9    hours, many GB
      128 bits (MD5)     3.4 x 10^38        ~2^64 = 1.8e19   no
      256 bits (SHA-256) 1.2 x 10^77        ~2^128 = 3.4e38  never""")
    p("    Read the bottom row: a real SHA-256 collision needs ~2^128")
    p("    hashes. No amount of hardware or time on Earth gets there, which")
    p("    is exactly the property we want - and exactly why we cannot")
    p("    demonstrate it live.")
    p()
    p("    So we do not weaken SHA-256 at all. We run the real, unmodified")
    p("    SHA-256 and simply LOOK AT its first 32 bits (8 hex digits),")
    p("    throwing the other 224 away. Truncation shrinks only the TARGET")
    p("    SPACE, so the identical birthday maths plays out in front of you")
    p("    in under a second. It is a scale model, not a broken hash.")
    p()
    p("    Why 32 and not some other size? It is the sweet spot for a live")
    p("    demo: ~65,000 tries takes a moment, and the table of seen")
    p("    fingerprints stays small enough to hold in memory. At 64 bits")
    p("    the same demo would need ~4.3 billion tries and gigabytes of")
    p("    storage; at 16 bits it would finish so fast (~256 tries) that")
    p("    the birthday effect would not be convincing.")
    p()
    p("    Now: try random 6-byte inputs until two share the same 8 hex")
    p("    digits.")
    seen: dict[str, bytes] = {}
    tries = 0
    while True:
        x = os.urandom(6)
        tries += 1
        fp = hashlib.sha256(x).hexdigest()[:8]
        if fp in seen and seen[fp] != x:
            y = seen[fp]
            break
        seen[fp] = x
    p()
    p(f"      input A = {y.hex()}   ->  {fp}")
    p(f"      input B = {x.hex()}   ->  {fp}   <- SAME fingerprint!")
    expected = math.sqrt(math.pi / 2 * 2 ** 32)
    p(f"      found after only {tries:,} tries "
      f"(birthday estimate ~{expected:,.0f})")
    p()
    p(f"    Notice how far short of 2^32 that is - only "
      f"{tries / 2 ** 32 * 100:.4f}% of")
    p("    the output space had to be sampled. Compare the two jobs:")
    p()
    p("      find ANY colliding pair   ~2^16 (~65,000) tries   <- just done")
    p("      match a CHOSEN target     ~2^32 (4.3 billion)     no shortcut")
    p()
    p("    The second job is a SECOND-PREIMAGE: the fingerprint is fixed in")
    p("    advance, so you cannot play new inputs off each other and the")
    p("    birthday shortcut disappears. An attacker who only needs SOME")
    p("    collision (two contracts, two certificates, two updates) always")
    p("    gets the cheaper of the two - so a hash must be sized against")
    p("    the birthday bound, not the full output length. That is why")
    p("    SHA-256 is 256 bits wide to deliver 128-bit security.")
    p()
    p("(b) A real collision in a real hash. Below is the FULL content of")
    p("    two different 128-byte messages (Wang et al. 2004), in hex.")
    p("    Only the highlighted bytes differ; everything else is the same:")
    d = [i for i in range(128) if _M1[i] != _M2[i]]
    color = sys.stdout.isatty()
    p()
    p("    message 1:")
    for off, row in hex_rows(_M1, d, color):
        p(f"      {off:>3}:  {row}")
    p()
    p("    message 2:")
    for off, row in hex_rows(_M2, d, color):
        p(f"      {off:>3}:  {row}")
    p()
    p(f"    ({len(d)} bytes differ, each by a single flipped bit.)")
    p()
    p("    They are different inputs - but MD5 gives ONE fingerprint:")
    p(f"      MD5(message 1) = {hashlib.md5(_M1).hexdigest()}")
    p(f"      MD5(message 2) = {hashlib.md5(_M2).hexdigest()}")
    p("      -> IDENTICAL. To MD5, these two messages are the same.")
    p()
    p("    SHA-256 is not broken, so it still tells them apart:")
    p(f"      SHA-256(message 1) = {sha(_M1)}")
    p(f"      SHA-256(message 2) = {sha(_M2)}")
    p("      -> different, as they should be.")
    p()
    p("Never use MD5/SHA-1 for security (forged CA cert 2008, Flame 2012).")


# --- STAGE 3 — integrity and passwords ----------------------------------------

def stage3() -> None:
    head(3, 5, "Two everyday uses")
    p("USE 1 - Check a file wasn't changed:")
    good = b"setup.sh: make install"
    p(f'  publish  sha256("{good.decode()}")')
    p(f"         = {sha(good)}")
    p("  Re-hash after download; if it differs, the file was altered.")
    p()
    p("USE 2 - Store passwords (the #1 thing people get wrong):")
    p()
    p("  WRONG: store sha256(password)")
    p(f'    alice -> {sha(b"Summer2024!", 16)}')
    p(f'    bob   -> {sha(b"Summer2024!", 16)}   same password, same hash!')
    p("    Also SHA-256 is fast -> cracked by rainbow tables instantly.")
    p()
    p("  BETTER: add a random salt per user (makes each hash unique):")
    sa, sb = os.urandom(16), os.urandom(16)
    p(f'    alice -> {hashlib.sha256(sa + b"Summer2024!").hexdigest()[:16]}...  (salt A)')
    p(f'    bob   -> {hashlib.sha256(sb + b"Summer2024!").hexdigest()[:16]}...  (salt B)')
    p()
    p("  RIGHT: use a slow, salted password hash (scrypt / argon2):")
    salt = os.urandom(16)
    slow = hashlib.scrypt(b"Summer2024!", salt=salt, n=2**14, r=8, p=1,
                          maxmem=64 * 1024 * 1024, dklen=32)
    p(f"    scrypt -> {slow.hex()[:16]}...  (~50 ms each)")
    p("    Slow on purpose: billions of guesses become infeasible.")
    p("    Verify by re-hashing the attempt and comparing (constant time).")


# --- STAGE 4 — the length-extension attack ------------------------------------
# Minimal SHA-256 so we can run a REAL forgery. (Teaching only.)

_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]
_H0 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
       0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xffffffff


def _compress(state, block):
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = _rotr(w[i-15], 7) ^ _rotr(w[i-15], 18) ^ (w[i-15] >> 3)
        s1 = _rotr(w[i-2], 17) ^ _rotr(w[i-2], 19) ^ (w[i-2] >> 10)
        w.append((w[i-16] + s0 + w[i-7] + s1) & 0xffffffff)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        t1 = (h + S1 + ch + _K[i] + w[i]) & 0xffffffff
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & 0xffffffff
        h, g, f = g, f, e
        e = (d + t1) & 0xffffffff
        d, c, b = c, b, a
        a = (t1 + t2) & 0xffffffff
    return [(x + y) & 0xffffffff for x, y in zip(state, (a, b, c, d, e, f, g, h))]


def _pad(msg_len):
    pad = b"\x80"
    pad += b"\x00" * ((56 - (msg_len + 1) % 64) % 64)
    pad += struct.pack(">Q", msg_len * 8)
    return pad


def my_sha256(msg):
    state = list(_H0)
    data = msg + _pad(len(msg))
    for i in range(0, len(data), 64):
        state = _compress(state, data[i:i+64])
    return b"".join(struct.pack(">I", x) for x in state)


def sha256_extend(prior, absorbed_len, extension):
    state = list(struct.unpack(">8I", prior))
    data = extension + _pad(absorbed_len + len(extension))
    for i in range(0, len(data), 64):
        state = _compress(state, data[i:i+64])
    return b"".join(struct.pack(">I", x) for x in state)


# ASCII diagrams used in stage 4.
_DIAG_MACHINE = r"""
    block 1        block 2        block 3 + filler
       |              |               |
       v              v               v
    +-----+        +-----+         +-----+
0 ->| MIX | --s1-> | MIX | --s2->  | MIX | -> FINGERPRINT
    +-----+        +-----+         +-----+     (last display value)
"""

_DIAG_ATTACK = r"""
NORMAL (the server, which knows the key):

   [ key ][ message ][ filler ]  -->  [ MIX chain ]  -->  tag

ATTACK (no key needed - start the machine AT 'tag' and keep pouring):

   [ key ][ message ][ filler ][ &role=admin ][ filler2 ]
   '---attacker cannot see----''-----attacker adds------'
                               |
              tag already = the display value HERE,
              so resume from tag  ----->  forged tag
"""


def stage4() -> None:
    head(4, 5, "The attack: why hash(key + message) is unsafe")
    p("This is the longest stage, so here is the shape of it first:")
    p()
    p("    A. the tempting recipe        tag = sha256(key + message)")
    p("    B. how SHA-256 really works   and what its output leaks")
    p("    C. the trick, with NO key     extend a hash you did not make")
    p("    D. the forgery, WITH a key    guest promotes itself to admin")
    p("    E. what is vulnerable         and how to fix it")
    p()
    p("Parts A and B are the idea; C proves the idea works; D turns it")
    p("into an attack. If you only read one part, read B.")

    # ---------------------------------------------------------------- A ---
    step("A. The tempting recipe")
    p("A website often sends a little note about you, such as:")
    p("    user=guest&role=viewer")
    p("and attaches a TAG: a short code meant to prove the note is genuine")
    p("and unchanged - like a wax seal on a letter.")
    p()
    p("To make the seal, the two sides share a secret KEY only they know.")
    p("A common recipe is:")
    p()
    p("    tag = sha256(key + message)")
    p()
    p("The idea: only someone with the key can make a matching tag, so if")
    p("the tag checks out, the note must be real.")
    p()
    p("It sounds solid. It is broken, and not because SHA-256 is weak.")

    # ---------------------------------------------------------------- B ---
    step("B. What a SHA-256 digest actually is")
    p("Picture SHA-256 as a machine with a little display:")
    p("  - you pour your data in, one scoop at a time")
    p("  - after each scoop it updates a number shown on the display")
    p("    (the new number depends on the old number plus the new scoop)")
    p("  - when you finish, the number on the display IS the fingerprint")
    p()
    diagram(_DIAG_MACHINE)
    p("That machine has a name. SHA-256 is a MERKLE-DAMGARD hash, and the")
    p("number on the display is its INTERNAL STATE (or 'chaining value'):")
    p("8 words of 32 bits = 32 bytes. Now count the output of SHA-256:")
    p("also 32 bytes. That is not a coincidence. When the data runs out,")
    p("the state is handed straight over AS the fingerprint - there is no")
    p("final scrambling step to disguise it.")
    p()
    p("    A SHA-256 DIGEST IS NOT A SUMMARY OF THE MESSAGE.")
    p("    IT IS A SNAPSHOT OF THE MACHINE.")
    p()
    p("Anyone holding that value can put it back on the display and pour")
    p("in MORE scoops - continuing the hash from where it stopped, without")
    p("knowing what came before.")
    p()
    p("That is the whole attack. Everything below is detail.")

    # ---------------------------------------------------------------- C ---
    step("C. The trick, with no key in sight")
    p("Before touching secrets, let us just prove the machine resumes.")
    p()
    p("C1. Hash some ordinary text X (nothing secret):")
    X = b"amount=10"
    dX = hashlib.sha256(X).digest()          # the fingerprint, real library
    mine = my_sha256(X)                       # our teaching 'machine'
    p(f"      X                    = {X.decode()}")
    p(f"      hashlib.sha256(X)    = {dX.hex()}")
    p(f"      our teaching machine = {mine.hex()}")
    p(f"      identical?  {'YES' if mine == dX else 'no'}")
    p("      Our 'machine' really is SHA-256, so nothing below is faked.")
    p()
    p("C2. Now forget X. We keep only its fingerprint, and the fact that")
    p("    X was 9 bytes long. Can we carry on hashing? Yes - but first")
    p("    we must rebuild the FILLER that SHA-256 added at the end.")
    E = b"&admin=1"
    glue = _pad(len(X))
    zeros = len(glue) - 1 - 8
    p()
    p("    The machine works in fixed 64-byte scoops, so after your 9")
    p("    bytes it tops up the last scoop. The padding rule is public -")
    p("    every SHA-256 does it identically - so it can be reconstructed:")
    p()
    p(f"      marker : {glue[:1].hex():<18}a single 1 bit, then zeros")
    p(f"      zeros  : {f'{zeros} x 00':<18}pad to 8 bytes short of a full"
      f" scoop")
    p(f"      length : {glue[-8:].hex():<18}{len(X) * 8} bits ({len(X)}"
      f" bytes), 64-bit big-endian")
    p(f"      {'':<27}-> {len(glue)} filler bytes in total")
    p()
    p("    Read that length field again: the filler depends on HOW LONG")
    p("    the message was, never on what it SAID. Knowing the length is")
    p("    enough. Knowing X is not required. Remember this - in part D")
    p("    the length is the one thing the attacker has to guess.")
    p()
    p("C3. Put the fingerprint back on the display and pour in our own")
    p(f'    extra text E = "{E.decode()}":')
    forged = sha256_extend(dX, len(X) + len(glue), E)
    p(f"      new fingerprint = {forged.hex()}")
    p()
    p("C4. Is that a REAL fingerprint of the longer text? Ask the library,")
    p("    hashing the whole thing from start to finish:")
    normal = hashlib.sha256(X + glue + E).digest()
    p(f"      hashlib.sha256( X + filler + E ) = {normal.hex()}")
    p(f"      our extended fingerprint         = {forged.hex()}")
    p(f"      same?  {'YES' if forged == normal else 'no'}")
    p()
    p("    We produced the hash of (X + filler + our text) knowing only")
    p("    X's fingerprint - never X itself. That is LENGTH EXTENSION.")

    # ---------------------------------------------------------------- D ---
    step("D. The forgery: now X is (key + message)")
    p("The attacker never sees the key. But the website publishes the")
    p("tag, and the tag is the machine's state after it swallowed the key")
    p("AND the message. So the attacker can keep pouring.")
    p()
    diagram(_DIAG_ATTACK)
    key = os.urandom(16)
    message = b"user=guest&role=viewer"
    tag = hashlib.sha256(key + message).digest()      # real library
    p(f"    message they see = {message.decode()}")
    p(f"    tag they see     = {tag.hex()[:32]}...")
    p(f"    key              = 16 secret bytes (they do NOT have it)")
    p()
    evil = b"&role=admin"

    def server_accepts(note: bytes, claimed_tag: bytes) -> bool:
        """The website: re-hash with the REAL key and compare."""
        return hmac.compare_digest(hashlib.sha256(key + note).digest(),
                                   claimed_tag)

    p("D1. The obvious attempt first - edit the note, resend the old tag,")
    p("    no cleverness at all:")
    p(f'      note = "{(message + evil).decode()}"')
    p(f"      tag  = the one they were given")
    p(f"      website accepts?  "
      f"{'YES' if server_accepts(message + evil, tag) else 'NO'}"
      f"  <- the tag really does bind the note")
    p()
    p("    Good: the tag is doing its job against casual editing. The")
    p("    break is not EDITING, it is RESUMING.")
    p()
    p("D2. To resume, the attacker must rebuild the filler, and for that")
    p("    they need the length of (key + message). They can see the")
    p("    message. The key length they must guess - and that is cheap:")
    p("    keys are realistically under 64 bytes, and each guess costs")
    p("    one request to the website, which answers accept/reject free.")
    p()
    attempts = 0
    for guess in range(1, 65):
        attempts += 1
        glue2 = _pad(guess + len(message))
        candidate_tag = sha256_extend(tag, guess + len(message) + len(glue2),
                                      evil)
        candidate_msg = message + glue2 + evil
        if server_accepts(candidate_msg, candidate_tag):
            forged_tag, forged_msg = candidate_tag, candidate_msg
            break
    p(f'      they append "{evil.decode()}" and try key lengths 1, 2, 3, ...')
    p(f"      guess {guess} bytes -> ACCEPTED, after {attempts} tries")
    p(f"      (the key really is {len(key)} bytes - they never learned it,")
    p("       they only learned how LONG it is)")
    p(f"      forged tag = {forged_tag.hex()[:32]}...")
    p()
    p("D3. The website re-checks with the REAL key, using the real library:")
    server = hashlib.sha256(key + forged_msg).digest()
    ok = hmac.compare_digest(server, forged_tag)
    p(f"      hashlib.sha256(key + forged_note) = {server.hex()[:32]}...")
    p(f"      attacker's forged tag             = {forged_tag.hex()[:32]}...")
    p(f"      match - note accepted?  {'YES' if ok else 'no'}")
    p()
    p("D4. Look at what actually went on the wire, though. The filler is")
    p("    copied in literally, so the forged note has raw bytes in the")
    p("    middle:")
    p()
    tokens = [chr(b) if 32 <= b < 127 else f"\\x{b:02x}" for b in forged_msg]
    line = ""
    for tok in tokens:
        if len(line) + len(tok) > 58:
            p(f"      {line}")
            line = ""
        line += tok
    p(f"      {line}")
    p()
    p("    An attacker cannot avoid that junk: those exact bytes are what")
    p("    the hash absorbed, so the tag is only valid WITH them. Whether")
    p("    the forgery lands therefore depends on the PARSER at the other")
    p("    end - and plenty of real formats shrug it off: query strings,")
    p("    cookies and loose serialisers skip what they cannot read, and")
    p("    when a key appears twice the LAST value usually wins. Here")
    p("    role=viewer is read first, then role=admin overwrites it.")
    p()
    p("    Result: a 'guest' just made themselves 'admin', and the note")
    p("    still passes the check - without ever knowing the secret key.")

    # ---------------------------------------------------------------- E ---
    step("E. Why it failed, what else is affected, and the fix")
    p("Why did the key fail to protect the note? It was mixed in only at")
    p("the START. The published tag already carries everything the key")
    p("did, so holding the tag is as good as holding the key - you just")
    p("continue from there.")
    p()
    p("Which hashes leak their state this way? Every plain Merkle-Damgard")
    p("one, however strong it is otherwise:")
    p()
    diagram("""
      vulnerable      MD5, SHA-1, SHA-256, SHA-512
      not vulnerable  SHA-3 / Keccak  - a sponge; its state is far larger
                                        than the digest, so the digest does
                                        not hand you the machine
                      BLAKE2, BLAKE3  - finalisation flag in the last block
                      SHA-512/256     - truncated: half the state is withheld""")
    p("SHA-256 is on the vulnerable list, yet stage 2 called it unbroken.")
    p("Both are true, and the distinction is the point of this stage:")
    p()
    p("    collision resistance  no two messages share a digest")
    p("    state secrecy         the digest does not reveal the machine")
    p()
    p("Those are different properties. Length extension is not a flaw in")
    p("the mixing - it is a consequence of the SHAPE of the construction.")
    p("A perfect compression function would not help.")
    p()
    p("The fix is to stop the tag from being a resumable state. Switching")
    p("to SHA-3 works; so does sha256(sha256(key + message)), because the")
    p("attacker only ever sees the OUTER hash's state and cannot resume")
    p("the inner one.")
    p()
    p("But do not invent your own. Use HMAC - the next stage - which")
    p("mixes the key in at the END as well, and is the construction that")
    p("has actually been analysed and standardised.")


# --- STAGE 5 — HMAC -----------------------------------------------------------

_DIAG_HMAC = r"""
                 message
                    |
   key --^ipad--> [ inner sha256 ] --> inner digest (32 bytes)
                                            |
   key --^opad--------------------------> [ outer sha256 ] --> TAG

   The tag is the OUTER hash's state. Resuming it (stage 4's trick)
   gets you a longer OUTER hash - but the server never continues the
   outer hash, it recomputes the inner one from the message. The
   extension lands on the wrong side of the nesting.
"""


def ipad_of(key, block=64):
    """The inner key: key padded to the block size, XORed with 0x36s."""
    if len(key) > block:
        key = hashlib.sha256(key).digest()
    return bytes(k ^ 0x36 for k in key.ljust(block, b"\x00"))


def opad_of(key, block=64):
    """The outer key: same padding, XORed with 0x5c s instead."""
    if len(key) > block:
        key = hashlib.sha256(key).digest()
    return bytes(k ^ 0x5c for k in key.ljust(block, b"\x00"))


def hmac_by_hand(key, message, block=64):
    if len(key) > block:
        key = hashlib.sha256(key).digest()
    key = key.ljust(block, b"\x00")
    ipad = bytes(k ^ 0x36 for k in key)
    opad = bytes(k ^ 0x5c for k in key)
    inner = hashlib.sha256(ipad + message).digest()
    return hashlib.sha256(opad + inner).digest()


def stage5() -> None:
    head(5, 5, "The fix: HMAC")
    p("Stage 4's break had one cause: the key went in only at the START,")
    p("so the published tag was a resumable snapshot of the machine.")
    p()
    p("HMAC's answer is to hash TWICE, folding the key in both times:")
    p()
    p("    HMAC(k, m) = sha256( (k^opad) + sha256( (k^ipad) + m ) )")
    p("                 '------- outer -------'  '---- inner ----'")
    p()
    diagram(_DIAG_HMAC)

    step("A. What ipad and opad are")
    p("Two fixed constants, repeated to the block size, XORed with the")
    p("key to make TWO different keys out of one:")
    p()
    demo_key = b"shared-secret-key"
    padded = demo_key.ljust(64, b"\x00")
    ipad = bytes(k ^ 0x36 for k in padded)
    opad = bytes(k ^ 0x5c for k in padded)
    p(f"    key                = {demo_key.decode()}")
    p(f"    padded to 64 bytes = {demo_key.decode()}" + "\\x00 x "
      f"{64 - len(demo_key)}")
    p(f"    ipad const = 0x36 repeated -> k^ipad = {ipad[:8].hex()}...")
    p(f"    opad const = 0x5c repeated -> k^opad = {opad[:8].hex()}...")
    p()
    p("    Why two different constants? So the inner and outer hashes are")
    p("    keyed DIFFERENTLY. If both used the same value the two hashes")
    p("    would share a key, and the proof of security would not hold.")
    p("    0x36 and 0x5c differ in 4 of their 8 bits, which is the point;")
    p("    the specific values are not magic.")
    p()
    p("    Two housekeeping rules complete the construction:")
    p("      - a key LONGER than the block is hashed down to 32 bytes")
    p("        first (that is why HMAC accepts any key length)")
    p("      - a key SHORTER than the block is padded with zeros")

    step("B. Check our version against the library")
    key = b"shared-secret-key"
    message = b"user=guest&role=viewer"
    mine = hmac_by_hand(key, message)
    lib = hmac.new(key, message, hashlib.sha256).digest()
    p(f"    our 4-line hmac_by_hand = {mine.hex()[:32]}...")
    p(f"    python's hmac module    = {lib.hex()[:32]}...")
    p(f"    match?  {'YES' if hmac.compare_digest(mine, lib) else 'no'}")
    p("    So the explanation above describes the real thing.")

    step("C. Now re-run stage 4's attack against it")
    tag = hmac.new(key, message, hashlib.sha256).digest()
    p(f"    tag = HMAC(key, \"{message.decode()}\")")
    p(f"        = {tag.hex()[:32]}...")
    p()
    p("    The attacker tries exactly what worked before: treat the tag as")
    p("    a machine state, and pour in more.")
    p()
    p("    Here is the subtle part, and it is worth slowing down for.")
    p("    The tag IS still a resumable state - of the OUTER hash. The")
    p("    outer hash absorbed (k^opad) plus the 32-byte inner digest:")
    p()
    p("        64 + 32 = 96 bytes")
    p()
    evil = b"&role=admin"
    glue = _pad(96)
    forged = sha256_extend(tag, 96 + len(glue), evil)
    inner = hashlib.sha256(ipad_of(key) + message).digest()
    truth = hashlib.sha256(opad_of(key) + inner + glue + evil).digest()
    p("    so the attacker CAN extend it, and the extension is genuinely")
    p("    correct as a hash operation:")
    p()
    p(f"      extended tag                       = {forged.hex()[:32]}...")
    p(f"      sha256(k^opad + inner + pad + evil)= {truth.hex()[:32]}...")
    p(f"      a valid continuation?  "
      f"{'YES - the resume itself still works' if forged == truth else 'no'}")
    p()
    p("    And yet it buys them nothing. Ask the server:")
    server = hmac.new(key, message + glue + evil, hashlib.sha256).digest()
    ok = hmac.compare_digest(forged, server)
    p(f"      HMAC(key, message + pad + evil)    = {server.hex()[:32]}...")
    p(f"      attacker's extended tag            = {forged.hex()[:32]}...")
    p(f"      accepted?  {'yes' if ok else 'NO - the attack fails'}")
    p()
    p("    WHY it fails, precisely: the attacker extended the OUTER hash,")
    p("    but the server does not verify by continuing anything. It")
    p("    recomputes from the message - inner hash first, then outer. For")
    p("    the forgery to work there would have to be some message m' with")
    p()
    p("        sha256(k^ipad + m') = inner + padding + evil")
    p()
    p("    i.e. a message whose INNER digest happens to equal the extended")
    p("    string. That is a preimage attack on SHA-256, and 32 bytes of")
    p("    output cannot be steered that way.")
    p()
    p("    The extension landed on the wrong side of the nesting. That is")
    p("    what the outer hash is for.")

    step("D. Using it correctly")
    p("Verification must compare in CONSTANT TIME:")
    p()
    p("    hmac.compare_digest(expected, received)     yes")
    p("    expected == received                        no")
    p()
    p("A plain == returns as soon as two bytes differ, so how LONG it")
    p("takes reveals how many leading bytes were right. An attacker who")
    p("can time the check recovers a valid tag one byte at a time -")
    p("roughly 32 x 256 attempts instead of 2^256.")
    p()
    p("A correct verifier, in full:")
    p()
    diagram("""
      def verify(key, message, received_tag):
          expected = hmac.new(key, message, hashlib.sha256).digest()
          return hmac.compare_digest(expected, received_tag)""")
    good = hmac.new(key, message, hashlib.sha256).digest()
    tampered = message.replace(b"viewer", b"admin!")
    p("    genuine message + its tag   -> "
      f"{'ACCEPTED' if hmac.compare_digest(hmac.new(key, message, hashlib.sha256).digest(), good) else 'rejected'}")
    p("    tampered message + old tag  -> "
      f"{'accepted' if hmac.compare_digest(hmac.new(key, tampered, hashlib.sha256).digest(), good) else 'REJECTED'}")
    p("    genuine message + bad tag   -> "
      f"{'accepted' if hmac.compare_digest(good, bytes(32)) else 'REJECTED'}")

    step("E. When HMAC is not the right tool")
    p("HMAC needs a SHARED secret, which means anyone who can CHECK a tag")
    p("can also MAKE one. Between two systems that already trust each")
    p("other, that is fine and HMAC is the right answer: fast, small, and")
    p("standardised.")
    p()
    p("But it cannot prove to a THIRD party who created a message, because")
    p("either holder of the key could have. For that you need two")
    p("different keys - sign with a private one, verify with a public one:")
    p()
    p("    HMAC        one shared secret     verifier can also forge")
    p("    signature   private + public      verifier can only verify")
    p("                                      and gets non-repudiation")
    p()
    p("That is a digital signature. See rsa_signatures.py in this folder,")
    p("which picks up exactly here.")


# --- recap + runner -----------------------------------------------------------

def recap() -> None:
    print("\n")
    p("-" * 54)
    p("RECAP")
    p("-" * 54)
    print()
    p("1. A hash is a keyless, one-way, fixed-size fingerprint.")
    p("2. MD5 and SHA-1 are broken. Use SHA-256 or SHA-3.")
    p("3. Store passwords with a slow, salted hash (scrypt/argon2).")
    p("4. Don't build a tag as hash(secret+message) - it's forgeable.")
    p("5. Use HMAC for shared-secret authenticity; signatures for")
    p("   public verification. Compare tags with hmac.compare_digest.")
    print()
    p("Next: rsa_signatures.py - the same authenticity problem, solved")
    p("with two keys instead of one shared secret.")
    print()


def main() -> None:
    print("\n  HASHING & HMAC - a 5-stage tutorial")
    if sys.stdin.isatty():
        p("Move with: Enter=next, b=back, a stage number to jump, q=quit.")

    stages = [stage1, stage2, stage3, stage4, stage5]
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
        else:                       # jump to a specific stage index
            i = action
    recap()


if __name__ == "__main__":
    main()