# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""
Hashing & HMAC — a short, stage-by-stage tutorial.

Run:  python hash_hmac_tutorial.py      (press Enter to move between stages)
      python hash_hmac_tutorial.py | cat (or pipe: runs all stages, no pauses)

Only the standard library is used (hashlib, hmac). The from-scratch SHA-256
in Stage 4 is for teaching the length-extension attack; use hashlib in real
code.
"""

import hashlib
import hmac
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
    p("(a) Watch one happen. Shrink SHA-256 to 32 bits (first 8 hex")
    p("    digits) and try random inputs until two land on the same value:")
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
    p(f"      found after only {tries:,} tries")
    p()
    p("    Hitting one CHOSEN target would need ~2^32 (4.3 billion) tries.")
    p("    Finding ANY colliding pair needs on the order of 2^16 (~65,000)")
    p("    - the 'birthday' shortcut. Collision strength is HALF the bits.")
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
    p("First, the goal in plain terms.")
    p("A website often sends a little note about you, such as:")
    p("    user=guest&role=viewer")
    p("and attaches a TAG: a short code meant to prove the note is genuine")
    p("and unchanged - like a wax seal on a letter.")
    p()
    p("To make the seal, the two sides share a secret KEY only they know.")
    p("A common recipe is:")
    p("    tag = sha256(key + message)")
    p("The idea: only someone with the key can make a matching tag, so if")
    p("the tag checks out, the note must be real. It sounds solid. It isn't.")
    p()
    p("To see why, picture SHA-256 as a machine with a little display:")
    p("  - you pour your data in, one scoop at a time")
    p("  - after each scoop it updates a number shown on the display")
    p("    (the new number depends on the old number plus the new scoop)")
    p("  - when you finish, the number on the display IS the fingerprint")
    p()
    diagram(_DIAG_MACHINE)
    p("The catch: the fingerprint is simply the display's current value.")
    p("Anyone who knows that value can put it back on the display and pour")
    p("in MORE scoops - continuing the hash from where it stopped, without")
    p("knowing what came before. That is the whole attack. Let's watch it,")
    p("first with NO key involved.")
    p()
    p("STEP 1 - hash some ordinary text X (nothing secret):")
    X = b"amount=10"
    dX = hashlib.sha256(X).digest()          # the fingerprint, real library
    mine = my_sha256(X)                       # our teaching 'machine'
    p(f"    X                       = {X.decode()}")
    p(f"    hashlib.sha256(X)       = {dX.hex()}")
    p(f"    our teaching machine    = {mine.hex()}")
    p(f"    identical?  {'YES' if mine == dX else 'no'}  <- our 'machine' really"
      f" is SHA-256, so")
    p("                 everything below is genuine, not faked.")
    p()
    p("STEP 2 - now pretend we DON'T know X. We know only its fingerprint")
    p("         and that X was 9 characters long. Can we keep hashing? Yes.")
    E = b"&admin=1"
    glue = _pad(len(X))
    zeros = len(glue) - 1 - 8
    p("    The machine works in fixed 64-byte scoops, so after your 9")
    p("    characters it tops up the last scoop with filler ('padding'):")
    p(f"      1 marker byte + {zeros} zero bytes + an 8-byte length "
      f"= {len(glue)} bytes")
    p("    We put the fingerprint back on the display and pour in our own")
    p(f'    extra text E = "{E.decode()}":')
    forged = sha256_extend(dX, len(X) + len(glue), E)
    p(f"      new fingerprint = {forged.hex()}")
    p()
    p("STEP 3 - is that a REAL fingerprint of the longer text? Check with")
    p("         Python's real library, hashing the whole thing start to end:")
    normal = hashlib.sha256(X + glue + E).digest()
    p(f"      hashlib.sha256( X + filler + E ) = {normal.hex()}")
    p(f"      our extended fingerprint         = {forged.hex()}")
    p(f"      same?  {'YES' if forged == normal else 'no'}  <- the real library"
      f" agrees. We built")
    p("             the hash of (X + filler + our text) knowing only X's")
    p("             fingerprint - never X itself. THAT is length extension.")
    p()
    p("Now the damage. Replace X with the secret (key + message). The")
    p("attacker never sees the key, but the website publishes the tag, and")
    p("a key's length is easy to guess:")
    p()
    diagram(_DIAG_ATTACK)
    key = os.urandom(16)
    message = b"user=guest&role=viewer"
    tag = hashlib.sha256(key + message).digest()      # real library
    p(f"    message they see = {message.decode()}")
    p(f"    tag they see     = {tag.hex()[:32]}...")
    p(f"    key              = 16 secret bytes (they do NOT have it)")
    p()
    p("Using the exact STEP 2 trick, they tack on their own text and get a")
    p("valid tag for it:")
    guess = 16
    glue2 = _pad(guess + len(message))
    evil = b"&role=admin"
    forged_tag = sha256_extend(tag, guess + len(message) + len(glue2), evil)
    forged_msg = message + glue2 + evil
    p(f'    they append "{evil.decode()}"')
    p(f"    forged tag = {forged_tag.hex()[:32]}...")
    p()
    p("The website re-checks with the REAL key using the real library:")
    server = hashlib.sha256(key + forged_msg).digest()
    ok = hmac.compare_digest(server, forged_tag)
    p(f"    hashlib.sha256(key + forged_note) = {server.hex()[:32]}...")
    p(f"    attacker's forged tag             = {forged_tag.hex()[:32]}...")
    p(f"    do they match - note accepted?  {'YES' if ok else 'no'}")
    p()
    p("Result: a 'guest' just made themselves 'admin', and the note still")
    p("passes the check - all without knowing the secret key.")
    p()
    p("Why did the key fail to protect the note? It was mixed in only at")
    p("the START. The published tag already carries everything the key did,")
    p("so holding the tag is as good as knowing the key - you just continue")
    p("from there. The fix (next stage, HMAC) mixes the key in at the END")
    p("too, so the tag can no longer be used to keep hashing.")


# --- STAGE 5 — HMAC -----------------------------------------------------------

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
    p("HMAC hashes twice, folding the key in each time:")
    p("    HMAC(k, m) = sha256( (k^opad) + sha256( (k^ipad) + m ) )")
    p("The key is applied at the END too (the outer hash), so the tag is")
    p("NOT a resumable state of the message - Stage 4's trick can't work.")
    p()
    key = b"shared-secret-key"
    message = b"user=guest&role=viewer"
    mine = hmac_by_hand(key, message)
    lib = hmac.new(key, message, hashlib.sha256).digest()
    p("Our by-hand version matches Python's hmac module:")
    p(f"    by hand    = {mine.hex()[:32]}...")
    p(f"    hmac module= {lib.hex()[:32]}...")
    p(f"    match?  {'YES' if hmac.compare_digest(mine, lib) else 'no'}")
    p()
    p("Now retry the Stage 4 forgery against HMAC:")
    tag = hmac.new(key, message, hashlib.sha256).digest()
    glue = _pad(64 + len(message))
    forged = sha256_extend(tag, 64 + len(message) + len(glue), b"&role=admin")
    server = hmac.new(key, message + glue + b"&role=admin",
                      hashlib.sha256).digest()
    ok = hmac.compare_digest(forged, server)
    p(f"    accepted?  {'yes' if ok else 'NO'}   <- the attack fails")
    p()
    p("Always compare tags in constant time to avoid timing leaks:")
    p("    hmac.compare_digest(expected, received)")
    p()
    p("HMAC needs a SHARED secret (both sides can make and check tags).")
    p("Need public verification / non-repudiation? Use a signature (RSA).")


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