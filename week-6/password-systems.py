# /// script
# requires-python = ">=3.9"
# dependencies = ["argon2-cffi"]
# ///
"""
pwstore.py — a transparent password storage & login console (OWASP practice)
============================================================================

An interactive teaching tool. It stores and verifies passwords the way the
OWASP Password Storage Cheat Sheet recommends (Argon2id), and it shows you
everything it does: the salt it generates, the hash it computes, the exact
record it stores, and — on login — the parameters it reloads to verify.

    uv run pwstore.py            # interactive menu (register / login / view store)
    uv run pwstore.py --demo     # scripted narrated walkthrough + attacker's view
    uv run pwstore.py --brief    # scripted walkthrough, explanations off
"""
import sys
import time
import secrets          # provides token_bytes() AND compare_digest()
import hashlib
import textwrap
import getpass

from argon2.low_level import hash_secret_raw, Type

# ── OWASP Argon2id parameters (as on the slide) ──────────────────────────────
ALGORITHM   = "argon2id"
MEMORY_KIB  = 19 * 1024      # m — 19 MiB (memory-hard)
TIME_COST   = 2             # t — iterations
PARALLELISM = 1             # p — lanes
SALT_LEN    = 16            # salt length in bytes (from a CSPRNG)
HASH_LEN    = 32            # hash length in bytes

USERS = {}          # the store: username -> record
EXPLAIN = True      # show the "why" notes (toggle in the menu)

# ── output helpers ───────────────────────────────────────────────────────────
def hr(char="─", n=60):
    print(char * n)

def op_header(text):
    print("\n" + "─" * 60)
    print(text)
    hr()

def step(n, title):
    print(f"\n  [{n}] {title}")

def field(label, value):
    print(f"        {label:<11}: {value}")

def why(text):
    if not EXPLAIN:
        return
    text = " ".join(text.split())
    print(textwrap.fill(text, 68, initial_indent="        » ",
                        subsequent_indent="          "))

def datablock(title, rows, note=None):
    """A titled, self-aligning block of label: value rows (no misleading boxes)."""
    w = max(len(label) for label, _ in rows)
    print(f"        {title}")
    print("        " + "-" * 58)
    for label, value in rows:
        print(f"        {label:<{w}} : {value}")
    if note:
        print("        " + "-" * 58)
        print(f"        {note}")

def mib(kib):
    return f"{kib} KiB ({kib // 1024} MiB)"

def slow_hash(password: bytes, salt: bytes) -> bytes:
    """The deliberately-slow, memory-hard Argon2id hash."""
    return hash_secret_raw(secret=password, salt=salt,
                           time_cost=TIME_COST, memory_cost=MEMORY_KIB,
                           parallelism=PARALLELISM, hash_len=HASH_LEN, type=Type.ID)

def record_rows(r, salt_label="salt", show_hash_as="hash (h)"):
    return [
        ("algorithm",       r["algorithm"]),
        ("memory (m)",      mib(r["memory_kib"])),
        ("iterations (t)",  str(r["time_cost"])),
        ("parallelism (p)", str(r["parallelism"])),
        (salt_label,        r["salt"]),
        (show_hash_as,      r["hash"]),
    ]

# ═════════════════════════════════════════════════════════════════════════════
# REGISTRATION — runs once, at sign-up
# ═════════════════════════════════════════════════════════════════════════════
def register(username: str, password: str) -> None:
    op_header(f"REGISTER '{username}'  (runs once, at sign-up)")

    step(1, "Receive the password")
    pwd = bytearray(password.encode("utf-8"))
    field("held", "in memory only — never printed, logged, or stored as plaintext")
    why("""If an attacker steals the store, backups, or logs, anything kept in
         plaintext or reversible form is game over. So the plaintext lives only
         in RAM long enough to be hashed, then is discarded.""")

    step(2, "Generate a unique random salt")
    salt = secrets.token_bytes(SALT_LEN)
    field("salt", f"{salt.hex()}  ({SALT_LEN} bytes)")
    field("source", "secrets.token_bytes() → OS CSPRNG (not the predictable random module)")
    why("""A per-user random salt makes two identical passwords hash to different
         values. It defeats precomputed 'rainbow tables' and hides which users
         share a password. The salt is not secret — it is stored beside the hash.""")

    step(3, "Slow-hash the password")
    t0 = time.perf_counter()
    h = slow_hash(bytes(pwd), salt)
    dt = (time.perf_counter() - t0) * 1000
    field("function", f"Argon2id(pwd, salt)  m={MEMORY_KIB}KiB t={TIME_COST} p={PARALLELISM}")
    field("hash (h)", f"{h.hex()}  ({HASH_LEN} bytes)")
    field("time", f"{dt:.0f} ms for this one hash (the slowness is deliberate)")
    why("""Argon2id is one-way (you cannot reverse h back to the password) and
         memory-hard (each guess needs 19 MiB), so offline guessing is slow and
         expensive — tens per second instead of billions.""")

    step(4, "Store algorithm + parameters + salt + hash")
    USERS[username] = {"algorithm": ALGORITHM, "memory_kib": MEMORY_KIB,
                       "time_cost": TIME_COST, "parallelism": PARALLELISM,
                       "salt": salt.hex(), "hash": h.hex()}
    print()
    datablock(f"This is the record now saved for '{username}':",
              record_rows(USERS[username]),
              note="the plaintext password is NOT stored — only salt, parameters, and hash")
    why("""The algorithm and parameters are stored so verification can reproduce
         the exact same computation later, and so the cost can be raised over
         time while old records still verify.""")

    for i in range(len(pwd)):
        pwd[i] = 0
    del pwd, password
    print(f"\n  '{username}' registered.")

# ═════════════════════════════════════════════════════════════════════════════
# VERIFICATION — runs on every login attempt
# ═════════════════════════════════════════════════════════════════════════════
def verify(username: str, password: str) -> bool:
    op_header(f"LOGIN '{username}'  (runs on every attempt)")

    step(1, "Receive the submitted password (call it pwd')")
    pwd = bytearray(password.encode("utf-8"))
    field("held", "in memory only")

    step(2, "Load the stored verification parameters")
    rec = USERS.get(username)
    if rec is None:
        why("""No such user. A real system would still run a dummy hash and return
             a generic 'invalid credentials', so it does not reveal which
             usernames exist. We stop early here only for clarity.""")
        print("\n  RESULT: REJECT  (unknown user)")
        return False
    salt = bytes.fromhex(rec["salt"])
    stored = bytes.fromhex(rec["hash"])
    datablock(f"Reloaded from the record for '{username}':",
              record_rows(rec, salt_label="salt (reused)", show_hash_as="stored hash (h)"))
    why("""The stored value is a one-way hash — it cannot be decrypted. So we
         re-derive: hash the submitted password with the identical salt and
         parameters, and check whether we land on the same value.""")

    step(3, "Re-hash the submitted password with those parameters")
    h_prime = slow_hash(bytes(pwd), salt)
    field("computed h'", h_prime.hex())
    field("stored h", stored.hex())
    why("""Argon2id is deterministic: same password + same salt + same parameters
         always give the same bytes. One wrong character changes the whole
         output.""")

    step(4, "Compare the two hashes in constant time")
    ok = secrets.compare_digest(h_prime, stored)
    field("compare", f"secrets.compare_digest(h', h) → {ok}")
    why("""compare_digest checks equality without stopping early at the first
         differing byte, so it does not leak — through timing — how much of the
         hash matched. It is the safe default for comparing secret-derived
         values; a plain '==' is not.""")

    for i in range(len(pwd)):
        pwd[i] = 0
    del pwd, password
    print(f"\n  RESULT: {'GRANT  (passwords match)' if ok else 'REJECT  (no match)'}")
    return ok

# ═════════════════════════════════════════════════════════════════════════════
# INTERACTIVE MENU
# ═════════════════════════════════════════════════════════════════════════════
def get_password(prompt):
    try:
        return getpass.getpass("  " + prompt)
    except Exception:
        return input("  " + prompt)

def do_register():
    username = input("\n  New username: ").strip()
    if not username:
        print("  cancelled — empty username"); return
    if username in USERS:
        if input(f"  '{username}' already exists. Overwrite? [y/N] ").strip().lower() != "y":
            print("  cancelled"); return
    pw = get_password("Choose a password: ")
    pw2 = get_password("Confirm password : ")
    if pw != pw2:
        print("  cancelled — the two entries did not match"); return
    if len(pw) < 8 or pw.lower() in {"password", "password123", "12345678", "qwerty"}:
        print("  warning: that password is weak; a real system should reject it. Continuing for the demo.")
    register(username, pw)

def do_login():
    username = input("\n  Username: ").strip()
    pw = get_password("Password: ")
    verify(username, pw)

def do_view():
    print()
    if not USERS:
        print("  the store is empty — no users registered yet"); return
    print(f"  The store holds {len(USERS)} record(s). None contains a plaintext password:\n")
    for u in USERS:
        datablock(f"'{u}'", record_rows(USERS[u]),
                  note="plaintext password: not stored")
        print()

def menu():
    print("\n" + "═" * 60)
    print("  PASSWORD STORAGE & LOGIN — a transparent teaching console")
    print("═" * 60)
    print("  Everything the system computes and stores is shown to you.")
    actions = {"1": do_register, "2": do_login, "3": do_view}
    while True:
        print("\n  Menu:")
        print("    1) Register a new user")
        print("    2) Log in")
        print("    3) View the stored records")
        print(f"    4) Explanations: {'ON' if EXPLAIN else 'OFF'}  (toggle)")
        print("    5) Quit")
        try:
            choice = input("  Choose [1-5]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  bye"); return
        if choice in actions:
            actions[choice]()
        elif choice == "4":
            globals()["EXPLAIN"] = not EXPLAIN
            print(f"  explanations now {'ON' if EXPLAIN else 'OFF'}")
        elif choice == "5":
            print("  bye"); return
        else:
            print("  please enter a number from 1 to 5")

# ═════════════════════════════════════════════════════════════════════════════
# SCRIPTED DEMO
# ═════════════════════════════════════════════════════════════════════════════
def attackers_view():
    print("\n" + "═" * 60); print("IF THE STORE LEAKS — WHAT THE ATTACKER GETS"); hr("═")
    rec = USERS["weakuser"]
    salt = bytes.fromhex(rec["salt"]); target = bytes.fromhex(rec["hash"])
    print("The record contains no password — only the hash. The only attack is")
    print("guess → hash → compare, one candidate at a time:\n")
    wordlist = ["123456", "qwerty", "letmein", "football", "password123", "dragon"]
    print(f"   wordlist: {wordlist}")
    t0 = time.perf_counter(); cracked = tried = None
    for i, g in enumerate(wordlist, 1):
        if secrets.compare_digest(slow_hash(g.encode(), salt), target):
            cracked, tried = g, i; break
    print(f"   tried {tried} guesses in {(time.perf_counter()-t0)*1000:.0f} ms → cracked: '{cracked}'")
    why("""The weak password fell because it was in the wordlist and each guess is
         only ~30 ms. Slow hashing buys time but does not rescue a guessable
         password — you still need a password policy and rate limiting. A long
         random passphrase is not in any wordlist, so brute force at ~30 ms per
         guess is hopeless.""")

def fast_vs_slow():
    print("\n" + "═" * 60); print("WHY 'SLOW': A FAST HASH IS THE WRONG TOOL"); hr("═")
    n = 200_000; t0 = time.perf_counter()
    for _ in range(n):
        hashlib.sha256(b"x").digest()
    sha = n / (time.perf_counter() - t0)
    s = secrets.token_bytes(SALT_LEN); t0 = time.perf_counter(); slow_hash(b"x", s)
    ar = 1 / (time.perf_counter() - t0)
    print(f"   SHA-256  : ~{sha/1e6:,.1f} million hashes/sec (one CPU thread)")
    print(f"   Argon2id : ~{ar:,.0f} hashes/sec")
    print(f"   → SHA-256 is ~{sha/ar:,.0f}x faster to attack (and real GPUs do billions/sec)")
    why("""Being fast is a feature for checksums and a liability for passwords.
         That is why OWASP rules out fast hashes (SHA-256, MD5) and reversible
         encryption for password storage.""")

def demo():
    print("═" * 60); print("DEMO — password storage and login the OWASP way".center(60)); hr("═")
    register("alice", "correct horse battery staple")
    register("bob",   "correct horse battery staple")
    print("\n  Note: alice and bob chose the same password, but their stored")
    print("  hashes differ because each got a unique salt:")
    print(f"    alice: {USERS['alice']['hash'][:24]}…")
    print(f"    bob  : {USERS['bob']['hash'][:24]}…")
    verify("alice", "correct horse battery staple")
    verify("alice", "hunter2")
    register("weakuser", "password123")
    attackers_view()
    fast_vs_slow()

if __name__ == "__main__":
    if "--brief" in sys.argv:
        EXPLAIN = False
    if "--demo" in sys.argv or "--brief" in sys.argv:
        demo()
    else:
        menu()