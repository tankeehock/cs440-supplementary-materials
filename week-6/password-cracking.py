# /// script
# requires-python = ">=3.9"
# dependencies = ["argon2-cffi"]
# ///
"""
crack.py — the password search space, shown by cracking (SMU-style lesson)
==========================================================================

A teaching demo for the "Password Search Space" slide. It makes the arithmetic
concrete by actually cracking passwords — but ONLY hashes this script generates
itself, to show students why passwords must be strong AND slowly hashed.

    uv run crack.py              # the full guided lesson
    uv run crack.py --try abcd   # brute-force a short password you pick yourself

────────────────────────────────────────────────────────────────────────────
ETHICS: This cracks hashes created inside this script, for education. Cracking
passwords, accounts, or systems you do not own is illegal. The lesson is
defensive: choose long random passwords, and store them with a slow hash.
────────────────────────────────────────────────────────────────────────────
"""
import sys
import time
import string
import hashlib
import itertools

# ── formatting ───────────────────────────────────────────────────────────────
def title(t): print("\n" + "═" * 70); print(t); print("═" * 70)
def note(t):  print("  " + t)

SECONDS_PER_YEAR = 3.15e7   # ~3 x 10^7, as on the slide

def human_time(seconds: float) -> str:
    years = seconds / SECONDS_PER_YEAR
    if years >= 1:
        return f"{years:.2e} years" if years >= 1e4 else f"{years:,.1f} years"
    for name, size in [("day", 86400), ("hour", 3600), ("minute", 60)]:
        if seconds >= size:
            return f"{seconds/size:,.1f} {name}s"
    return f"{seconds:.3f} seconds"

# ═════════════════════════════════════════════════════════════════════════════
# PART 1 — the search space (the slide's arithmetic, generalised)
# ═════════════════════════════════════════════════════════════════════════════
def part1_search_space():
    title("PART 1 — HOW BIG IS THE SEARCH SPACE?")
    note("A brute-force attacker must try combinations. The count is:")
    note("     (alphabet size) ^ (password length)")
    note("Length and alphabet are EXPONENTS; attacker speed is only a divisor.\n")

    # the exact slide example
    alphabet, length, rate = 52, 8, 1e6
    space = alphabet ** length
    secs = space / rate
    note("The slide's example:")
    note(f"   52 characters (a-z, A-Z), length 8   → 52^8 = {space:.2e} passwords")
    note(f"   attacker rate 10^6 guesses/sec       → {space:.2e} / 1e6 = {secs:.2e} sec")
    note(f"   in years (1 yr ≈ 3e7 sec)            → {secs/SECONDS_PER_YEAR:.1f} years (worst case)")
    note(f"   on average you find it in half that  → {secs/2/SECONDS_PER_YEAR:.1f} years\n")

    # generalise: length & alphabet vs attacker hardware
    note("Now watch two things move the answer — length/alphabet, and hardware:")
    note(f"{'':<14}{'1e6/sec (CPU)':>18}{'1e9/sec (GPU)':>18}{'1e12/sec (rig)':>18}")
    charsets = [("lower a-z", 26), ("+digits", 36), ("+UPPER", 62), ("+symbols", 95)]
    for label, a in charsets:
        for L in (8,):
            space = a ** L
            row = f"  {label:<10} L={L}"
            for r in (1e6, 1e9, 1e12):
                row += f"{human_time(space/r):>18}"
            print(row)
    print()
    note("Same idea, fixing the alphabet at 95 and growing the length:")
    for L in (6, 8, 10, 12):
        space = 95 ** L
        row = f"  95-char   L={L:<3}"
        for r in (1e6, 1e9, 1e12):
            row += f"{human_time(space/r):>18}"
        print(row)
    print()
    note("Takeaway: +1 character multiplies the space; faster hardware only")
    note("divides it. That asymmetry is why length beats complexity, and why a")
    note("defender's best move is to SLOW each guess (see Part 4).")

# ═════════════════════════════════════════════════════════════════════════════
# PART 2 — brute force in practice (on a FAST hash, so it's crackable live)
# ═════════════════════════════════════════════════════════════════════════════
def sha256_hex(b): return hashlib.sha256(b).hexdigest()

def brute_force(target_hex, charset, max_len, budget_attempts=8_000_000, budget_sec=20):
    attempts, t0 = 0, time.perf_counter()
    for length in range(1, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            attempts += 1
            if sha256_hex("".join(combo).encode()) == target_hex:
                return "".join(combo), attempts, time.perf_counter() - t0
            if attempts >= budget_attempts or time.perf_counter() - t0 > budget_sec:
                return None, attempts, time.perf_counter() - t0
    return None, attempts, time.perf_counter() - t0

def part2_brute_force():
    title("PART 2 — BRUTE FORCE, FOR REAL (fast hash)")
    victim = "safe"                       # 4 lowercase chars, so it cracks quickly
    charset = string.ascii_lowercase
    target = sha256_hex(victim.encode())
    note(f"Victim password (secret): hidden. Its SHA-256 is public if the DB leaks:")
    note(f"   stored hash = {target}")
    note(f"Attacker tries every combination of {len(charset)} letters, length 1..{len(victim)}:\n")

    found, attempts, elapsed = brute_force(target, charset, max_len=len(victim))
    rate = attempts / elapsed if elapsed else 0
    note(f"   CRACKED: '{found}'  after {attempts:,} guesses in {elapsed:.2f}s")
    note(f"   effective rate ≈ {rate:,.0f} guesses/sec (pure-Python SHA-256, one core)\n")
    note("Extrapolate that SAME rate to bigger passwords:")
    for L, cs, cslabel in [(8, 26, "lower"), (8, 62, "mixed+digits"), (12, 95, "full")]:
        secs = cs ** L / rate
        note(f"   length {L}, {cslabel:<12} → {cs}^{L} / {rate:,.0f}/s ≈ {human_time(secs)}")
    note("\nEven this toy cracker shows the cliff: 4 chars fall instantly, but a")
    note("random 12-char password is out of reach — as long as the hash is slow")
    note("enough to keep the guess rate low (Part 4).")

# ═════════════════════════════════════════════════════════════════════════════
# PART 3 — why real passwords fall FAST (they are not random)
# ═════════════════════════════════════════════════════════════════════════════
def dict_attack(target_hex, candidates):
    t0 = time.perf_counter()
    for i, guess in enumerate(candidates, 1):
        if sha256_hex(guess.encode()) == target_hex:
            return guess, i, time.perf_counter() - t0
    return None, len(candidates), time.perf_counter() - t0

def profile_guesses(name, year):
    bases = [name, name.capitalize(), name.upper()]
    tails = ["", "123", "!", "1", str(year), str(year)[-2:]]
    return [b + t for b in bases for t in tails]

def part3_dictionary():
    title("PART 3 — IN REALITY, PASSWORDS ARE NOT RANDOM")
    note("The slide's point: people reuse common words, patterns, and personal")
    note("info. So the attacker doesn't search 52^8 — only a tiny relevant set.\n")

    common = ["123456", "password", "qwerty", "aaaa", "abc123", "asdfg",
              "111111", "letmein", "iloveyou", "admin", "monkey", "password123"]
    victim = "abc123"                       # a pattern straight off the slide
    found, tried, el = dict_attack(sha256_hex(victim.encode()), common)
    note(f"(a) Common-list attack — wordlist of {len(common)} patterns:")
    note(f"    CRACKED '{found}' as guess #{tried} in {el*1000:.2f} ms — length was irrelevant.\n")

    # personal-info-derived (social engineering)
    name, year = "john", 1990
    victim2 = "john1990"                     # derived from name + birth year
    candidates = profile_guesses(name, year)
    found2, tried2, el2 = dict_attack(sha256_hex(victim2.encode()), candidates)
    note(f"(b) Targeted attack — attacker knows the name '{name}' and birth year {year}:")
    note(f"    generates {len(candidates)} obvious variants, e.g. {candidates[:4]} …")
    note(f"    CRACKED '{found2}' as guess #{tried2} in {el2*1000:.2f} ms.\n")
    note("Lesson: a long password that is still a WORD or PATTERN has a small")
    note("effective search space. Randomness is what makes length count.")

# ═════════════════════════════════════════════════════════════════════════════
# PART 4 — the defence (tie back to pwstore.py / Argon2id)
# ═════════════════════════════════════════════════════════════════════════════
def part4_defense():
    title("PART 4 — THE DEFENCE: SHRINK THE ATTACKER'S RATE")
    note("A defender controls two levers against everything above:\n")
    note("  1. Force a large RANDOM search space (length + true randomness).")
    note("     This kills dictionary/pattern attacks — the word isn't in any list.\n")
    note("  2. SLOW each guess with a memory-hard hash (Argon2id, from pwstore.py).")
    try:
        from argon2.low_level import hash_secret_raw, Type
        import secrets
        salt = secrets.token_bytes(16)
        t0 = time.perf_counter()
        hash_secret_raw(b"password123", salt, time_cost=2, memory_cost=19*1024,
                        parallelism=1, hash_len=32, type=Type.ID)
        per_guess = time.perf_counter() - t0
    except Exception:
        per_guess = 0.03  # fallback estimate if argon2 not installed
    fast_rate = 5e8       # a modest GPU SHA-256 rate, for contrast
    slow_rate = 1 / per_guess
    note(f"     one Argon2id guess here ≈ {per_guess*1000:.0f} ms  → only ~{slow_rate:,.0f} guesses/sec")
    note(f"     compare a fast hash on a GPU  → ~{fast_rate:,.0f} guesses/sec\n")

    space = 62 ** 8
    note("Cracking a RANDOM 8-char mixed password (62^8):")
    note(f"   fast hash  : {human_time(space/fast_rate)}")
    note(f"   Argon2id   : {human_time(space/slow_rate)}")
    note("\nStrong-and-random defeats the wordlist; slow hashing defeats the brute")
    note("force. You need both — that is exactly what pwstore.py demonstrated.")

def lesson():
    print("═" * 70)
    print("  PASSWORD SEARCH SPACE — a cracking lesson (education only)".center(70))
    print("═" * 70)
    note("Cracks only hashes generated in this script. See the ETHICS note in the file.")
    part1_search_space()
    part2_brute_force()
    part3_dictionary()
    part4_defense()

# ── optional: let a student brute-force a password THEY choose ────────────────
def try_password(pw):
    title(f"BRUTE-FORCE A PASSWORD YOU CHOSE: '{pw}'")
    if pw.islower() and pw.isalpha():
        charset, label = string.ascii_lowercase, "a-z (26)"
    elif pw.isalnum() and pw.islower():
        charset, label = string.ascii_lowercase + string.digits, "a-z0-9 (36)"
    else:
        charset, label = string.ascii_letters + string.digits, "a-zA-Z0-9 (62)"
    note(f"charset: {label}, length {len(pw)}, search space {len(charset)}^{len(pw)} = {len(charset)**len(pw):.2e}")
    target = sha256_hex(pw.encode())
    found, attempts, el = brute_force(target, charset, max_len=len(pw))
    if found is not None:
        note(f"CRACKED '{found}' after {attempts:,} guesses in {el:.2f}s ({attempts/el:,.0f}/s)")
    else:
        rate = attempts / el if el else 1
        est = len(charset) ** len(pw) / rate
        note(f"gave up after {attempts:,} guesses in {el:.1f}s (budget hit) — that's the point.")
        note(f"at this rate the full space would take ≈ {human_time(est)}")

if __name__ == "__main__":
    if "--try" in sys.argv:
        i = sys.argv.index("--try")
        if i + 1 < len(sys.argv):
            try_password(sys.argv[i + 1])
        else:
            print("usage: uv run crack.py --try <password>")
    else:
        lesson()