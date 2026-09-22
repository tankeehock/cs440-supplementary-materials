# Password Cracking — the search space, shown by cracking

CS440 AY26T1 · Kee Hock · uv + Python, one file

You will watch a password die. Not a hypothetical one — a real SHA-256 hash,
brute-forced in front of you in under a second. Then you will watch the same
attack fail against a password four characters longer, and you will be able to
say *exactly why*, in arithmetic, before you run it.

Everything happens in one script, `password-cracking.py`, on your own machine.
No wordlist downloads, no hashcat, no internet, and no hash that the script did
not create itself.

> **Ethics.** This script cracks only hashes it generates inside its own
> process. Cracking passwords, accounts, or systems you do not own is illegal.
> The lesson here is entirely defensive: you attack a password in order to
> learn what makes one survive.

### How to work through this

About **45 minutes** for sections 0-5, plus 20 for the extensions. Sections 1-4
are one 25-second run of the script — read them *alongside* the transcript, not
after it. Do section 5 (`--try`) on a password you have actually used; that is
the part students remember.

This is the **attacker's half** of week 6. Run it first, then
[`../simple-password-auth/`](../simple-password-auth/README.md) builds the
defence it argues for. Together they sit between week 4 (`hashes.py`, where you
learned what a hash *is* and met password storage for the first time) and week 7
(what the system does with you *after* it decides you are who you claim).

## Objective

**By the end you will be able to compute a password's search space, estimate
how long an offline attacker needs to exhaust it at a given guess rate, and
explain why a defender's two levers — randomness and slow hashing — are the
only ones that matter.**

The lab reaches that objective by **count it, crack it, shrink it**: you first
compute how big the space is on paper, then actually crack a password to turn
"guesses per second" from a slide number into a measured one, then watch real
(non-random) passwords collapse that space to nothing — and finally see the
defence put the rate back down where it belongs.

### How each activity builds the objective

Each part has a narrow objective and demonstrates its lesson with something you
can see happen on screen:

| Activity | Objective (what you do) | What it demonstrates (the learning value) |
|---|---|---|
| **1. The arithmetic** | Compute `alphabet ^ length`, divide by an attacker's rate | Length and alphabet are **exponents**; attacker hardware is only a **divisor**. That asymmetry is the whole lesson. |
| **2. Brute force, for real** | Crack a 4-character password from its SHA-256 | "Guesses per second" becomes a number *you measured*, and the extrapolation from 4 → 8 → 12 characters becomes credible. |
| **3. Passwords are not random** | Crack `abc123` and `john1990` from tiny wordlists | The **theoretical** space is not the **effective** space. A pattern has entropy near zero no matter how long it is. |
| **4. The defence** | Time one Argon2id hash; recompute the same crack | A defender cannot shrink the attacker's hardware — but can shrink the attacker's **rate**, by five or six orders of magnitude. |
| **5. Workshop** (`--try`) | Brute-force a password *you* choose | You feel the cliff personally: the run that returns instantly, and the run that gives up. |
| **6. What to actually do** | Turn the findings into a personal policy | Every recommendation is traced to something you watched happen, so none of it is folklore. |
| **7. Extensions** (optional) | Six small edits to the script | Settles the questions the lesson raises but does not answer — masks, mangling rules, and why salting does *not* slow this crack. |

### The five ideas the activities make concrete

Read these once and refer back; each activity above turns one of them into
something you can run.

1. **The search space is `alphabet ^ length`.** An 8-character password drawn
   from the 52 letters `a-z A-Z` has `52^8 ≈ 5.35 × 10^13` possibilities. That
   number is the *entire* security of the password against brute force. Nothing
   else about it matters.

2. **Exponent beats divisor.** Adding one character *multiplies* the space by
   the alphabet size. Buying a GPU a thousand times faster only *divides* the
   time by a thousand. A defender who adds four characters has already outrun a
   decade of the attacker's hardware budget — which is why **length beats
   complexity**, and why a 20-character passphrase beats `P@ssw0rd!`.

3. **The effective search space is what the attacker actually searches.**
   `correcthorsebatterystaple` is 25 characters, but if it is on a list, it is
   guess number *n* in that list. Real attackers do not start at `aaaaaaaa`;
   they start with leaked-password corpora, then mangling rules (`Password` →
   `P@ssw0rd123!`), then personal information. **Randomness is what makes
   length count.** And in the limiting case — a password you *reused* on a site
   that was breached — the effective space is **1**, which is Part 3(c).

4. **The threat model here is the *offline* attack.** The premise of every part
   of this lab is that the password database has already leaked. The attacker
   holds the hashes and runs guesses on their own hardware, at their own pace —
   no login form, no rate limit, no lockout, no logging. This is why "we lock
   the account after 5 attempts" is not an answer to anything in this script.

5. **The defender has exactly two levers.** Grow the space (length × true
   randomness), and slow each guess (a memory-hard hash such as Argon2id). One
   without the other fails: a slow hash does not rescue `password123`, and a
   random password stored under fast SHA-256 is one GPU-day away. You need
   both — which is the subject of the companion lab,
   [`../simple-password-auth/`](../simple-password-auth/README.md).

## Code map: which activity lives where in `password-cracking.py`

The whole lab is one file. Every landmark below is a **literal, searchable
string** in the source — open the file and search for it, or from a terminal
run e.g. `grep -n "PART 3" password-cracking.py` to jump to the exact line.

| Lab activity | Command | Search this tag | What you'll find |
|---|---|---|---|
| **1. The arithmetic** | (default run) | `PART 1` | `part1_search_space()` — the slide's example, then the two sweep tables |
| **2. Brute force, for real** | (default run) | `PART 2` | `part2_brute_force()`, driven by `brute_force()` — the `itertools.product` odometer |
| **3. Passwords are not random** | (default run) | `PART 3` | `part3_dictionary()`, `dict_attack()`, `profile_guesses()` |
| **4. The defence** | (default run) | `PART 4` | `part4_defense()` — times a live Argon2id hash |
| **5. Workshop** | `--try <pw>` | `try_password` | charset inference, then the same `brute_force()` under a budget |
| *time formatting* | — | `human_time` | seconds → days/years, with `SECONDS_PER_YEAR = 3.15e7` (the slide's `3 × 10^7`) |

Two things worth noticing while you read:

- **`brute_force()` is an odometer.** `itertools.product(charset, repeat=length)`
  generates `aaaa, aaab, aaac, …` in order, wrapped in a loop over lengths
  1..max. There is no cleverness in it at all — that is the point. Brute force
  is the *dumbest* possible attack, and it is the one the arithmetic in Part 1
  is about.
- **The attack is `guess → hash → compare`.** Look at the single line inside
  the loop: `sha256_hex(...) == target_hex`. The attacker never reverses the
  hash, because a hash cannot be reversed. They re-do the defender's
  computation, over and over. Every defence in Part 4 works by making that one
  line slower.

## 0. Setup

The only requirement is [uv](https://docs.astral.sh/uv/). You do not need
Python installed and you do not need to install anything else —
`password-cracking.py` declares `argon2-cffi` in a
[PEP 723](https://peps.python.org/pep-0723/) header, so `uv run` fetches an
interpreter and builds a throwaway environment on the first run.

```bash
cd week-6/cracking
uv run password-cracking.py
```

The first run takes a few seconds while uv downloads `argon2-cffi`; after that
it is instant. The command is identical on Windows, macOS and Linux. The whole
lesson takes about 25 seconds to run end to end and writes nothing to disk.

> Unfamiliar with a term — *mask attack*, *KDF*, *memory-hard*, *credential
> stuffing*? There is a [glossary](#glossary) at the end of this sheet.

```bash
uv run password-cracking.py              # the full guided lesson, Parts 1-4
uv run password-cracking.py --try abcd   # Part 5: brute-force a password you pick
```

---

## 1. The arithmetic

- **Objective:** compute a search space, and see what moves it.
- **Concept tested:** `alphabet ^ length`; exponent vs divisor.
- **Code:** `PART 1` → `part1_search_space()`.

Run the lesson and read the first block. It starts with the slide's own
example, worked in full:

```
     52 characters (a-z, A-Z), length 8   → 52^8 = 5.35e+13 passwords
     attacker rate 10^6 guesses/sec       → 5.35e+13 / 1e6 = 5.35e+07 sec
     in years (1 yr ≈ 3e7 sec)            → 1.7 years (worst case)
     on average you find it in half that  → 0.8 years
```

Three things to take from those four lines:

- **Worst case vs average.** Exhausting the space is the worst case. On average
  the attacker finds the password halfway through, so **divide by two**. This
  is why "it would take 1.7 years" should always be heard as "about 10 months".
- **`1 year ≈ 3 × 10^7 seconds`** is the only conversion you need to do this
  arithmetic in your head. Memorise it.
- **1.7 years is not a long time.** For an offline attack on a leaked database,
  the attacker has as long as they like. An 8-character password from a
  52-character alphabet — which passes most corporate password policies — is
  *already* insufficient at a rate that a single 2010-era CPU could sustain.

Then two sweep tables show what actually moves the answer. Here is the first,
holding length at 8 and growing the alphabet:

```
                     1e6/sec (CPU)     1e9/sec (GPU)    1e12/sec (rig)
  lower a-z  L=8          2.4 days       3.5 minutes     0.209 seconds
  +digits    L=8         32.7 days      47.0 minutes     2.821 seconds
  +UPPER     L=8         6.9 years          2.5 days       3.6 minutes
  +symbols   L=8       210.6 years         76.8 days         1.8 hours
```

and the second, holding the alphabet at 95 and growing the length:

```
  95-char   L=6            8.5 days      12.3 minutes     0.735 seconds
  95-char   L=8         210.6 years         76.8 days         1.8 hours
  95-char   L=10     1.90e+06 years     1,900.8 years         1.9 years
  95-char   L=12     1.72e+10 years    1.72e+07 years    1.72e+04 years
```

**Read both tables the same way — left to right is the attacker's budget, top
to bottom is the defender's choice.** Moving one column right (a 1000× faster
attacker) costs the defender about two characters. Moving one *row* down in the
second table costs the attacker a factor of `95^2 ≈ 9000`. The defender wins
that race trivially, and for free, by pressing two more keys.

Notice also that the two tables are not equally powerful. Going from `a-z` to
the full 95-character keyboard at length 8 buys a factor of about 88,000. Going
from length 8 to length 12 at the *same* alphabet buys a factor of
`95^4 ≈ 81,000,000`. **Length is the stronger lever**, and it is also the one
users can actually comply with — nobody forgets a four-word passphrase, and
everybody forgets which character they replaced with `@`.

### Where `1e6`, `1e9` and `1e12` come from

The three columns are not arbitrary. Roughly:

| Column | What achieves it |
|---|---|
| `1e6/sec` | A scripting-language loop on one core — about what you will measure in Part 2. Also a fair number for a *slow* hash on good hardware. |
| `1e9/sec` | One modern CPU using all cores and SIMD, on a fast hash. |
| `1e12/sec` | A small GPU rig. A single current gaming card runs SHA-256 at roughly 10<sup>10</sup>/sec and MD5 at roughly 10<sup>11</sup>/sec; eight in one box puts MD5 and NTLM past 10<sup>12</sup> and SHA-256 around 10<sup>11</sup>. Such a box rents by the hour. |

Do not take those on trust — `hashcat -b` prints the benchmark for every
algorithm on whatever machine you run it on, and the numbers are published for
most cards. The point is only that **the right-hand column is not science
fiction; it is a weekend purchase or an afternoon's cloud spend.** Design
against it.

Notice which algorithm you are benchmarking, too. The same card that does
10<sup>11</sup> MD5 guesses per second does only a few thousand bcrypt guesses
per second, and fewer still for Argon2id. **The algorithm choice moves the
attacker between columns more violently than their hardware budget does** —
which is Part 4.

### The same numbers in bits — the vocabulary everyone else uses

Every other source you read — NIST, your password manager's strength meter,
academic papers — measures passwords in **bits of entropy** rather than raw
counts. It is the same arithmetic with a logarithm on top:

```
    H  =  L × log₂(N)          H = bits, L = length, N = alphabet size
```

because `N^L = 2^(L × log₂ N)`. One bit is one doubling, so **every extra bit
doubles the attacker's work**, and the useful conversions are:

| Per character of… | is worth |
|---|---|
| lowercase (`N=26`) | 4.7 bits |
| alphanumeric (`N=62`) | 5.95 bits |
| full keyboard (`N=95`) | 6.6 bits |
| one Diceware word (`N=7776`) | **12.9 bits** |

Two things fall out immediately. First, a single dice-chosen word is worth
about **two full-keyboard characters** (12.9 ÷ 6.6 ≈ 2) — which is why
passphrases win on both strength and memorability: six words beats twelve
random symbols you will never remember. Second, the year tables collapse into
one rule of thumb worth memorising:

> **At `1e12` guesses/sec, 80 bits ≈ 35,000 years — and every 10 bits is ×1000.**

So 70 bits is ~35 years, 60 bits is ~12 days, 50 bits is ~20 minutes. Now you
can price any password in your head. Here are the recipes that matter, with the
Part 1 tables re-expressed:

| Recipe | Bits | At `1e12`/sec (fast hash) |
|---|---|---|
| 8 random lowercase | 37.6 | 0.2 seconds |
| 8 random alphanumeric | 47.6 | 3.6 minutes |
| 8 random full keyboard | 52.6 | 1.8 hours |
| **4 Diceware words** | 51.7 | 1 hour |
| **6 Diceware words** | 77.5 | 7,000 years |
| 12 random full keyboard | 78.8 | 17,000 years |
| 16 random alphanumeric (manager-generated) | 95.3 | 1.5 billion years |

**The caveat that makes Part 3 necessary.** `H = L × log₂(N)` is only valid if
every character was chosen **uniformly at random**. It describes the *generator*,
not the string. `Password1!` is 10 characters from an alphabet of 95 and the
formula happily says 65 bits — but a human chose it, so its real entropy is
closer to **10 bits**, and Part 3 will crack it from a list. Never apply the
formula to a password a person invented; it is a measure of dice, not of
keyboards.

---

## 2. Brute force, for real

- **Objective:** measure a guess rate rather than assume one, then extrapolate.
- **Concept tested:** the offline attack loop, `guess → hash → compare`.
- **Code:** `PART 2` → `part2_brute_force()`, `brute_force()`.

Part 2 stops talking and cracks something:

```
  Victim password (secret): hidden. Its SHA-256 is public if the DB leaks:
     stored hash = 8b3369944dd2a3fab39e32d1aeb1f763946a458ae3e6368a46432adc8f3a0860
  Attacker tries every combination of 26 letters, length 1..4:

     CRACKED: 'safe'  after 334,781 guesses in 0.18s
     effective rate ≈ 1,867,010 guesses/sec (pure-Python SHA-256, one core)
```

Your hash will match exactly — SHA-256 is deterministic and unsalted here, so
every student in the room gets the same 64 hex characters for `safe`. **That is
itself the lesson of the companion lab**: with no salt, one precomputed table
cracks everyone at once. Compare this with the two different hashes alice and
bob get for the *same* password in
[`../simple-password-auth/`](../simple-password-auth/README.md).

Your *rate* will differ, because it is your laptop. The script then reuses your
measured rate — not a slide number — to extrapolate:

```
     length 8, lower        → 26^8 / 1,867,010/s ≈ 1.3 days
     length 8, mixed+digits → 62^8 / 1,867,010/s ≈ 3.7 years
     length 12, full         → 95^12 / 1,867,010/s ≈ 9.19e+09 years
```

Four characters fell in 0.18 seconds. Twelve outlast the universe. The cliff
between them is the entire subject of the lab.

### Caveat: this rate is a floor, not the attacker's rate

Be honest with yourself about what ~1.9 million/sec measures. It is
**Python loop overhead**, not cryptography. `hashlib.sha256` is compiled C and
is not the bottleneck; building a tuple, joining it into a string, encoding it
to bytes and comparing hex strings is. A real attacker runs
[hashcat](https://hashcat.net/) on a GPU and does **tens of billions** of
SHA-256 guesses per second — four to five orders of magnitude above what you
just measured.

So when you read `length 8, mixed+digits → 3.7 years`, mentally divide by
10,000. A random 8-character mixed-case-and-digits password, stored under
SHA-256, falls to a single rented GPU in **hours**. This script's slowness
flatters the defender; the arithmetic in Part 1, with the `1e12/sec` column, is
the honest one.

---

## 3. In reality, passwords are not random

- **Objective:** separate the *theoretical* search space from the *effective* one.
- **Concept tested:** dictionary attacks and targeted (OSINT-driven) guessing.
- **Code:** `PART 3` → `part3_dictionary()`, `dict_attack()`, `profile_guesses()`.

Everything in Parts 1 and 2 assumed the password was drawn **uniformly at
random**. It almost never is. Part 3 runs two attacks that ignore the
arithmetic entirely.

**(a) The common-list attack.** Twelve entries, one of which is the victim's:

```
  (a) Common-list attack — wordlist of 12 patterns:
      CRACKED 'abc123' as guess #5 in 0.01 ms — length was irrelevant.
```

Five guesses. Not `36^6 = 2.2 billion` — *five*. The theoretical space was
never searched because the password was never drawn from it. Real wordlists are
not 12 entries; `rockyou.txt` is 14 million, and modern corpora built from
breach dumps run into the billions, ordered by observed frequency so the most
likely candidates come first.

**(b) The targeted attack.** The attacker knows the name `john` and the birth
year `1990` — from LinkedIn, from a conference bio, from the CT-log
reconnaissance you did in week 5:

```
  (b) Targeted attack — attacker knows the name 'john' and birth year 1990:
      generates 18 obvious variants, e.g. ['john', 'john123', 'john!', 'john1'] …
      CRACKED 'john1990' as guess #5 in 0.00 ms.
```

Read `profile_guesses()` — it is six lines. Three capitalisations crossed with
six suffixes. That is the *entire* attack, and it is a fair model of what a real
rule-based cracker does, just with 30,000 rules instead of 18.

`john1990` is 8 characters from a 62-character alphabet. Part 1 says `62^8`, or
**6.9 years at 1e6/sec**. It fell in 5 guesses and zero milliseconds. **The
password's length told you nothing about its strength.**

This is the single most important idea in the lab: *entropy is a property of
the process that generated the password, not of the string.* `Tr0ub4dor&3` and
`correct horse battery staple` — the xkcd pair — are the canonical illustration.
The first looks random and is not; the second looks simple and is, if the four
words were chosen by dice rather than by a human.

### (c) The attack you will actually meet: credential stuffing

There is a third case the script does not model, and it is the most common one
in practice. The effective search space is not small — **it is one.**

An attacker does not crack your bank password. They take the username and
password you used on a forum that was breached three years ago, and they try
that exact pair on two hundred other sites, automatically. If you reused it,
they are in on the first guess. No hashing, no wordlist, no GPU — the password
was already cracked, by someone else, somewhere else, and the only thing being
tested is whether you reused it.

This reframes everything above:

- **Strength does not help.** A 90-bit password that you used on two sites is,
  on the second site, worth exactly zero bits once the first one leaks. All the
  arithmetic in Part 1 assumed the attacker has to *guess*. Here they do not.
- **Uniqueness is a separate property from strength**, and for most people it is
  the one that is actually failing. This is the single strongest argument for a
  password manager — not that it generates strong passwords, but that it makes
  *unique* ones free, and nobody can remember two hundred unique passwords
  without one.
- **It explains the defences that Parts 1-4 cannot justify.** MFA does nothing
  against an offline crack, but it is decisive against credential stuffing,
  because the replayed password is no longer sufficient. So is a
  breached-password screen at registration, which is why
  [Have I Been Pwned](https://haveibeenpwned.com/) exists and why the OWASP
  cheat sheet asks you to call it.

**A three-line exercise.** Go to Have I Been Pwned and enter an email address
you control. The result is a list of breaches your credentials are already in.
Then ask the only question that matters: *is the password from any of those
breaches still in use anywhere?* That is your real exposure, and no amount of
the arithmetic in Part 1 addresses it.

---

## 4. The defence: shrink the attacker's rate

- **Objective:** see the defender's second lever measured, not asserted.
- **Concept tested:** memory-hard hashing as a rate limit that survives a leak.
- **Code:** `PART 4` → `part4_defense()`.

The defender cannot confiscate the attacker's GPU. They *can* make each guess
cost 22 milliseconds instead of 0.2 nanoseconds, by storing passwords under a
deliberately slow, memory-hard function:

```
       one Argon2id guess here ≈ 22 ms  → only ~46 guesses/sec
       compare a fast hash on a GPU  → ~500,000,000 guesses/sec

  Cracking a RANDOM 8-char mixed password (62^8):
     fast hash  : 5.1 days
     Argon2id   : 1.52e+05 years
```

**Five days versus a hundred thousand years and more, for the same password.**
Nothing about the password changed. The only thing that changed is how the
defender stored it.

> **Your numbers will differ, and only some of them should.** The `fast hash`
> row is fixed — the script assumes a flat 5×10⁸ guesses/sec for it. The
> Argon2id row is *measured on your machine*, so a faster laptop reports a
> faster per-guess time and correspondingly fewer years. Anything from roughly
> 15 to 40 ms per guess is normal. What does **not** move is the conclusion: the
> gap stays in the range of "days" against "longer than you will be alive".

Two details worth pausing on:

- **Why *memory*-hard and not just slow?** A GPU has thousands of tiny cores and
  very little memory per core. Argon2id is configured here to need 19 MiB per
  hash, so a card with 8 GiB of memory can run only ~430 of them at once no
  matter how many cores it has. Memory-hardness attacks the attacker's
  *parallelism*, which is the thing that made GPUs devastating against SHA-256
  in the first place.
- **The cost is paid by both sides, asymmetrically.** The defender pays 22 ms
  once per login. The attacker pays 22 ms **per guess**, times the whole search
  space. That asymmetry is the entire design.

And the limit, stated plainly in the script: slow hashing does *not* rescue
`password123`. Part 3's wordlist attack still finds it, just at 46 guesses per
second instead of a billion — and 5 guesses at 46/sec is still a third of a
second. **You need both levers.** Part 4 ends by pointing at the companion lab,
which is where the storage side is built properly.

---

## 5. Workshop — brute-force a password you chose

- **Objective:** feel the cliff on a password you picked yourself.
- **Code:** `try_password` → `brute_force()` under a budget.

```bash
uv run password-cracking.py --try abcd
```

```
  charset: a-z (26), length 4, search space 26^4 = 4.57e+05
  CRACKED 'abcd' after 19,010 guesses in 0.01s (1,834,387/s)
```

Now add characters and watch it stop working:

```bash
uv run password-cracking.py --try zzzzz     # 26^5  — budget hit
uv run password-cracking.py --try Tr0ub4    # 62^6  — "≈ 9.4 hours"
```

```
  charset: a-zA-Z0-9 (62), length 6, search space 62^6 = 5.68e+10
  gave up after 8,000,000 guesses in 4.8s (budget hit) — that's the point.
  at this rate the full space would take ≈ 9.4 hours
```

Three honest caveats about this mode, all of which are good discussion:

1. **"Gave up" means the budget ran out, not that the password is safe.** The
   cracker stops after 8,000,000 attempts or 20 seconds, whichever comes first
   (`budget_attempts` / `budget_sec` in `brute_force()`). `--try zzzzz` reports
   giving up *and* estimates the full space at under seven seconds — because
   `zzzzz` is the very last string in the odometer's order, and 8 million
   guesses was not quite the 11.9 million needed to reach it. A real attacker
   with a ten-minute budget would have it. **The budget is the lab's patience,
   not the attacker's.**
2. **The charset is inferred from your password, and generously.** A digits-only
   password like `123456` has no cased characters, so `islower()` is false and
   it falls through to the 62-character alphabet — reporting `62^6` when the
   attacker would obviously try `10^6` first, ten thousand times faster. The
   script is *too kind* to that password. Real crackers infer nothing; they
   follow a mask or a rule set.
3. **It starts at length 1.** So most of the reported guess count is spent on
   shorter passwords than yours. That is realistic — an attacker does sweep
   short lengths first, because they are nearly free.

**Try this.** Pick a password you have actually used, and before running it,
write down: its alphabet, its length, its search space, and the time at
`1e12/sec`. Then run `--try` on it. The estimate the script prints and the one
you computed should agree to an order of magnitude. If your hand-computed
number is under a day, change that password today.

---

## 6. So what should you actually do?

This is the part of the lab that changes your behaviour rather than your
vocabulary. Every recommendation below is traceable to something you just
watched happen — the point is that none of it is folklore.

**Use a password manager for everything you do not have to memorise.** Let it
generate 16+ random characters and never look at them. *Why:* 16 alphanumeric
characters is ~95 bits (section 1's table), which is out of reach in every
column of every table in this lab — and it makes uniqueness free, which is the
only defence against Part 3(c).

**Memorise three passwords, not thirty.** Realistically you must be able to
type, from memory: your device login, your password-manager master password,
and your email password (because email is the reset path for everything else).
Everything else lives in the manager. *Why:* Part 3 showed what happens when
humans are asked to invent many passwords — they produce patterns.

**Make those three Diceware passphrases.** Roll physical dice or use your
manager's generator against the EFF long wordlist, and take **six words** for
the master password, five for the rest. *Why:* six words is 77.5 bits, which the
bits table prices at ~7,000 years against a `1e12`/sec rig on a *fast* hash, and
effectively never against a slow one (answer key 5). And unlike `Xk7#mQ2$`, you
can actually remember it.

**Turn on MFA wherever it is offered, starting with email.** *Why:* it is the
only control in this list that defeats Part 3(c), because it breaks the
assumption that a correct password is sufficient.

**Check your addresses on Have I Been Pwned, and rotate anything that appears.**
*Why:* rotation on a schedule is theatre; rotation on *evidence* is the whole
point.

And the things **not** to do, each one refuted by a specific part of this lab:

| Don't | Because |
|---|---|
| Substitute `@` for `a`, `0` for `o`, `!` for `i` | Part 3 — mangling rules are the *first* thing a cracker applies. `P@ssw0rd!` is `password` plus three rules. |
| Use a base password plus the site name (`Tiger-amazon`, `Tiger-gmail`) | Part 3(b) — this is exactly `profile_guesses()`, and real rule sets model it explicitly. |
| Rotate passwords every 90 days | Forced rotation drives users to `Spring2026!` → `Summer2026!`, which is a pattern with almost no entropy. NIST withdrew this advice in 2017. |
| Trust a website's strength meter that only counts character classes | It is computing `L × log₂(N)` on a human-chosen string — the exact mistake section 1 warns about. A good meter (zxcvbn) instead matches against wordlists and patterns. |
| Assume a long password is automatically a strong one | Part 3 — `john1990` and `correcthorsebatterystaple` are both long; only one was generated by a random process. |

---

## 7. Extensions (optional)

Each of these is a small edit to `password-cracking.py` that answers a question
the lesson raises but does not settle. They are ordered by effort.

**7.1 — Price your own password in bits.** No code. Take a password you use,
count its length and alphabet, compute `H = L × log₂(N)`, and look it up in the
rule of thumb (`80 bits ≈ 35,000 years at 1e12/sec; ±10 bits is ×1000`). Then
ask the Part 3 question: *was it generated by a random process?* If not, the
number you computed is fiction, and the honest estimate is "it is in a list".

**7.2 — Grow the wordlist.** In `part3_dictionary()`, extend `common` with
twenty passwords you would expect people to use. Re-run. The interesting
measurement is not whether it cracks — it is *how few* entries you needed. This
is the experiment that makes "14 million entries in `rockyou.txt`" feel large
rather than abstract.

**7.3 — Add a mangling rule.** Extend `profile_guesses()` with leetspeak
substitution (`a→@`, `o→0`, `i→1`) and a `capitalise + symbol + digits` variant.
Count the candidates before and after. You will roughly triple the list and
cover a large share of real "strong-looking" passwords — which is precisely the
trade a rule-based cracker makes, at a scale of ~30,000 rules.

**7.4 — Implement a mask attack.** `brute_force()` uses one charset for every
position. Change it to accept a per-position list — hashcat's
`?u?l?l?l?d?d?d?d` means "upper, three lower, four digits". Then compute the
space for that mask against the full `95^8`: the mask is `26 × 26³ × 10⁴ ≈
4.6 × 10⁹`, against `6.6 × 10¹⁵` — a factor of about **1.5 million**. That is
what an attacker buys by *guessing the shape* of your password instead of its
content, and it is why "capital letter, then letters, then a year" is a
catastrophic habit.

**7.5 — Salt the Part 2 hash, and be surprised.** Add
`salt = secrets.token_bytes(16)` and hash `salt + guess` in both `sha256_hex`
call sites. Re-run Part 2 twice and note that the stored hash changes every run.
Now answer carefully: **did the crack get slower?** It did not — and that is the
lesson. A salt does nothing against brute force on a *single known target*. What
it destroys is precomputation and amortisation across users (rainbow tables,
cracking 10,000 accounts for the price of one). Students who expect salting to
slow this crack have merged the salt's job with the KDF's, which is the most
common misconception the companion lab has to undo.

**7.6 — Re-price the defence.** In `part4_defense()`, raise `memory_cost` to
`64*1024` and `time_cost` to `4`, and re-run. Confirm that the guess rate falls
roughly in proportion and that the "Argon2id" row in the final comparison moves
with it. Then ask the operational question: how many logins per second can your
server absorb at that setting? That trade — user-visible latency against
attacker cost — is the real parameter-tuning decision, and it is the same one
the companion lab's `MEMORY_KIB` constant encodes.

---

## Glossary

Terms this lab uses, in the sense it uses them.

| Term | Meaning |
|---|---|
| **Search space** | The number of candidate passwords an attacker must consider: `alphabet^length` for a randomly generated password. |
| **Effective search space** | The number they *actually* try, given what they know about how the password was chosen. For a human-chosen password this is far smaller — often a few thousand. |
| **Entropy (bits)** | `log₂(search space)`. One bit = one doubling of the attacker's work. Valid only for randomly *generated* secrets. |
| **Brute force** | Trying every combination in order. The dumbest attack, and the one Part 1's arithmetic prices. |
| **Dictionary attack** | Trying entries from a list of likely passwords. Part 3(a). |
| **Wordlist / corpus** | The list itself. `rockyou.txt` (14 M entries, from a 2009 breach) is the classic teaching one; modern corpora are built from aggregated breach dumps. |
| **Mangling rules** | Transformations applied to each wordlist entry — capitalise, append digits, leetspeak. Multiplies a list's reach for almost no cost. Part 3(b), extension 7.3. |
| **Mask attack** | Brute force with a *per-position* charset, e.g. "upper, 3 lower, 4 digits". Exploits password *shape*. Extension 7.4. |
| **Credential stuffing** | Replaying a username/password pair leaked from one site against many others. Not cracking at all. Part 3(c). |
| **Rainbow table** | A precomputed `hash → password` lookup, amortised across many targets. Defeated entirely by salting — see the companion lab. |
| **Online vs offline attack** | *Online:* guessing at a live login form, where rate limiting and lockout apply. *Offline:* guessing against a stolen hash on your own hardware, where they do not. **This lab is entirely offline.** |
| **Hash rate** | Guesses per second, the divisor in every calculation here. Depends on the algorithm far more than on the hardware. |
| **KDF** | Key derivation function — a hash deliberately made slow and expensive, for storing passwords. Argon2id, scrypt, bcrypt, PBKDF2. |
| **Memory-hard** | A KDF that requires a large working memory per evaluation, to deny the attacker the massive parallelism a GPU otherwise provides. Part 4. |
| **Salt** | A unique, random, *non-secret* value hashed alongside each password so that no two users' computations are the same. Companion lab, activity 2. |
| **Pepper** | A *secret* value, stored outside the database, mixed into every hash. Different job from a salt. Companion lab, "Where this stops". |
| **hashcat / John the Ripper** | The standard password-recovery tools. `hashcat -b` benchmarks your hardware; this lab deliberately does not use them, but everything here is a toy model of what they do. |
| **Diceware** | Generating a passphrase by choosing whole words at random from a fixed list (the EFF long list has 7776 = 6⁵ words, so five dice rolls per word, 12.9 bits per word). |

---

## Predict before you run

Fill in the middle column from Part 1's arithmetic *before* running anything.
Use `1 year ≈ 3 × 10^7 seconds`.

| # | Question | Your prediction | Where to check |
|---|---|---|---|
| 1 | `26^8` at `1e9/sec` — minutes or years? | | Part 1, first table |
| 2 | Which is bigger: `95^8` or `26^12`? | | compute both |
| 3 | Part 2 cracks a 4-char password in ~0.2 s. How long for 5 chars? 6? | | multiply by 26 each time |
| 4 | `john1990` is 8 chars from 62. How many guesses will Part 3 need? | | Part 3(b) |
| 5 | Argon2id at 46 guesses/sec — how long to exhaust a 6-word dice passphrase (`7776^6`)? | | Part 4 |
| 6 | Does Part 4's slow hash save `password123`? | | Part 4's closing note |
| 7 | Two users pick the same password. Do the Part 2 hashes match? | | Part 2, vs the companion lab |
| 8 | How many bits is `Summer2026!`? How many bits is it *really*? | | Section 1, "the caveat" |
| 9 | Your password is 100 bits and unique to one site. That site is breached and its store was plaintext. What protected you? | | Part 3(c) |
| 10 | You add a random salt to Part 2's hash. Does the 4-character crack get slower? | | Extension 7.5 |

---

## Answer key (instructor)

1. **About 3.5 minutes** (`26^8 ≈ 2.09e11`, ÷ `1e9` ≈ 209 s). Students who
   answer "years" are anchoring on the 52-character example and have not
   noticed the alphabet shrink. Worth surfacing: lowercase-only is not a
   password policy, it is a formality.
2. **`26^12`** (`9.5e16`) beats **`95^8`** (`6.6e15`) by about 14×. This is the
   question that settles "length vs complexity" numerically: four extra
   characters from the *smallest* useful alphabet beat the entire symbol
   keyboard. It also reframes passphrases — a 4-word phrase from a
   7776-word list is `7776^4 ≈ 3.7e15`, comparable to the full-keyboard
   8-character password, and vastly easier to remember.
3. **~5 s, then ~2 minutes.** Each character multiplies by 26. The point of
   asking is that most students' intuition is *additive* — they guess
   "maybe twice as long" — and the exponent is the thing the lab exists to
   correct.
4. **5.** Guess #5 of 18. The intended shock is the gap between question 4's
   answer and the `62^8 ≈ 2.2e14` the same password's *shape* would suggest:
   **thirteen orders of magnitude**, purchased by the attacker knowing a name
   and a year.
5. **Effectively never** — `7776^6 ≈ 2.2e23` ÷ 46/sec ≈ `1.5e14` years, about
   ten thousand times the age of the universe. Pair it with question 2 to make
   the positive recommendation concrete: *a random multi-word passphrase, stored
   under a slow hash, is the whole answer.*
6. **No.** It buys time — 5 guesses at 46/sec is ~0.1 s instead of ~0.1 µs —
   and that is all. The defences are independent and both are required: a
   password policy and breach-corpus check for lever one, Argon2id for lever
   two. Students who answer "yes" have collapsed the two levers into one, which
   is the most common misconception in this topic.
7. **Yes, identical** — and that is a defect, not a feature. SHA-256 is
   unsalted and deterministic, so identical passwords produce identical hashes,
   one rainbow table cracks the whole database at once, and the leak itself
   reveals *which users share a password*. Run the companion lab's `--demo` for
   the contrast: alice and bob choose the same passphrase and their stored
   hashes are unrelated, because each got 16 random bytes of salt.

8. **65 bits by the formula, roughly 10 in reality.** `L=11`, `N=95` gives
   `11 × 6.6 ≈ 73` bits if you count the shift-symbols, ~65 if you are stricter
   about the alphabet — and both numbers are fiction, because a human produced
   it from the template *Season + Year + !*. There are perhaps a few hundred
   seasons-and-years and a handful of trailing symbols: call it 10-12 bits. This
   question is the fastest way to expose the strength-meter fallacy, and it is
   worth doing on the board before anyone runs anything.
9. **Nothing protected you, and nothing could have.** The site stored plaintext;
   your password's strength was never tested. This is the question that
   separates the two halves of week 6: password *strength* is the user's lever,
   password *storage* is the operator's, and the user cannot compensate for an
   operator who gets it wrong. What limits the damage is **uniqueness** (the
   breach does not open your other accounts) and **MFA** (the password alone is
   not sufficient) — neither of which is about strength at all.
10. **No.** The crack takes the same time, because there is one target and the
    attacker has the salt. Salting defeats *precomputation* and *amortisation
    across users*, not brute force against a known hash. Expect most of the room
    to get this wrong; it is the highest-value misconception in the topic, and
    extension 7.5 lets them prove it to themselves in two lines of code.

### Where to take the discussion next

- **NIST SP 800-63B** reversed the old advice in 2017: no composition rules, no
  forced rotation, minimum length 8 (15 for memorised secrets in the 2024
  revision), and *do* screen candidate passwords against breach corpora. Every
  one of those changes follows directly from Part 3 — rules push users toward
  patterns, and patterns are what the effective search space is made of.
- **Rate limiting is not in this lab, on purpose.** The whole script assumes the
  database already leaked. Lockouts, CAPTCHAs and MFA defend the *online* path;
  they do nothing here. Ask students which of their favourite defences survive
  the offline assumption — the honest answer is "length, randomness, and the
  KDF", which is exactly the objective.
- **Then go build the defence:** [`../simple-password-auth/`](../simple-password-auth/README.md)
  is the same story from the server's side — salting, Argon2id, constant-time
  comparison, and what an attacker gets from a store that was built correctly.

---

> **Ethics, restated.** Every hash this script cracks, it created moments
> earlier in its own memory. Nothing touches a network. Running the same
> techniques against a password, account, or system you do not own — or do not
> have written authorisation to test — is a crime in Singapore under the
> Computer Misuse Act and in most other jurisdictions. You learn the attack so
> that you can price the defence.
