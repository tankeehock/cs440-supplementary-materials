# Reverse-engineering lab — the secret is in the binary

> ### ⚠ Container-only, nothing sensitive
> This whole lab runs inside a throwaway Docker container (`docker run --rm`)
> that binds to nothing. The binary is a toy; the "flag" is a made-up string.
> The point is the *method* — reading a compiled program — not the secret.
> The week-10 README has the scope/legal note; it applies here.

You are handed a compiled program, `license-check`, that asks for a licence
key and says "Access granted" for exactly one correct answer. **You do not get
the source.** Your job is to recover the key by reading the binary, then type
it in to print the flag.

This is the foundational skill of the "rev" category in every CTF: a compiled
program is not a black box. The logic that checks your input is right there in
the machine code, and recovering it is a matter of knowing which tool to point
at it.

---

## Before you start: what a compiled program actually is

When you run `gcc license-check.c -o license-check`, the compiler translates
your C into **machine code** — raw bytes the CPU executes directly — and packs
it, together with the program's constant data, into one file in the **ELF**
format (Executable and Linkable Format, the standard on Linux). Crucially,
*translation is not hiding*: every string literal, every constant array, and
the exact sequence of operations all survive into the file. Reverse engineering
is just reading them back out.

An ELF file is divided into **sections**, and three of them matter here:

| Section | Holds | In this challenge |
| --- | --- | --- |
| `.text` | the machine-code **instructions** | the comparison loop that checks your key |
| `.rodata` | **read-only** constants (string literals, `const` arrays) | the encrypted key bytes and the string `"cs440"` |
| `.data` | writable globals with an initial value | (not interesting here) |

A **symbol** is a name the compiler attached to an address — a function like
`main` or a variable like `enc`. If the binary still has its symbols (it is
"not stripped"), your tools can print those names instead of bare addresses,
which makes reading it far easier.

### The tools, and what each one *reads*

Everything below is inside the container. Each tool reads a different view of
the same file:

| Tool | What it shows you | When you reach for it |
| --- | --- | --- |
| `file` | the ELF header — architecture, stripped?, etc. | first, to know what you're holding |
| `strings` | runs of printable bytes anywhere in the file | the cheap first look for readable secrets |
| `objdump -s` | a raw **hex dump** of a section's bytes | when the data isn't printable text |
| `objdump -d` | the **disassembly** — `.text` bytes turned back into assembly | to read the actual logic |
| `nm` | the symbol table (names → addresses) | to locate a function or variable fast |
| `gdb` | runs the program and inspects memory/registers **live** | to watch values the moment they're computed |

---

## Build and enter

```bash
cd week-10/reverse-engineering
docker build -t cs440-rev .
docker run -it --rm cs440-rev
```

`docker build` compiles the challenge *inside* the image (and then deletes the
source, so the only way in is through the compiled binary). `docker run -it
--rm` gives you an interactive shell and throws the container away on exit, so
you can experiment freely and reset by re-running. You land as the unprivileged
user `player` in `/home/player`.

First, meet the program:

```bash
./license-check
# Enter licence key: hello
# Denied.
```

One valid answer exists, and it is 18 characters long — far more combinations
than you could ever type. So read the program instead.

---

## Step 1 — identify what you are looking at

```bash
file license-check
```

`file` reads the first few bytes (the **magic number** `\x7fELF`) and the ELF
header, and reports what the file is:

> `ELF 64-bit LSB … x86-64 … dynamically linked … with debug_info, not stripped`

Read it field by field — each word changes how you'll approach it:

- **`ELF 64-bit … x86-64`** — a 64-bit Linux executable for Intel/AMD CPUs, so
  the assembly you'll read is x86-64, and addresses are 8 bytes wide.
- **`dynamically linked`** — it borrows `printf`, `fgets` etc. from the system
  C library at runtime rather than baking them in.
- **`not stripped` / `with debug_info`** — the symbol names survived. This is a
  gift: `objdump` will label the key arrays `<enc>` and `<key>` for you.
  (Real targets are usually *stripped*; then you work from addresses instead of
  names — the technique is identical, only less comfortable.)

## Step 2 — the first thing everyone tries: `strings`

```bash
strings license-check | grep -iE 'key|licence|flag|CS440|granted'
```

`strings` walks the whole file and prints every run of **four or more
printable characters** — it is how you spot passwords, URLs or flags that a
lazy program left lying around as plaintext. `grep -iE` just filters that
output to lines matching any of those words (`-i` = case-insensitive, `-E` =
the `|` means "or").

You will see the prompt `Enter licence key:`, the banners, and the template
`CS440{%s}`. **You will not see the key.** That `%s` is the tell: in C,
`printf("CS440{%s}", input)` builds the string *at runtime* from whatever you
typed — so the correct key is never stored as a literal anywhere in the file
for `strings` to find. This is the moment the lab is teaching: *"it's not in
`strings`" is the start of reverse engineering, not the end.*

## Step 3 — find the data the check uses

`strings` only prints *printable* runs. The key material here is stored as raw
(mostly non-printable) bytes, so dump the `.rodata` section's bytes directly:

```bash
objdump -s -j .rodata license-check
```

`-s` means "show the full contents of a section as hex", and `-j .rodata`
restricts it to the read-only-data section. Among the output:

```
 2010 11404207 4210406b 05433c12 6b475b52  .@B.B.@k.C<.kG[R
 2020 1f586373 34343000 456e7465 72206c69  .Xcs440.Enter li
```

How to read a hex-dump line: the leftmost column (`2010`) is the **address**;
the middle columns are the raw **bytes** in hex; the right column is those same
bytes shown as text (a `.` wherever a byte isn't printable). So at address
`0x2010` there are 18 noise bytes — `11 40 42 07 …` — and right after them, at
`0x201b`, the printable string `cs440`. Two constant arrays sitting side by
side. You don't yet know what they *mean* — so read the code that uses them.

## Step 4 — read the comparison loop

```bash
objdump -d -M intel license-check | less    # then type: /main  and press enter
```

`objdump -d` **disassembles** `.text`: it turns the machine-code bytes back
into human-readable assembly instructions. `-M intel` selects Intel syntax
(destination on the left, `dst, src` — easier to read than the default AT&T).
`| less` lets you scroll and `/main` jumps to the `main` function.

### Reading x86-64, just enough

You only need a handful of instructions to follow this loop. In Intel syntax
the **destination is first**:

| Instruction | Means |
| --- | --- |
| `mov dst, src` | copy `src` into `dst` |
| `lea dst, [addr]` | put the **address** `addr` into `dst` (not the value there) |
| `movzx dst, BYTE PTR [r]` | load **one byte** from the memory at address `r`, zero-extended into `dst` |
| `xor a, b` | `a = a XOR b` (bitwise) |
| `cmp a, b` | compare `a` and `b`, setting flags a later jump reads |

Also: `rip+0xNNN` is **RIP-relative addressing** — the CPU computes an address
as "here, plus an offset", which is how position-independent code refers to its
own constants. `objdump` helpfully resolves it and writes the target in a
comment, e.g. `# 2010 <enc>`.

With that, the heart of `main` reads like this (your addresses will match —
this binary is deterministic):

```asm
lea    rax,[rip+...]        # 2010 <enc>     ; address of the 18 noise bytes
lea    rax,[rip+...]        # 2022 <key>     ; address of the string "cs440"
...
movzx  esi,BYTE PTR [rax]   ; esi = input[i]       (your i-th character)
movzx  eax,BYTE PTR [rdx+rax*1]   ; eax = key[i % 5]   (indexes into "cs440")
xor    esi,eax              ; esi = input[i] XOR key[i % 5]
movzx  eax,BYTE PTR [rax]   ; eax = enc[i]          (the i-th noise byte)
cmp    dl,al                ; require: (input[i] XOR key[i%5]) == enc[i]
```

Because the binary isn't stripped, `objdump` even labels the arrays `<enc>` and
`<key>` in the comments. The logic falls out:

> for every byte *i*:  `input[i] XOR key[i % 5]  ==  enc[i]`

### Why that is trivial to invert

XOR has one property that makes this whole scheme worthless as protection:
**it is its own inverse**. For any bytes `a` and `k`, `(a XOR k) XOR k == a`.
So XOR both sides of the check by `key[i % 5]`:

> `input[i]  ==  enc[i] XOR key[i % 5]`

You already have both `enc` (Step 3) and `key` (`"cs440"`). The key is just
the one XORed with the other.

> **Prefer a live view?** Instead of reading hex, let `gdb` print the arrays
> the moment the program loads them:
> ```bash
> gdb -q license-check -ex 'break main' -ex run -ex 'x/18bx &enc' -ex 'x/5c &key' -ex quit
> ```
> `x` is gdb's "examine memory" command; the format `18bx` means *18 bytes in
> hex*, and `5c` means *5 bytes as characters*. It prints the same `enc` bytes
> and `cs440` you found with `objdump`, without reading the dump by hand.

---

<details>
<summary><b>Intended solution</b> — try the steps above first, then open this.</summary>

### Recover the key with the two arrays

`enc` (18 bytes, from `0x2010`) and `key` = `"cs440"`. Invert the XOR:

```bash
python3 - <<'PY'
enc = bytes([0x11,0x40,0x42,0x07,0x42,0x10,0x40,0x6b,0x05,
             0x43,0x3c,0x12,0x6b,0x47,0x5b,0x52,0x1f,0x58])
key = b"cs440"
# key[i] = enc[i] XOR cs440[i mod 5]  — XOR undoes XOR
print(bytes(enc[i] ^ key[i % len(key)] for i in range(len(enc))).decode())
PY
```

Output:

```
r3v3rs3_1s_a_sk1ll
```

### Collect the flag

```bash
echo -n 'r3v3rs3_1s_a_sk1ll' | ./license-check
# Access granted.
# Submit this as your flag:  CS440{r3v3rs3_1s_a_sk1ll}
```

(`echo -n` sends the key with **no trailing newline**; the `-n` matters because
the program compares the exact 18 bytes.) The recovered key *is* the flag —
which is why `strings` could never find it, and why you had to read the program.

</details>

---

## What this challenge is really teaching

- **Obfuscation is not encryption.** XORing the key with a constant that ships
  *next to it* in the same binary buys nothing: the attacker reading the binary
  has both halves, and XOR undoes itself. "Secret stored on the client" always
  means "secret the attacker has, in a format they will decode."
- **`strings` is step one, not the answer.** The real skill is what you do when
  the thing you want is *not* a printable string: find the right section, dump
  its bytes, then read the code that consumes them.
- **Compilation is reversible enough.** You reconstructed the exact check from
  machine code in about six instructions. Stripping and optimising make this
  harder, not impossible — that is the next rung of the same ladder.

### Want it harder?

Rebuild with the defences a real target would have and redo it:

```bash
#   gcc -O2 -s -o harder license-check.c
#     -s  strips symbols, so <enc>/<key> lose their names (work from addresses)
#     -O2 optimises, so the loop is less literal
```

The method does not change — `file`, then the data section, then the code —
only the amount of label-free reading you do. Then move on to
[`../buffer-overflow/`](../buffer-overflow/), where reading the binary is how
you *find* the bug.
