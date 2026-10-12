# Week 10 — Binary exploitation, in a box

> ### ⚠ Deliberately vulnerable, container-only
> Every challenge here is compiled with modern defences **switched off on
> purpose** so the classic techniques are visible. Each runs entirely inside a
> throwaway Docker container (`docker run --rm`) that binds to nothing — it
> never listens on a network and never touches your host. *Breaking the program
> inside the container is the exercise; the container is the scope.* Do not copy
> these build flags onto anything real, and do not run these techniques against
> software or hosts you do not own or have **written** authorisation to test.
> (§5 of the week-7 README has the legal note; it applies here too.)

Weeks 7 and 9 were about policy — who is *allowed* to do what, and how a
protocol proves identity. This week is about what happens when a program's
*implementation* lets an attacker do something the policy never granted. No
login is bypassed and no key is stolen; instead the attacker feeds the program
input it was not written to survive, and the CPU does the rest.

These are the challenges every capture-the-flag (CTF) beginner meets first,
rebuilt here as small, readable, self-contained labs:

| Folder | Category | The one-sentence idea |
| --- | --- | --- |
| [`reverse-engineering/`](reverse-engineering/) | **rev** | The check that guards the flag is *in the binary* — read the binary and the check reveals the answer. |
| [`stack-visualizer/`](stack-visualizer/) | **pwn** | Print the stack before and after a too-long `strcpy` and *watch* your input overwrite the saved return address, byte by byte. |
| [`buffer-overflow/`](buffer-overflow/) | **pwn** | The same overwrite with real CTF tooling (64-bit, `pwntools`, cyclic patterns): redirect execution to a `win()` function. |

Suggested order: **reverse-engineering → stack-visualizer → buffer-overflow.**
Reverse engineering teaches you to *read* a compiled program; stack-visualizer
shows you an overflow happening slot by slot in a tiny 32-bit program; and
buffer-overflow redoes that overflow the way a real CTF would. If the tooling in
the last lab ever feels abstract, the middle lab is the picture behind it.

---

## The mental model for both

A compiled C program is just bytes the CPU interprets. Two facts drive this
entire week:

1. **The source is still in there.** Compilation translates C to machine code,
   it does not hide it. Constants, string comparisons and the shape of the
   control flow all survive into the binary, and tools like `strings`,
   `objdump`, `gdb` and `radare2` read them straight back out. "The password is
   checked on the client" is never safe — the client *is* the attacker's
   laboratory. That is challenge 1.

2. **Code and data share the same memory, and C does not check bounds.** A
   local array and the address the function will return to sit on the same
   stack. `char buf[64]` reserves 64 bytes but nothing stops a `read()` of 200
   bytes from writing straight past the end, over the saved return address.
   Whoever controls that address controls the program counter. That is
   challenge 2.

Neither is a kernel bug or a memory-corruption exploit against your machine.
Challenge 1 is *information that was never actually hidden*; challenge 2 is *a
program trusting the length of its own input*. Both are the program working
exactly as written — the bug is in what it was written to do.

---

## Prerequisites

- **Docker.** That is the only hard requirement — everything (compiler, `gdb`,
  `objdump`, `python3`, `pwntools`) is installed *inside* the image, so your
  host stays clean and the lab is identical on Windows, macOS and Linux.

  ```bash
  docker --version        # any recent version is fine
  ```

- A terminal and some patience. No prior assembly knowledge is assumed; each
  README teaches what it needs where it needs it.

> **Apple Silicon / ARM note.** The walkthroughs quote exact addresses and
> offsets (x86-64 in two labs, 32-bit x86 in `stack-visualizer`). Every
> Dockerfile pins `--platform=linux/amd64` so the binaries match the
> walkthrough everywhere; on an ARM host Docker runs them under emulation,
> which is slower but correct.

---

## Running a challenge

Each folder is independent. The pattern is always the same:

```bash
cd week-10/reverse-engineering     # or stack-visualizer, or buffer-overflow
docker build -t cs440-rev .        # build the image (first time only)
docker run -it --rm cs440-rev      # drop into the box
```

`--rm` deletes the container on exit, so you can experiment freely and reset by
re-running. The flag lives inside the container; capturing it is the goal. Full
step-by-step walkthroughs — including the intended solution if you get stuck —
are in each folder's `README.md`.

---

## How to work through them

Give each challenge a genuine attempt *before* reading its "Intended solution"
section. The READMEs are written so that the top half is the briefing and the
tools, and the solution is clearly fenced off at the bottom. The learning is in
the struggle to connect "I can see the check" to "therefore the input is…"; the
solution is there to confirm it, not to replace it.
