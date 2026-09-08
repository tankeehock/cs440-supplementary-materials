# Week 7 — Access Control Lists on your own machine

Access control theory is short: every request is a triple *(subject, object,
action)*, and the reference monitor consults a policy to allow or deny it. The
interesting part is that your laptop already implements this, and you can read
the policy out of it with a terminal.

This is a **guided tutorial you run in a terminal**, not a script to execute.
Work through it on the OS you actually use, one command at a time, reading the
output each time — the output is the lesson. Both operating systems are covered end to end, and section 4
puts the two models side by side.

Two models appear here:

- **POSIX permission bits** — the classic `rwx` for *owner / group / other*.
  Nine bits, three subjects. Cheap and coarse.
- **ACLs** — an ordered list of entries, each naming a *specific* principal
  (user, group or SID) and the rights they are allowed or denied. Arbitrarily
  many subjects, far finer-grained actions.

Windows has **only** ACLs. macOS has both: the bits are the fallback, ACLs sit
in front of them.

> **Scope:** everything below runs on files you create, in your own home
> directory. Nothing needs administrator rights except the clearly marked
> optional steps. Do not run these against system directories — read there,
> don't write.

---

## 1. Shared setup

Create a playground so nothing in the lab touches your real files.

**Windows (PowerShell)**

```powershell
cd $HOME
mkdir acl-lab
cd acl-lab
"secret material" | Out-File -Encoding utf8 report.txt
mkdir shared
"team notes" | Out-File -Encoding utf8 shared\notes.txt
```

**macOS (Terminal)**

```bash
cd ~
mkdir acl-lab
cd acl-lab
echo "secret material" > report.txt
mkdir shared
echo "team notes" > shared/notes.txt
```

At the end, section 7 removes it.

---

## 2. Windows

Windows stores a **security descriptor** on every object: an owner, a primary
group, a **DACL** (who may do what) and a **SACL** (what gets audited). The
DACL is the ACL you will be reading.

Two tools reach it: `icacls.exe` (compact, scriptable, works in `cmd.exe` and
PowerShell) and PowerShell's `Get-Acl` / `Set-Acl` (verbose, object-oriented).
Use both — they show the same data at different resolutions.

### 2.1 Who am I?

A subject is not just a username. It is a token carrying a user SID, every
group SID, and a set of privileges.

```powershell
whoami                       # DOMAIN\username
whoami /user                 # your SID
whoami /groups               # every group in your token — this is what the ACL is matched against
whoami /priv                 # privileges (SeTakeOwnershipPrivilege, SeBackupPrivilege, ...)
whoami /all                  # everything at once
```

Local accounts and groups:

```powershell
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember -Group Administrators
net localgroup Administrators          # older equivalent, works in cmd.exe
```

> Note in `whoami /groups` that most privileges show **"Group used for deny
> only"** or that `Administrators` is present but disabled. That is UAC: your
> admin token is split, and the powerful half is only attached to elevated
> processes.

### 2.2 Read an ACL

```powershell
icacls report.txt
icacls shared
icacls shared /t                       # recurse into the whole tree
icacls C:\Windows\System32\drivers\etc\hosts     # a real system file — read only, do not modify
```

Sample output, annotated — this is a real listing of a file just created in a
user directory, so **every** entry is inherited:

```
report.txt NT AUTHORITY\SYSTEM:(I)(F)
           BUILTIN\Administrators:(I)(F)
           DESKTOP\alice:(I)(F)
```

**Rights** (the letters in parentheses):

| Code | Meaning |
| --- | --- |
| `F` | Full control |
| `M` | Modify (read + write + delete) |
| `RX` | Read and execute |
| `R` | Read only |
| `W` | Write only |
| `D` | Delete |
| `(DE,Rc,WDAC,...)` | Explicit fine-grained rights, when no shorthand fits |

**Inheritance flags:**

| Flag | Meaning |
| --- | --- |
| `OI` | Object inherit — files inside inherit this entry |
| `CI` | Container inherit — subfolders inherit this entry |
| `IO` | Inherit only — the entry does not apply to this object itself |
| `NP` | No propagate — inherits one level down, then stops |
| `I` | **Inherited** from the parent, not set on this object directly |

That `(I)` is the single most useful thing on the line. Entries marked `(I)`
were not set here; they came from the parent folder and cannot be edited in
place — you edit the parent, or you break inheritance first (section 2.5).

### 2.3 Read the same ACL in PowerShell

```powershell
Get-Acl report.txt | Format-List
```

```powershell
# One row per ACE — the actual list structure
(Get-Acl report.txt).Access | Format-Table IdentityReference, FileSystemRights, AccessControlType, IsInherited, InheritanceFlags -AutoSize
```

```powershell
# Owner and group only
(Get-Acl report.txt).Owner
(Get-Acl report.txt).Group

# The whole descriptor as SDDL — the string form Windows stores internally
(Get-Acl report.txt).Sddl
```

The SDDL string is worth decoding once by hand. `D:` starts the DACL, then each
`(A;;FA;;;SID)` is one ACE: `A` = allow (`D` = deny), `FA` = file all access,
and the trailing SID is the principal.

### 2.4 Change an ACL

Grant a second local account read access. Substitute a real account name from
`Get-LocalUser`, or use the well-known `Users` group.

```powershell
icacls report.txt /grant "Users:(R)"           # allow read
icacls report.txt                              # confirm the new ACE appears
```

Deny beats allow — this is the rule that surprises people:

```powershell
icacls report.txt /deny "Users:(W)"
icacls report.txt
```

```
report.txt BUILTIN\Users:(DENY)(W)      <- deny, listed FIRST
           BUILTIN\Users:(R)
           NT AUTHORITY\SYSTEM:(I)(F)
           ...
```

Two things to see in that output. Deny entries print as `(DENY)`, and Windows
has sorted the deny **above** the allow without being asked — that is the DACL
canonicalisation described in section 4, visible on your own screen. A user in
two groups, one allowed and one denied, is denied.

Remove entries:

```powershell
icacls report.txt /remove:g "Users"            # remove the grant
icacls report.txt /remove:d "Users"            # remove the deny
icacls report.txt /remove "Users"              # remove both
```

Set inheritable rights on a folder so new files pick them up:

```powershell
icacls shared /grant "Users:(OI)(CI)(M)"
"new file" | Out-File -Encoding utf8 shared\fresh.txt
icacls shared\fresh.txt                        # the entry is there, marked (I)
```

Windows re-propagates: remove the entry from the parent and it disappears from
the child too, because `(I)` entries are recomputed rather than owned by the
child. Watch it happen:

```powershell
icacls shared /remove:g "Users"
icacls shared\fresh.txt                        # the inherited entry is gone
```

That is only true while the child still accepts inheritance. Break it — with
`/inheritance:d` below, or the "disable inheritance" button in Explorer — and
the entries a folder had at that moment are copied into it as explicit ACEs.
It stops receiving corrections from above, but keeps propagating what it froze
to everything below. Watch a permission outlive the grant that created it:

```powershell
mkdir drift, drift\sub
icacls drift /grant "Users:(OI)(CI)(M)"      # a grant on the parent
icacls drift\sub                             # sub inherits it: (I)(OI)(CI)(M)

icacls drift\sub /inheritance:d              # someone protects the subfolder
icacls drift\sub                             # same entry, now explicit — no (I)

icacls drift /remove:g "Users"               # years later, the grant is revoked
icacls drift                                 # gone from the parent
icacls drift\sub                             # STILL THERE on the subfolder

"x" | Out-File drift\sub\later.txt           # and files created afterwards
icacls drift\sub\later.txt                   # inherit the stale grant: (I)(M)
```

That is where permission drift comes from on Windows. Note the last two lines
especially: the protected folder does not merely keep the old grant, it keeps
handing it out to new files indefinitely. Tightening the parent fixes neither.

### 2.5 Inheritance and ownership

```powershell
icacls shared /inheritance:e     # enable inheritance from parent
icacls shared /inheritance:d     # disable, but COPY the inherited entries down first
icacls shared /inheritance:r     # disable and REMOVE all inherited entries
```

`/inheritance:d` is the safe one. **`/inheritance:r` will lock you out of your
own folder**, and it is worth doing once, deliberately, to see it happen:

```powershell
icacls shared /inheritance:r
icacls shared                    # the folder is listed with NO entries at all
Get-ChildItem shared             # Access to the path ... is denied
Remove-Item -Recurse shared      # also denied — you cannot even delete it
```

An empty DACL is not "no restrictions", it is **deny everyone** — the ACL was
the only thing granting you access, and you just removed all of it. This is the
difference from POSIX bits, where `chmod 000` still leaves the owner able to
`chmod` back.

You are not actually stuck, because you still **own** it, and an owner can
always rewrite the DACL no matter what the DACL says. Either of these recovers
it:

```powershell
icacls shared /reset                          # restore inheritance from the parent
icacls shared /grant "$($env:USERNAME):(OI)(CI)(F)"   # or grant yourself back in
```

That is why ownership is the more powerful thing to hold, and why the next
section is about it.

Ownership — the owner can always rewrite the DACL, which is why it matters:

```powershell
icacls report.txt /setowner "$env:USERNAME"
takeown /f report.txt                          # take ownership (needs the privilege)
takeown /f shared /r /d Y                      # recursively
```

Back up and restore ACLs — the ACL equivalent of a config snapshot:

```powershell
icacls shared /save acl-backup.txt /t          # save the tree's ACLs
icacls shared /grant "Users:(F)"               # make a mess
icacls . /restore acl-backup.txt               # put it back (run from the PARENT dir)
```

> **`/save` works as a normal user; `/restore` does not.** Restoring writes
> owner and inherited entries back, which needs privileges an ordinary account
> does not hold, so unelevated it reports
> `Not all privileges or groups referenced are assigned to the caller` and
> changes nothing — note it says *"Successfully processed 0 files"*, not that it
> failed. Run the restore from an **administrator** PowerShell. The save half is
> still worth doing unprivileged: it is a readable before-picture.

Reset a tree to pure inherited permissions:

```powershell
icacls shared /reset /t /c /q
```

Useful modifiers on any `icacls` command: `/t` recurse, `/c` continue on error,
`/q` quiet, `/l` operate on the symlink rather than its target.

### 2.6 Write an ACE from PowerShell

`icacls` is faster, but the PowerShell form shows the object model explicitly,
which is the part that matches the lecture.

```powershell
$acl  = Get-Acl report.txt
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "Users",          # principal
            "Read",           # rights
            "Allow")          # allow or deny
$acl.AddAccessRule($rule)
Set-Acl -Path report.txt -AclObject $acl

(Get-Acl report.txt).Access | Format-Table IdentityReference, FileSystemRights, AccessControlType
```

Break inheritance the same way `icacls /inheritance:d` does:

```powershell
$acl = Get-Acl shared
$acl.SetAccessRuleProtection($true, $true)   # ($isProtected, $preserveInherited)
Set-Acl -Path shared -AclObject $acl
```

### 2.7 Beyond files

ACLs in Windows are not a filesystem feature — they are on every securable
object.

```powershell
Get-Acl HKLM:\SOFTWARE | Format-List          # registry key
Get-Acl HKCU:\Software\Microsoft | Format-List
```

```powershell
sc.exe sdshow Spooler                          # a service's SDDL
netsh http show urlacl                         # who may bind which HTTP URLs
Get-SmbShareAccess -Name "C$"                  # share-level ACL
```

Old-school file attributes, which are *not* ACLs but are often confused with
them:

```powershell
attrib report.txt                              # R/H/S/A flags
Get-ChildItem -Force                           # show hidden entries
```

### 2.8 Optional: effective access

Windows has no built-in CLI that answers "what can user X actually do to this
file, after all groups and deny entries are resolved". Sysinternals
[AccessChk](https://learn.microsoft.com/sysinternals/downloads/accesschk) does:

```powershell
accesschk.exe -q username C:\Users\you\acl-lab\report.txt
accesschk.exe -d -q username C:\Users\you\acl-lab
```

---

## 3. macOS

macOS layers two mechanisms. The POSIX bits are checked, and an ACL — stored in
the extended attribute `com.apple.system.Security` — can grant *or deny* on top
of them. macOS ACLs are the same NFSv4/Windows-style model, not the Linux
`getfacl`/`setfacl` POSIX-draft model, so those two commands do not exist here.

### 3.1 Who am I?

```bash
whoami                    # short name
id                        # uid, gid, and every group membership
id -P                     # passwd-style line
groups                    # group names only
dscl . -list /Users       # every local user, including hidden service accounts
dscl . -list /Groups
dscl . -read /Users/$(whoami) UniqueID PrimaryGroupID NFSHomeDirectory
dseditgroup -o checkmember -m $(whoami) admin    # am I an admin?
```

### 3.2 Read permissions and ACLs

The plain listing shows only the nine POSIX bits:

```bash
ls -l report.txt
```

Add `-e` to print ACL entries, and `-d` to describe the directory itself rather
than its contents:

```bash
ls -le report.txt
ls -lde shared
ls -le@ report.txt        # also list extended attributes
ls -lO report.txt         # file flags (hidden, uchg, ...)
```

Somewhere with real ACLs on a stock system — read only:

```bash
ls -lde ~/Library
ls -lde /Users/Shared
ls -le /var/db/sudo 2>/dev/null
```

Output looks like:

```
-rw-r--r--+ 1 alice  staff  16 Sep  9 10:04 report.txt
 0: user:bob allow read,write
 1: group:everyone deny delete
```

The **`+`** after the mode string means "an ACL is present" — without `-e` that
plus sign is your only clue. Each numbered line is one ACE, **evaluated in
order**, top down, first match wins. Order is the policy, so the index numbers
matter.

### 3.3 The permission vocabulary

macOS ACEs are far finer-grained than `rwx`:

| Applies to | Permissions |
| --- | --- |
| Files | `read`, `write`, `append`, `execute` |
| Directories | `list`, `search`, `add_file`, `add_subdirectory`, `delete_child` |
| Both | `delete`, `readattr`, `writeattr`, `readextattr`, `writeextattr`, `readsecurity`, `writesecurity`, `chown` |

And four inheritance flags, directories only:

| Flag | Meaning |
| --- | --- |
| `file_inherit` | New files inside inherit this ACE |
| `directory_inherit` | New subdirectories inherit it |
| `limit_inherit` | Propagate one level, then stop |
| `only_inherit` | The ACE is a template — it does not apply to this directory itself |

### 3.4 Change an ACL

Add an entry (`+a` appends at the canonical position):

```bash
chmod +a "$(whoami) allow read,write" report.txt
ls -le report.txt
```

Deny something — and prove that a deny ACE overrides the POSIX bits:

```bash
chmod +a "$(whoami) deny write" report.txt
ls -le report.txt
echo "try to append" >> report.txt      # Permission denied, even though ls shows rw-
```

Remove it and the write works again:

```bash
chmod -a "$(whoami) deny write" report.txt
echo "now it works" >> report.txt
```

Position matters, so there are index-based forms:

```bash
chmod +a# 0 "$(whoami) allow read" report.txt    # insert at index 0
chmod =a# 1 "$(whoami) allow read,write" report.txt  # replace entry 1
chmod -a# 1 report.txt                            # delete entry 1
```

Strip every ACL from a file, or a whole tree:

```bash
chmod -N report.txt
chmod -R -N shared
```

Inheritance on a directory:

```bash
chmod +a "$(whoami) allow read,write,file_inherit,directory_inherit" shared
touch shared/fresh.txt
ls -le shared/fresh.txt        # inherited ACE, marked "inherited"
```

macOS inheritance is a **template applied once, at creation** — not a live link
to the parent. Remove the ACE from the directory and the copy already stamped on
the file stays exactly where it is:

```bash
chmod -a "$(whoami) allow read,write,file_inherit,directory_inherit" shared
ls -lde shared                 # the entry is gone from the directory
ls -le  shared/fresh.txt       # ... and still present on the file
```

This is the opposite of the Windows behaviour in section 2.4, and it is why
permission drift is the normal state of a long-lived macOS share: fixing the
parent fixes nothing that already exists. It is also why the next command has to
exist at all.

Push a directory's inheritable ACEs onto everything already inside:

```bash
chmod -R +ai "$(whoami) allow read" shared     # +ai = add as inherited
```

### 3.5 POSIX bits, owners and groups

```bash
chmod 640 report.txt          # rw- r-- ---
chmod u+x,go-rwx report.txt   # symbolic form
stat -f "%Sp %Su:%Sg %N" report.txt
```

```bash
chown $(whoami) report.txt
chgrp staff report.txt
sudo chown -R $(whoami):staff shared
umask                          # the mask applied to newly created files
```

Special bits, worth seeing once:

```bash
ls -ld /tmp                    # drwxrwxrwt — the 't' is the sticky bit
ls -l /usr/bin/passwd          # -r-sr-xr-x — the 's' is setuid
find /usr/bin -perm -4000 -type f 2>/dev/null | head    # every setuid binary
```

### 3.6 Flags and extended attributes

Not ACLs, but part of the same "why can't I delete this" question:

```bash
ls -lO report.txt
chflags uchg report.txt        # user-immutable: even root-owned edits fail
rm report.txt                  # refused
chflags nouchg report.txt      # release it
```

```bash
xattr -l report.txt            # list extended attributes
xattr -p com.apple.quarantine <a-downloaded-file>
xattr -d com.apple.quarantine <a-downloaded-file>    # the "downloaded from the internet" mark
```

### 3.7 Groups — the case POSIX bits cannot express

Create a group, add yourself, and grant it access. This is the situation the
nine permission bits have no way to describe: a second named group, with its own
rights, alongside the owning one.

```bash
sudo dseditgroup -o create cs440
sudo dseditgroup -o edit -a $(whoami) -t user cs440
dseditgroup -o read cs440

chmod +a "group:cs440 allow read,write,file_inherit,directory_inherit" shared
ls -lde shared
```

Clean up when done:

```bash
sudo dseditgroup -o delete cs440
```

### 3.8 Beyond the filesystem

```bash
sudo -l                                    # what may I run via sudo?
cat /etc/sudoers.d/* 2>/dev/null           # policy files (read with `sudo visudo` to edit)
csrutil status                             # System Integrity Protection — a MAC layer above ACLs
ls -le /System/Library | head              # SIP-protected; ACLs alone don't explain the denials
```

The last one is the point: on modern macOS a *mandatory* layer (SIP, and TCC
for privacy-sensitive folders) sits above the *discretionary* ACL layer. An
allow ACE is necessary but not sufficient.

---

## 4. Side by side

| Concept | Windows | macOS |
| --- | --- | --- |
| Show ACL | `icacls FILE` / `Get-Acl FILE` | `ls -le FILE` |
| Show directory's own ACL | `icacls DIR` | `ls -lde DIR` |
| Add allow entry | `icacls F /grant "user:(R)"` | `chmod +a "user allow read" F` |
| Add deny entry | `icacls F /deny "user:(W)"` | `chmod +a "user deny write" F` |
| Remove entry | `icacls F /remove "user"` | `chmod -a "user allow read" F` |
| Remove all ACLs | `icacls F /reset` | `chmod -N F` |
| Inheritable entry | `(OI)(CI)` flags | `file_inherit,directory_inherit` |
| Re-apply to existing children | automatic | `chmod -R +ai` |
| Break inheritance | `icacls D /inheritance:d` | (no equivalent — remove the ACEs) |
| Change owner | `icacls F /setowner U`, `takeown` | `chown U F` |
| My identity | `whoami /all` | `id` |
| Group membership | `Get-LocalGroupMember` | `dseditgroup -o read GROUP` |
| Backup / restore | `icacls D /save`, `/restore` | no built-in equivalent |
| Recurse | `/t` | `-R` |

Structural differences worth stating out loud:

- **Ordering.** Windows canonicalises the DACL: explicit denies, then explicit
  allows, then inherited. macOS evaluates ACEs strictly in listed order, first
  match wins — so on macOS the index is part of the policy.
- **Fallback.** Windows has no permission bits; an object with an empty DACL
  denies everyone. macOS falls back to POSIX bits when no ACE matches.
- **Deny.** Both support explicit deny, and in both it takes precedence in
  practice. Deny entries are a blunt instrument — prefer *not granting* over
  *granting then denying*.
- **Inheritance.** Windows keeps inherited entries live: edit the parent and
  every unprotected child updates. macOS copies them once at creation and never
  looks back, so an existing tree has to be re-stamped by hand. Sections 2.4 and
  3.4 show both.

---

## 5. Why this matters — ACLs and privilege escalation

Most privilege escalation in a real engagement is not a memory-corruption
exploit. It is an **ACL that grants a low-privilege subject write access to an
object a high-privilege subject trusts**. No CVE, no shellcode — just the
policy, misconfigured, doing exactly what it was told.

So the commands in sections 2 and 3 are not only administration tools. They are
the *first* thing an attacker runs after landing on a host, and the first thing
a defender should run when hardening one. Same commands, opposite intent.

The pattern to look for is always the same triple:

> **An object that a privileged process executes, reads or trusts — that an
> unprivileged principal can modify.**

Anything matching that shape is an escalation path. Everything below is a
specific instance of it.

### 5.1 Windows

**Writable service binaries.** Services usually run as `LOCAL SYSTEM`. If the
executable on disk is writable by `Users`, whoever can write it chooses what
SYSTEM runs at next start.

```powershell
# Every service, its binary and the account it runs as
Get-CimInstance Win32_Service | Select-Object Name, StartName, PathName | Format-Table -Wrap

# Then check the ACL on each path — look for Users / Everyone / Authenticated Users with (M), (W) or (F)
icacls "C:\Program Files\SomeApp\service.exe"
```

The tell is a line like `BUILTIN\Users:(M)` on a binary whose service runs as
SYSTEM. Third-party installers that unpack into `C:\` rather than
`C:\Program Files` are the classic offender, because the root of `C:\` grants
`Authenticated Users` write by default and children inherit it.

**Weak ACLs on the service object itself.** The binary can be untouchable while
the *service configuration* is not. If your group holds change-config rights,
you never need to touch the file — you repoint the service.

```powershell
sc.exe sdshow Spooler          # read the service's SDDL
```

In that SDDL, an ACE granting `Users` or `Authenticated Users` write-ish rights
(`WD` = WRITE_DAC, `WO` = WRITE_OWNER, or the service-specific change-config
right) is the finding.

**Unquoted service paths.** A `PathName` of `C:\Program Files\My App\svc.exe`
with no quotes makes Windows try `C:\Program.exe`, then
`C:\Program Files\My.exe`, before the real target. Combine with a writable
parent directory and it is an escalation.

```powershell
Get-CimInstance Win32_Service |
  Where-Object { $_.PathName -notmatch '^"' -and $_.PathName -match ' ' } |
  Select-Object Name, PathName
```

That one-liner is the version you will find posted everywhere, and on a real
host it is almost all noise — it returned **229 hits** on the machine this lab
was written on, and not one was a finding. The reason is `svchost.exe -k
netsvcs -p`: the space is in the *arguments*, not in the path. The condition
that actually matters is a space in the executable path itself, before any
argument:

```powershell
Get-CimInstance Win32_Service | Where-Object {
    $p = $_.PathName
    $p -and $p -notmatch '^"' -and (($p -split '(?<=\.exe)')[0]) -match ' '
} | Select-Object Name, StartName, PathName
```

That returns **0** on a healthy host. Getting from 229 to 0 is the whole skill:
a finding is what survives after you have explained away everything that merely
matches the pattern. And even a real hit is only exploitable if you can write
to one of the directories the truncated path would resolve into — check with
`icacls` before reporting it.

**Writable directories on `PATH`, and DLL search order.** If any directory on
the system `PATH` is user-writable, a planted DLL or EXE gets loaded by whatever
privileged process searches there.

```powershell
$env:PATH -split ';' | ForEach-Object {
    $p = $_.Trim().TrimEnd('\')
    if ($p -and (Test-Path -LiteralPath $p)) { icacls $p }
}
```

Both bits of tidying earn their place. `Test-Path` skips `PATH` entries that no
longer exist — a real machine has several, and without the guard `icacls`
reports a failure for each and buries the output you came for. `TrimEnd('\')`
handles entries written with a trailing backslash: passing `C:\Program Files\`
to a native program lets that final `\` escape the closing quote, and `icacls`
receives a mangled path and complains about "the filename, directory name, or
volume label syntax". On the machine this was written on, those two lines are
the difference between a clean sweep of 18 directories and two spurious errors.

A `PATH` directory that does **not** exist is itself worth noting, by the way:
whoever can create it decides what gets loaded from it.

**Registry ACLs.** The service configuration also lives in the registry. A
writable `ImagePath` value is the same finding as a writable binary.

```powershell
Get-Acl HKLM:\SYSTEM\CurrentControlSet\Services\Spooler | Format-List
(Get-Acl HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run).Access |
  Format-Table IdentityReference, RegistryRights, AccessControlType
```

**Scheduled tasks.** A task running as SYSTEM whose script or binary is
writable by you is the same shape again.

```powershell
Get-ScheduledTask | Where-Object { $_.Principal.UserId -match 'SYSTEM' } |
  Select-Object TaskName, TaskPath
Get-ScheduledTask -TaskName "<name>" | Select-Object -ExpandProperty Actions
```

**Files that hold credentials.** Here the finding is a *read* ACL, not a write
one — over-permissive inheritance on a directory that happens to contain
secrets.

```powershell
icacls C:\Windows\Panther\Unattend.xml 2>$null      # install-time answer files
icacls C:\inetpub\wwwroot\web.config 2>$null        # connection strings
```

**Privileges, not just ACLs.** `whoami /priv` is the highest-value single
command on a Windows host, because several privileges are equivalent to
administrator by design — they let the holder step *around* the DACL rather
than satisfy it:

| Privilege | Why it is an escalation |
| --- | --- |
| `SeImpersonatePrivilege` | Impersonate a token you can coerce a privileged process into handing you — the "potato" family of techniques |
| `SeBackupPrivilege` | Read **any** file regardless of its DACL — including the SAM and SYSTEM hives |
| `SeRestorePrivilege` | Write any file regardless of its DACL |
| `SeTakeOwnershipPrivilege` | Take ownership of any object; the owner can always rewrite the DACL |
| `SeDebugPrivilege` | Open any process, including SYSTEM ones, and read or inject into its memory |
| `SeLoadDriverPrivilege` | Load kernel code |

This is the practical lesson of section 2.1: the ACL answers "does this subject
match an allow ACE", but a privilege can make the question moot. A complete
access-control model has both, and an audit that only reads DACLs misses half
the picture.

### 5.2 macOS

**setuid and setgid binaries.** A setuid-root binary runs as root no matter who
invokes it. The inventory is small on a stock system, so anything unexpected —
particularly something a third-party installer added — is worth a hard look.

```bash
find / -perm -4000 -type f 2>/dev/null          # setuid
find / -perm -2000 -type f 2>/dev/null          # setgid
ls -lO /usr/bin/passwd
```

The risk is not the mechanism, it is a setuid binary that can be *influenced*:
one that shells out, honours an environment variable, or takes a filename it
writes to. [GTFOBins](https://gtfobins.github.io/) catalogues which standard
binaries become a root shell when they are setuid or reachable via `sudo`.

**LaunchDaemons.** Anything in `/Library/LaunchDaemons` runs as root at boot.
Two things must be root-owned and not group- or world-writable: the plist, and
the program it points at.

```bash
ls -le /Library/LaunchDaemons/
ls -le /Library/LaunchAgents/

# The referenced programs — are any of them writable by you?
for f in /Library/LaunchDaemons/*.plist; do
  /usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$f" 2>/dev/null ||
  /usr/libexec/PlistBuddy -c "Print :Program" "$f" 2>/dev/null
done
```

Anything owned by your user, or writable by `staff` or `admin`, is an
escalation to root at the next boot.

**Group-writable directories on root's `PATH`.** Homebrew's `/usr/local/bin` is
the recurring example — on many machines it is owned by the console user. If
any script run by root ever resolves a command through such a directory, the
directory's ACL is the real access-control boundary.

```bash
echo $PATH | tr ':' '\n' | while read -r d; do ls -lde "$d" 2>/dev/null; done
```

**`sudo` policy.** Independent of the filesystem ACL, and often the shortest
path:

```bash
sudo -l                                  # NOPASSWD entries, and which binaries
```

A `NOPASSWD` entry on any binary that can spawn a shell or write an arbitrary
file is root. Again: GTFOBins.

**ACLs used offensively.** The write direction matters too. An attacker with a
foothold can use the same `chmod +a` you practised in section 3.4 to hide
artifacts or resist cleanup — a `deny read,list` ACE makes a file effectively
invisible to normal tooling, and `chflags schg` makes it stubborn to delete.
Section 3.2's lesson is the defence: the `+` in `ls -l` is the only clue that
an ACL exists at all, so a listing without `-e` can be actively misleading
during an investigation.

```bash
ls -l  suspicious-dir       # shows a '+' and nothing else
ls -le suspicious-dir       # shows the deny ACE that is hiding things
ls -lO suspicious-dir       # shows the immutable flag
```

**Layers above the ACL.** Note also that on macOS, root is no longer the top of
the model. SIP protects system paths from root itself, and TCC gates access to
the user's private data by *application*, not by uid — so an ACL allow is
necessary but not sufficient.

```bash
csrutil status
```

### 5.3 The same commands, as a defensive audit

Nothing in 5.1 or 5.2 is a separate attacker toolkit. It is section 2 and
section 3, run systematically and read with a specific question in mind:

| Question | Windows | macOS |
| --- | --- | --- |
| What runs with high privilege? | `Get-CimInstance Win32_Service`, `Get-ScheduledTask` | `ls /Library/LaunchDaemons`, `find / -perm -4000` |
| Who can modify what it executes? | `icacls <path>` | `ls -le <path>` |
| What can I do that I should not? | `whoami /priv`, `whoami /groups` | `sudo -l`, `id` |
| Is this a deliberate grant or drift? | look for `(I)` — inherited | compare against the parent's inheritable ACEs |
| What was the baseline? | `icacls <tree> /save` | no built-in; snapshot `ls -leR` |

The hardening rules that fall out of it are short:

1. **No non-administrative write on anything a privileged process executes** —
   binary, script, plist, configuration or the directory containing it.
2. **Grant to groups, never deny to groups.** Deny ACEs are a patch over a
   grant that should not have existed; they are also fragile, because a second
   allow path often exists.
3. **Watch inheritance drift**, and know which kind your OS produces. On macOS
   every existing file keeps the grants that were inheritable the day it was
   created, so tightening a parent fixes nothing already inside it. On Windows
   the propagation is automatic, and the drift hides in the folders someone
   protected with `/inheritance:d` — those stopped receiving corrections. Either
   way this is the most common source of over-permissive ACLs in the field, and
   neither is visible unless you go and look.
4. **Quote your service paths, and install under `C:\Program Files`** so that
   the restrictive default ACL is what gets inherited.
5. **Audit privileges alongside ACLs.** `SeBackupPrivilege` on a service
   account defeats every file ACL you wrote.

> **Ethics.** Everything above is enumeration — reading policy on a machine you
> own, which is exactly what a system administrator does. Running it against
> systems you do not own, or do not have written authorisation to test, is
> unlawful under the Computer Misuse Act (Singapore) and its equivalents
> elsewhere. In an engagement, the scope document is what makes this legal; in
> this course, your own laptop is the scope. The purpose here is to be able to
> *find these misconfigurations before someone else does*.

---

## 6. From ACLs to RBAC — the demo server

Everything so far attaches the policy to the **object**: this file lists these
principals with these rights. That is precise, and it does not scale. A
thousand files times a hundred people is a policy nobody can read, which is
exactly how the drift in section 5.3 accumulates.

Applications solve it by attaching the policy to the **subject** instead, with a
level of indirection:

```
subject ──assigned──▶ role ──grants──▶ permission ──guards──▶ action
```

Nobody is granted a permission directly; they are put in a role, and the role
carries the permissions. When someone changes jobs you change one role
assignment rather than revisiting every object they ever touched.

[`rbac-demo/`](rbac-demo/) is a small Flask server that implements this and
shows its working — every authorisation decision is printed as a trace naming
the subject, its roles, what those roles expand to, what the route required, and
the verdict.

```bash
uv run week-7/rbac-demo/app.py            # http://127.0.0.1:8000
uv run week-7/rbac-demo/app.py --policy   # print the policy matrix and exit
```

Log in as `carol` (viewer), `bob` (editor), `dave` (auditor), `alice` (admin) or
`mallory`, who has no roles at all — authenticated, and authorised for nothing.
Then watch a denial from the command line:

```bash
curl -u carol:carol123 -X POST -H 'Content-Type: application/json' \
     -d '{"title":"nope"}' http://127.0.0.1:8000/api/reports
```

```
  [DENY ] POST   /api/reports    subject=carol      needs=report:write
          roles     : viewer
          expands to: report:read
          reason    : no role held by this subject grants report:write
```

Four things in it are worth carrying back to the ACL half of this lab:

- **Deny by default.** No role, no session, or a permission that does not exist
  — every path ends at denied. Windows behaves the same way with an empty DACL;
  macOS does not, because it falls back to the permission bits.
- **401 is not 403.** "I do not know who you are" and "I know, and no" are
  different answers, and returning the wrong one tells an attacker whether valid
  credentials would have helped.
- **The audit log is an object too.** `/audit` needs `audit:read`. Systems that
  forget this let an intruder read — or quietly edit — the record of what they
  did.
- **Broken authorisation does not look broken.** `rbac-demo` is a deliberately
  vulnerable target with **seven planted bugs**. Three break the check directly,
  each sitting next to its correct twin: one with **no check at all** (logged in
  is not authorised), one whose **check trusts a role the caller supplies** in a
  header, and one where the check is **correct but too coarse** —
  `@requires("report:write")` proves you may edit reports, not that you may edit
  *this* report, which is IDOR. Section 5's first move finds all three: log in as
  the lowest-privileged account, replay the high-privilege requests, tamper with
  any identity field, and walk the id in the URL.
- **A clean audit log is not evidence.** Two of those three never reach the
  reference monitor at all, so `/audit` has no record of the bypass. The third
  is logged as an ALLOW, because the check that ran did succeed — it was simply
  answering a coarser question than the situation needed.
- **You can bypass every check without touching one.** The other four bugs are
  three XSS and an open redirect. An injected script runs in the *victim's*
  browser, so the victim's session and roles are used and every guard passes
  honestly — an `editor` who gets a script in front of an `admin` has, in
  effect, `user:manage`. The sharpest one needs no permission at all: `check()`
  logs the request path on every decision including **denials**, and `/audit`
  renders it, so a user authorised for nothing puts code in the auditor's
  browser simply by being refused. Re-run with `--safe` and fire the same
  payloads to see the difference one function makes.

See [`rbac-demo/README.md`](rbac-demo/README.md) for the full walkthrough,
including where RBAC stops: it can say "editors may edit reports", but not "bob
may edit *this* report". That last question is about the object, and it needs an
ACL — which is where this lab started.

---

## 7. Cleanup

**Windows (PowerShell)**

```powershell
cd $HOME
icacls acl-lab /reset /t /c /q     # undo any inheritance you broke
Remove-Item -Recurse -Force acl-lab
```

The `/reset` line matters if you tried `/inheritance:r` in section 2.5: a folder
with an emptied DACL refuses to be deleted, even by you, and `Remove-Item` fails
with "Access to the path ... is denied". Resetting the tree's ACLs first puts
the inherited entries back so the delete can proceed.

**macOS**

```bash
cd ~
chmod -R -N acl-lab        # drop ACLs first
chflags -R nouchg acl-lab  # release any immutable flags
rm -rf acl-lab
```

---

## 8. Appendix — Linux / WSL

If you are working in WSL or on a Linux VM, the ACL model is the older POSIX
draft one, with different tools — which are **not installed by default** on
Ubuntu (including WSL's default image), so start with:

```bash
sudo apt install acl        # provides getfacl and setfacl
```

```bash
getfacl FILE                                  # read
setfacl -m u:username:rw FILE                 # modify
setfacl -m d:u:username:rwx DIR               # default (inheritable) entry
setfacl -x u:username FILE                    # remove one entry
setfacl -b FILE                               # remove all
getfacl DIR | setfacl --set-file=- OTHERDIR   # copy an ACL
```

The `+` in `ls -l` means the same thing as on macOS. Note that on WSL, files
under `/mnt/c` are Windows files seen through a translation layer — what
`getfacl` reports there is a synthesised view, not the real Windows DACL. Read
those with `icacls.exe` from PowerShell instead.

---

## 9. Reference

- `icacls /?` — the full flag list, including every fine-grained right
- `Get-Help Get-Acl -Full`, `Get-Help Set-Acl -Full`
- `man chmod` — the ACL section is the second half; `man ls`; `man chflags`
- [Windows access control](https://learn.microsoft.com/windows/win32/secauthz/access-control)
- [SDDL string format](https://learn.microsoft.com/windows/win32/secauthz/security-descriptor-string-format)
