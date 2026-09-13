# Certificate Transparency OSINT — what the padlock tells everyone else

CS440 AY26T1 · Kee Hock · uv + Python, nothing else

In the PKI lab you asked *"who can issue a certificate my browser will accept?"*
and the answer was: any of ~150 root CAs, plus every intermediate they have
delegated to. Certificate Transparency is the industry's answer to that
problem. Since 2018 Chrome has refused any certificate that is not published in
a public, append-only, cryptographically-verifiable log at issue time.

That fixes mis-issuance detection. It also means **every certificate anyone ever
issued for your domain is a matter of public record**, including the ones for
hosts you assumed nobody knew about. No packet you send ever touches the target.
This is the first thing a competent attacker does, and it is free.

This lab runs in two halves:

- **Part A — a guided walkthrough of `smu.edu.sg`.** Eight steps, worked through
  together, with the answers given. Follow along at your own terminal.
- **Part B — the same eight steps against `tech.gov.sg`, on your own.** Hints
  only. The commands are identical; the findings are not.

## The tool

Everything runs through `ct_osint.py`. The only requirement is
[uv](https://docs.astral.sh/uv/) — the script is standard library only, so
there is no `jq`, no `curl`, and nothing to install. You do not even need
Python: `uv run` fetches an interpreter for you.

```bash
cd week-5/osint-challenge-with-cert
uv run ct_osint.py --help
```

The command is identical on Windows, macOS and Linux.

One subcommand per step. The last column is the **code map**: each step is one
function in `ct_osint.py`, tagged with a searchable landmark. Open the file and
search the tag, or run e.g. `grep -n "STEP 4" ct_osint.py` to jump straight to
the code behind that step. (The file's top comment block is a map that mirrors
this table.)

| Command | Step | Find it in `ct_osint.py` |
|---|---|---|
| `fetch <domain>` | download the log — the only command that touches the network | `COMMAND: fetch` → `cmd_fetch()` |
| `names <domain>` | every hostname belonging to the target | `STEP 0` → `cmd_names()` |
| `surface <domain>` | 1 — measure the attack surface | `STEP 1` → `cmd_surface()` |
| `naming <domain>` | 2 — read the naming convention | `STEP 2` → `cmd_naming()` |
| `nonprod <domain>` | 3 — non-production and admin hosts | `STEP 3` → `cmd_nonprod()` |
| `shared <domain>` | 4 — who else is on these certificates | `STEP 4` → `cmd_shared()` |
| `timeline <domain>` | 5 — watch a certificate grow over time | `STEP 5` → `cmd_timeline()` |
| `revoked <domain>` | 6 — read the revocations | `STEP 6` → `cmd_revoked()` |
| `wildcards <domain>` | 7 — wildcards vs exact names | `STEP 7` → `cmd_wildcards()` |
| `all <domain>` | steps 1–7 in sequence | `COMMAND: all` → `cmd_all()` |

The name-parsing every step shares — `own_names()`, `registrable()`,
`family_of()` — lives under `SECTION 2` (data helpers). Every command prints an
explanation of what you are looking at; add `--brief` to suppress it once you
know.

### Under the hood — the raw recipe

The tool is a convenience wrapper. There is no magic in it: it calls one public
API and filters the JSON. Before you rely on the tool, do it once by hand so you
know what it is standing on. This is the classic one-liner (needs `curl` and
`jq`):

```bash
TARGET="smu.edu.sg"
curl -s "https://api.certspotter.com/v1/issuances?domain=$TARGET&include_subdomains=true&expand=dns_names" > "$TARGET.ct.logs"
jq -r --arg t "$TARGET" '.[].dns_names[] | select(. == $t or endswith("." + $t))' "$TARGET.ct.logs" | sort -u
```

That `curl` is exactly what `uv run ct_osint.py fetch smu.edu.sg` runs, and the
`jq` line is exactly what `names` does — the `.ct.logs` files in this folder were
produced by that `curl`, so `jq` reads them directly.

Two things to notice in the raw form, because the tool hides them:

- **Filter in `jq`, not in `grep`.** A tempting `grep "$TARGET"` treats the dots
  as "any character" and matches anywhere in the line, so `smu.edu.sg` would also
  match `smuXedu.sg` and `notsmu.edu.sg.evil.com`. The `jq` `select(. == $t or
  endswith("." + $t))` matches the apex or a real sub-domain and nothing else —
  which matters the moment someone registers a look-alike.
- **The `curl` above fetches one page only.** See the pagination trap below.

### Working offline

`smu.edu.sg.ct.logs` and `tech.gov.sg.ct.logs` are captured API responses, so
the whole lab works with no internet and sends nothing to anybody. `fetch` is
there so you can point the tool at a domain of your own later.

> **The pagination trap.** Cert Spotter returns **100 issuances per request**.
> Both captures here hit that ceiling exactly, so neither is complete — you are
> looking at a sample, not an inventory. `fetch` pages properly (it hands the
> last `id` back as `after=` until the API returns an empty array); the captures
> predate that and stop at one page. Any conclusion of the form *"target X has
> no host named Y"* is unsound until you have paged to the end. This is the most
> common error in subdomain enumeration and it applies to every "none found" in
> this lab.

---

## Certificate Transparency, end to end

You cannot read CT as an attacker until you understand what it is and why it
exists, because every recon opportunity in this lab is a *side-effect* of a
mechanism built for the opposite purpose.

### The problem it solves

The PKI lab left you with an uncomfortable fact: your browser trusts ~150 root
CAs, and **any** of them (or any intermediate they delegate to) can issue a
certificate for `smu.edu.sg`, or your bank, or anyone. Nothing in the X.509
chain stops a CA from issuing a certificate it should never have issued —
whether by mistake, by compromise, or by government coercion. Before 2013, a
mis-issued certificate for your domain could be used against your users and
**you would have no way to know it existed.** There was no public record of what
had been issued.

Certificate Transparency (RFC 6962, proposed by Google) fixes exactly that. The
idea is simple: make every certificate issuance *public and permanent*, so that
mis-issuance is detectable. If a CA issues a rogue certificate for your bank, it
now appears in a public log the bank can watch — and the CA cannot un-issue it
or hide it.

### The mechanism: append-only, cryptographically verifiable

A CT log is not just a database — it is an **append-only Merkle hash tree**.
That structure is what makes the log trustworthy without trusting the log
operator:

- Every entry is a leaf in the tree; the operator periodically signs the root
  hash, called a **Signed Tree Head (STH)**.
- **Inclusion proofs** let anyone prove a given certificate is in the log.
- **Consistency proofs** let anyone prove the new tree is a pure *extension* of
  the old one — nothing was deleted or rewritten.

So a log physically *cannot* retroactively remove or alter a certificate without
producing a cryptographic contradiction that auditors would catch. This is the
same append-only, tamper-evident idea as a blockchain, predating the fashion for
the word. **Permanence is the whole point** — and, for you, the reason a
hostname logged once is discoverable forever, even after the host is gone.

### The receipt: SCTs, and how browsers enforce it

When a CA submits a certificate, the log returns a **Signed Certificate
Timestamp (SCT)** — a signed promise to include it within a fixed window (the
Maximum Merge Delay, usually 24h). The certificate then carries SCTs from
several independent logs (embedded in the cert, or delivered via a TLS
extension or OCSP stapling).

This is the enforcement lever. **Since April 2018 Chrome refuses any certificate
that does not present valid SCTs** (Apple's platforms followed months later). A
CA that skips CT logging produces certificates that modern browsers reject —
which is why logging is not optional in practice. That mandate is precisely what
guarantees your recon is *complete-ish*: a serious site cannot have a
browser-trusted certificate that never appeared in a log.

> **Precertificates — you can see hosts before they go live.** To embed SCTs in
> the final certificate, the CA first logs a *precertificate*. So a hostname can
> appear in CT **before the service behind it is ever deployed** — a staging
> host, a product not yet announced, a customer not yet live. For an attacker,
> that is a preview of the roadmap; for a defender monitoring their own domains,
> it is early warning.

### The ecosystem — and where you sit in it

Four roles keep CT honest:

- **CAs** submit certificates as they issue them.
- **Logs** store them append-only and hand back SCTs (operated by Google,
  Cloudflare, DigiCert, Let's Encrypt/Sectigo, and others — deliberately many,
  so no one operator is trusted).
- **Monitors** watch the logs for certificates that matter to them.
- **Auditors** verify the logs are behaving (STHs consistent, promises kept).

**In this lab you are a monitor.** Cert Spotter (the API `ct_osint.py` queries)
is a monitor-as-a-service that has already ingested the logs and lets you search
them by domain. Other front ends onto the same global data set:
[crt.sh](https://crt.sh) (web UI + SQL), Censys, and Facebook's CT monitor. They
differ in interface and freshness, not in the underlying record.

The real-world payoff of the defensive design is real: CT is how Google caught
Symantec mis-issuing certificates (including for Google's own domains) in
2015–2017, which ended in browsers distrusting Symantec's CA business entirely.
The system works — mis-issuance really is caught now.

### The double edge — the crux of this lab

Here is the tension to hold in your head for the rest of the exercise:

> **Certificate Transparency is a defensive mechanism whose defining property —
> total, permanent, public disclosure of every certificate — is also the single
> best reconnaissance source an attacker has.**

The property that lets a bank catch a rogue certificate is the same property
that lets an attacker enumerate the bank's entire named surface for free. CT did
not create this exposure; it *revealed* it. The names were always there, quietly
protected by the belief that nobody was looking. CT is a public, authenticated,
permanent record that everybody is looking, all the time. The rest of this lab
is you learning to look.

---

## The adversarial mindset

Before the mechanics, the mindset. The eight steps are just `jq` filters; what
turns them into reconnaissance is the questions you ask while reading the
output. This section is the part that transfers to every other target and every
other OSINT source — the tool is disposable, the way of thinking is not.

### Where this sits: the first move, and a free one

Every attack model puts reconnaissance first — it is phase 1 of the Cyber Kill
Chain and the whole left-hand `Reconnaissance` column of MITRE ATT&CK. Recon
splits into two kinds, and the distinction is the entire point of this lab:

- **Active recon** touches the target: port scans, DNS brute-forcing, hitting
  web apps, vulnerability scanners. It is effective and it is *loud* — it lands
  in the target's logs, trips their IDS, and can be attributed to your IP.
- **Passive recon** never touches the target. You read what third parties
  already publish about it. It is silent, leaves nothing in the target's logs,
  and in most jurisdictions is not even unlawful.

Certificate Transparency is the richest passive source in existence, and it is a
gift the defender cannot refuse: CT is *mandatory*. A site that wants a
certificate browsers will trust **must** publish it, so opting out of the
disclosure means opting out of HTTPS. The attacker gets a continuously-updated,
authenticated inventory of the target's hostnames, and the target cannot see a
single query being made. Before you send one packet, you already have the map.

### The core asymmetry

The defender has to secure *every* host, patch *every* service, and get it right
*every* time. The attacker needs **one** way in, **once**. CT recon is how the
attacker turns that asymmetry into a to-do list: it enumerates the defender's
entire externally-named surface so the attacker can shop it for the weakest
point. You are not looking for the front door — that is hardened and watched.
You are looking for the door someone forgot.

### Reading the steps as an attacker's questions

Each step below answers a question a real intruder is actually asking. Keep the
question in mind, not the command:

| Step | The `jq` does… | …but the attacker is asking |
|---|---|---|
| 1 surface | counts hostnames | *How big is the target, really — and what did the count leak that I didn't ask for?* |
| 2 naming | groups labels | *What is their naming rule, so I can guess hosts that aren't even in this data?* |
| 3 nonprod | greps keywords | *Where is the soft underbelly — the box built by a developer, not defended by ops?* |
| 4 shared | reads co-tenants | *Who is my real target? Can I attack their vendor instead of their hardened perimeter?* |
| 5 timeline | sorts by date | *What is new? New means untested, unmonitored, and not yet hardened.* |
| 6 revoked | filters revoked | *What has gone wrong here before, and on what date?* |
| 7 wildcards | counts `*.` | *What are they deliberately hiding, and did they leave a gap?* |

Three of these deserve a sharper edge:

- **Non-production is the prize (step 3), not the leftovers.** An attacker
  targets `dev`, `uat` and `staging` *first*, because they are the same
  application as production with the defences removed: debug endpoints on, real
  data copied down, default credentials, no WAF, and an owner who thinks nobody
  knows the host exists. CT tells them it exists.
- **The supply chain is a way around the wall, not through it (step 4).** If the
  target's own perimeter is hard, you do not batter it — you find the SaaS
  vendor or CDN sharing its certificate and attack *that*, because compromising
  the vendor compromises every tenant at once. The target's firewall never sees
  it coming. This is why one weak vendor is a breach of a hundred customers.
- **Newness is weakness (step 5).** A host that first appears in CT last week has
  had one week of exposure to hardening, monitoring and patching — often none.
  The timeline hands the attacker a queue sorted by "least defended first."

### Recon is a pivot, not a destination

CT recon produces *names*, and names are only the input to the next move. The
attacker's loop is **enumerate → pivot → enumerate again**:

- a hostname pivots to an **IP** (resolve it), which pivots to a **hosting
  provider / ASN**, which pivots to **neighbouring hosts** on the same block;
- a name like `adminer.` or `temporal-ui.` pivots to a **known piece of
  software**, which pivots to its **default credentials and CVEs**;
- a naming convention pivots to **hosts not in the data at all** (step 2);
- a vendor on a shared certificate pivots to a **completely different target**
  (step 4).

Each answer is the seed of the next question. That is what separates recon from
a directory listing: you are building a graph, and CT is one rich, free, silent
starting node.

### The discipline that separates a pro from a script

Two habits in this lab are not busywork — they are what a real operator does to
avoid wasting the one thing they cannot get more of, time and stealth:

- **Rate your confidence.** Step 3's `postgraduate` false positives and step 4's
  `frozenclouds.net` are the lesson. Chasing a host that isn't real burns time
  and, in active recon, burns stealth. A good analyst says *"candidate, not
  confirmed"* and prioritises accordingly.
- **Never trust an absence.** The pagination trap means "no host named X" is
  almost always "no host named X *in the first 100 results*." Attackers who
  assume completeness miss the one host that mattered; defenders who assume it
  declare themselves safe while exposed.

### Now flip it — this is a defensive skill

Everything above is exactly how a blue team runs **Attack Surface Management**:
the defender monitors CT for their *own* domains, on a schedule, to see
themselves the way an attacker does. A new certificate for a host nobody
authorised is shadow IT or a breach in progress; a mis-issued certificate for
your domain is a CA compromise you need to report. The attacker's map and the
defender's inventory are the *same query* — the only difference is who runs it
first. The point of learning to read CT as an attacker is so you can defend
against one, and Part A's step 8 asks you to write exactly that recommendation.

---

# Part A — Guided walkthrough: `smu.edu.sg`

Run each command as you read. Every number below is reproducible.

## Step 1 — Measure the surface

*In the code: search `STEP 1` → `cmd_surface()` in `ct_osint.py`.*

```bash
uv run ct_osint.py surface smu.edu.sg
```

```
  Issuances in capture  : 100
  Distinct names        : 255
  Belonging to target   : 96
  Foreign names         : 159 (on certificates the target shares)
  WARNING               : capture is exactly 100 issuances, a multiple of the
                          API's 100-per-page limit. It was probably truncated:
                          treat this as a sample, not an inventory.
```

Start with the gap between 255 and 96, because it is not a mistake.

**How the three numbers are computed.** There is no cleverness here — it is set
arithmetic on the names the log already handed you, and understanding it is the
whole of step 1:

1. **Distinct names (255)** — collect *every* `dns_names` entry from *every*
   certificate in the capture into one set.
2. **Belonging to target (96)** — keep only the names that are the apex itself
   (`smu.edu.sg`) or end in `.smu.edu.sg`. This is a suffix test, nothing more.
3. **Foreign names (159)** — simply `255 − 96`. Everything the log returned that
   is **not** SMU's.

So the tool never went looking for foreign domains. It did not query them, guess
them, or resolve anything. They are the leftover after subtracting SMU's own
names from everything that arrived.

**Why anything foreign arrived at all** is the part worth slowing down on,
because it is a quirk of *how the query matches*. You asked Cert Spotter for
`domain=smu.edu.sg&include_subdomains=true`. That matches a **certificate** when
*any one* of its Subject Alternative Names is in SMU's scope — but the API then
returns the **entire certificate record, every SAN on it**. Watch it happen on a
single certificate in this capture:

```
one certificate carries 82 SANs:
  in-scope (why the API returned it): ['ccms.smu.edu.sg']
  foreign (came along for the ride) : ['*.bulletin.fsu.edu', '*.calendar.ucalgary.ca',
                                       '*.catalog.berkeley.edu', ...] (81 total)
```

That certificate was returned to you *because of its one `ccms.smu.edu.sg`
name*, and it dragged 81 other universities' hostnames into your results with
it. Multiply that across the capture and you get 159 names for organisations you
never asked about. You asked one question; the *structure of other people's
certificates* decided what else you would see.

**Why it matters.** Two reasons, and they point in opposite directions:

- *It is a finding, not noise.* A hostname is only on a certificate with
  `ccms.smu.edu.sg` if it shares that certificate — which means it shares
  infrastructure, a vendor, or a private key with SMU. That is a supply-chain
  signal you got for free, and step 4 is where you cash it in. The `Top foreign
  domains` line is your first hint: dozens of `.edu` schools clustered on SMU's
  certificates is not a coincidence.
- *It is a trap for the careless.* Nothing stops a report from listing all 255
  as "SMU's attack surface." They are not — 159 of them are other institutions,
  and confusing "names the log returned" with "names the target owns" is the
  single most common beginner error in CT recon. The suffix test in step 2 of
  the arithmetic above is exactly the discipline that keeps them apart. Never
  confuse *what the API returned* with *what the target owns*.

Ninety-six hostnames — the real number — is already a substantial map of an
institution, obtained without sending SMU a single packet.

## Step 2 — Read the naming convention

*In the code: search `STEP 2` → `cmd_naming()` in `ct_osint.py`.*

```bash
uv run ct_osint.py naming smu.edu.sg
```

```
  elearn                : elearn, elearndev, elearnstg, elearnuat
  elearnapps            : elearnapps, elearnapps-dev
  givenow               : givenow, givenow-qa
  isiseddaapi           : isiseddaapi, isiseddaapi-qa
  smu-api               : smu-api, smu-api-qa
```

Five **self-documenting environment ladders**. From `elearn` alone you know the
organisation runs dev, staging and UAT tiers, and you know how it spells them.

The rule is worth more than the hosts, because it **generalises past the edge of
your data**. You have `smu-api` and `smu-api-qa`; `smu-api-dev` and
`smu-api-uat` are now educated guesses rather than blind ones. Remember the
capture is truncated at 100 entries — the convention is how you reason about
what you did not receive.

Then the second half of the output, the obscurity probe:

```
  Obscurity probe -- labels >= 20 chars, all lowercase alphanumeric:
    (none)
```

Nothing. Not one SMU hostname is an unguessable string — every label is a
readable word. **That is a finding, not an absence of one.** SMU is not
attempting obscurity anywhere, so every host it owns is exactly as discoverable
as this command makes it. Part B's target answers this differently.

## Step 3 — Isolate the non-production and administrative hosts

*In the code: search `STEP 3` → `cmd_nonprod()` in `ct_osint.py`.*

```bash
uv run ct_osint.py nonprod smu.edu.sg
```

```
    *.intranet.smu.edu.sg          <- intranet
    elearnapps-dev.smu.edu.sg      <- dev
    elearndev.smu.edu.sg           <- dev
    elearnuat.smu.edu.sg           <- uat
    givenow-qa.smu.edu.sg          <- qa
    intranet.smu.edu.sg            <- intranet
    isiseddaapi-qa.smu.edu.sg      <- qa
    pnc-admin.smu.edu.sg           <- admin
    postgraduate.smu.edu.sg        <- uat
    postgraduate2.smu.edu.sg       <- uat
    praasadmin.smu.edu.sg          <- admin
    smu-api-qa.smu.edu.sg          <- qa
    x509-sf-tlms-qa.smu.edu.sg     <- qa
```

Thirteen hits — and **only eleven are real**. Look at the right-hand column,
which is the whole reason it is there: `postgraduate` and `postgraduate2`
matched on `uat`, because "postgrad·**uat**·e" contains the string. They are
false positives.

Say that out loud in class. Keyword matching is the correct first pass and it
*always* needs a human second pass; a student who reports thirteen
non-production hosts has over-reported by two, and in a real engagement that
lands in a client deliverable.

The reverse error is quieter and worse. Compare against `names` and you will
find this keyword set **misses** `libproxy.smu.edu.sg` and
`*.libproxy.smu.edu.sg` — among the most interesting hosts in the file, since a
library proxy is an authentication endpoint whose job is holding credentials
that unlock paid journal subscriptions. Recall and precision are both imperfect.
The filter finds candidates; the analyst decides.

The eleven real ones: three learning-platform non-prod tiers, four QA APIs
(`givenow` handles donations), two self-named admin interfaces, and the internal
portal. **Why they matter:** non-production systems run debug modes and verbose
errors, carry stale unpatched builds, hold real data copied down from
production, use weak or shared credentials, sit outside the WAF and monitoring
that guard production, and are owned by whoever built them rather than by an ops
team. Same application, defences off.

## Step 4 — Follow the shared certificate

*In the code: search `STEP 4` → `cmd_shared()` in `ct_osint.py`.*

Back to those 159 foreign names.

```bash
uv run ct_osint.py shared smu.edu.sg
```

```
    names  issued       target names on this certificate
    -----  ------       ----------------------------------------
       23  2026-06-23   ink.library.smu.edu.sg, search.library.smu.edu.sg
       82  2025-08-04   ccms.smu.edu.sg
       90  2025-08-14   ccms.smu.edu.sg
       92  2025-08-27   ccms.smu.edu.sg, courses.smu.edu.sg
       99  2025-09-19   ccms.smu.edu.sg, courses.smu.edu.sg

  Widest certificate    : 99 names, 83 distinct registrable domains
```

**Two different mechanisms here, and the difference is the lesson.**

**The 82–99 name certificates are SaaS tenancy.** They are issued for
`*.coursedog.com` and span 83 institutional domains — Berkeley, FSU, Pomona,
Pratt, Ramapo, Durham College, Trent, UWI Cave Hill. Coursedog is a course-catalog
and scheduling vendor, and SMU's share is two names: `ccms` and `courses`.

So without contacting SMU you have learned which third party operates its course
catalog — normally procurement-confidential, and *actionable*, because you would
now attack Coursedog instead. SMU's perimeter, WAF and security team are
irrelevant to that path. Note the direction: **SMU is the tenant, the customer of
a platform.** Part B's target sits on the other side of exactly this arrangement.

**The 23-name certificate is something else entirely.** Run it and look:

```
  *.tcorp.nsw.gov.au        imperva.com               ink.library.smu.edu.sg
  *.enel.com                giapps.zurich.com.hk      search.library.smu.edu.sg
  dprs.saputo.com           yatzran3.tnuva.co.il      ... and an adult-content site
```

An Australian state treasury corporation, Zurich Insurance Hong Kong, an Italian
energy utility, a Canadian dairy, an Israeli food company, a divorce law firm, a
Denver music school, and an adult-content site — sharing one certificate, and
therefore **one private key**, with SMU's library.

That is a **CDN/WAF shared certificate**: `imperva.com` on the list gives it
away. Imperva bundles unrelated customers onto a single certificate at the edge.
Two findings fall out. First, SMU's library sits behind Imperva — you now know
their WAF vendor, which tells you what you would have to evade. Second, SMU's
cryptographic identity is co-tenanted with two dozen strangers it has never
heard of, chosen by a vendor, with no notification and no consent.

Both mechanisms produce the same log entry and mean very different things. Say
which one you are looking at.

## Step 5 — Put the certificates on a timeline

*In the code: search `STEP 5` → `cmd_timeline()` in `ct_osint.py`.*

```bash
uv run ct_osint.py timeline smu.edu.sg --match coursedog
```

```
    issued       names   growth
    ------       -----   ------
    2025-08-04      82        ####################################
    2025-08-07      86   +4   ######################################
    2025-08-14      90   +4   ########################################
    2025-08-27      92   +2   #########################################
    2025-08-27      93   +1   #########################################
    2025-09-19      99   +6   ############################################
    2026-04-16      96   -3   ##########################################
```

Eighty-two names in early August, ninety-nine six weeks later. **You are watching
a SaaS vendor onboard customers, one reissue at a time**, and each reissue dates
the addition to the day. `timeline` also prints the 49 names that appeared across
the series — that is Coursedog's new-customer list for the quarter.

Note the drop to 96 in April 2026: names *left*. CT records churn in both
directions.

The general lesson: *"when did X start using Y?"* is often answerable from a
public log alone, and no amount of press-release discipline conceals it.

## Step 6 — Read the revocations

*In the code: search `STEP 6` → `cmd_revoked()` in `ct_osint.py`.*

```bash
uv run ct_osint.py revoked smu.edu.sg
```

```
    issued       pubkey (first 16)  host(s)
    ------       -----------------  ------------------------------
    2025-11-26   1aedba25c2ad5fd3   isiseddaapi.smu.edu.sg
    2025-11-26   71f187fccd2bc4ae   isiseddaapi-qa.smu.edu.sg
    2026-01-07   d945ce5b632b7c9a   praasadmin.smu.edu.sg
    2026-03-11   610e4c64f97f4e78   elearnapps-dev.smu.edu.sg
    2026-05-14   df212c80917cfef0   smucar.smu.edu.sg

  Same-day cluster      : 2025-11-26: isiseddaapi.smu.edu.sg;
                          isiseddaapi-qa.smu.edu.sg
```

Five revocations, and the tool flags the interesting one: production and QA of
the *same* application, issued the same day and revoked together. Something they
**shared** drove that, not anything about either host — a routine re-key or a
decommission does not take out prod and QA in lockstep.

Now check the pubkey column, which is why it is printed: **`1aedba25…` and
`71f187fc…` are different keys.** So the obvious hypothesis — one leaked private
key used for both — is *not* supported by the evidence in front of you. What
survives is a shared *process*: one request batch, one operator, one CA account,
one mis-issuance unwound together. Good analysts say which of their hypotheses
the data killed.

What to check next: whether replacements for those names appear shortly after
(re-key) or never (decommission).

Then the counter-intuitive part. The PKI lab's Discussion 2 established that
validation is offline and revocation checking is unreliable — clients fail open,
OCSP is soft-fail, CRLs go stale — so a revoked certificate whose key an attacker
holds may still be accepted by plenty of clients. But the greater value here is
different: **revocation is an incident beacon.** It is the organisation publicly
announcing that something went wrong with this exact host on this date. It marks
which systems have a history of key-handling problems and timestamps the event,
with zero contact with the target. Defenders should assume their revocations are
read as telemetry.

## Step 7 — Count wildcards against exact names

*In the code: search `STEP 7` → `cmd_wildcards()` in `ct_osint.py`.*

```bash
uv run ct_osint.py wildcards smu.edu.sg
```

```
  Wildcard names        : 4
  Exact names           : 91
  Wildcard share        : 4%

    *.eservices.smu.edu.sg  *.libproxy.smu.edu.sg
    *.intranet.smu.edu.sg   *.smu.edu.sg
```

`*.intranet.smu.edu.sg` tells you the zone exists and nothing about what is
inside it — you would still have to guess or brute-force the labels, which is
noisy and touches the target. Ninety-one exact names are a finished inventory,
delivered free and silently. Wildcards genuinely reduce CT disclosure, and SMU
is barely using them.

But the trade-off cuts both ways. One wildcard key secures every host in the
zone, so a single compromise takes all of them, and the blast radius grows
silently as hosts are added. Wildcards need the DNS-01 ACME challenge, pushing
organisations toward longer-lived, more manually handled certificates. And hosts
behind a wildcard **do not appear in CT at all** — so *you* lose CT as your own
detection channel for mis-issuance and for shadow IT inside your zone. You are
trading attacker visibility for defender visibility, which is why "use wildcards
everywhere" is not the answer.

## Step 8 — Write the defensive recommendation

CT cannot be opted out of. What would you actually tell SMU?

1. **Assume every hostname is public and defend accordingly.** Authentication
   and network restriction (VPN, allowlist, zero-trust proxy) in front of every
   host from step 3, so knowing the name buys nothing. *Cost:* engineering work
   on systems whose owners believe they are already hidden, plus developer
   friction. The only measure that fixes the problem rather than reducing
   disclosure.
2. **Monitor CT yourself, continuously.** `ct_osint.py fetch` on a schedule,
   diffed against the last run, alerting on names you did not expect. Catches
   mis-issuance *and* shadow IT — someone stands up a host, gets a certificate,
   and you know immediately. Turns the attacker's tool into your asset
   inventory. *Cost:* small. Highest value here and most commonly skipped.
3. **Wildcards for internal and non-production zones.** *Cost:* blast radius,
   weaker automation, and the loss of defender visibility from step 7.
4. **Private DNS zone and private CA for internal hosts** — they never get a
   publicly-trusted certificate, so nothing is logged. *Cost:* you now operate a
   CA, with every failure mode from the PKI lab as your problem.
5. **Naming discipline** — stop encoding function and environment in public
   hostnames. *Cost:* real operational readability, for a gain that is easy to
   overestimate. Be honest that this is the weakest item here.

The mature reading: **(1) and (2) are substantive; (5) is close to a fig leaf.**
CT is not a vulnerability. It is the disclosure that reveals which of your hosts
were quietly relying on not being named.

### What Part A established

Eight commands, no packets sent to SMU: 96 hostnames, the environment-naming
rule, eleven non-production and admin systems, two third-party vendors and the
83 other institutions co-tenanted with one of them, a dated onboarding timeline,
and five incidents with dates. Now do it yourself.

---

# Part B — Open challenge: `tech.gov.sg`

Same eight commands, same order, no answers. GovTech is a different kind of
organisation from a university and the findings differ in kind, not just in
detail — at least one step has an answer that is the **opposite** of SMU's, and
one has an answer that is *nothing at all*. Both are results worth writing down.

Work in pairs. Produce a short written finding for each step.

```bash
uv run ct_osint.py all tech.gov.sg      # or one step at a time
```

**Step 1 — `surface`.** How many names, how many are GovTech's, and does the gap
behave the same way as SMU's?
> *Hint:* the ratio is very different. Before explaining why, look at what the
> foreign names actually **are** — that is step 4 arriving early.

**Step 2 — `naming`.** What do the labels reveal, can you predict unseen hosts,
and did anyone try to hide?
> *Hint:* the ladders are deeper than SMU's — read them for which services exist
> in **production as well as** dev and staging, which is not the same risk. Then
> the obscurity probe, which returned nothing for SMU, returns three things here
> and **one is a false positive** — be ready to say which and why. For the
> genuine hits, look hard at the label immediately *after* the random one and go
> find out what software has that name. Then say in one sentence what the random
> label was for and why it failed.

**Step 3 — `nonprod`.** Far more hits than SMU's thirteen.
> *Hint:* don't just list them — group them by the **platform** they belong to,
> and pick out the two or three that are administrative *consoles* for internal
> engineering tooling rather than web applications. Names worth researching:
> `adminer`, `temporal-ui`, `databricks`, `gcsoc`. Check the right-hand keyword
> column for false positives as you go.

**Step 4 — `shared`.** Who else is on GovTech's certificates?
> *Hint:* this is where GovTech is the **mirror image** of SMU. In Part A, SMU
> was one small tenant on a vendor's certificate. Here — which organisations are
> these, and who is hosting whom? One name in the list is **not a government
> domain at all**; flag it and say what you would ask about it rather than
> guessing what it is.

**Step 5 — `timeline --match airbase`.** Same growth analysis.
> *Hint:* the series runs from single digits to the high twenties over about two
> months. Read it as a story: say what event each jump represents and name three
> organisations with the date they appear. This is the strongest finding in the
> GovTech set. (Running `timeline` with no `--match` auto-picks a series; the
> `airbase` anchor gives the fullest view.)

**Step 6 — `revoked`.** The answer is **zero**.
> *Hint:* interpret it, don't report it as nothing. Give two competing
> explanations — one flattering to GovTech, one not — and say what evidence
> would distinguish them. Re-read the pagination trap before you commit.

**Step 7 — `wildcards`.** GovTech uses proportionally far more than SMU.
> *Hint:* quantify it, then argue whether it is deliberate policy or a
> side-effect of running a multi-tenant platform — and what it costs GovTech's
> own security team, not just what it denies an attacker.

**Step 8 — the recommendation.** Three measures with costs.
> *Hint:* GovTech's exposure is structurally different from SMU's. Its biggest
> disclosure is not about GovTech's own hosts at all — it is about its
> **customers**. At least one recommendation should address what a platform
> provider owes the tenants whose names it publishes.

**Deliverable.** One page: eight findings, plus a closing paragraph on which
target is more exposed and why. "More hostnames" is not an answer — argue it on
what the names let an attacker *do*.

---

<!-- ============ INSTRUCTOR SECTION — remove before distributing ============ -->

## Instructor answer key — Part B (`tech.gov.sg`)

**Step 1.** 111 names, **79** GovTech's — a much tighter ratio than SMU's
255/96, and for the opposite reason. SMU's foreign names came from being one
tenant on a huge vendor certificate; GovTech's 32 foreign names are other
*government bodies* on certificates GovTech itself operates. Same query,
inverted relationship.

**Step 2.** The ladders are deeper and more revealing than SMU's:

```
  butler              : butler, dev.butler, stg.butler
  temporal-ui.butler  : temporal-ui.butler, temporal-ui.dev.butler,
                        temporal-ui.stg.butler
  developer           : developer, preview.developer, dev.preview.developer,
                        stg.preview.developer
  v2.developer        : v2.developer, dev.v2.developer, stg.v2.developer
  thunderbird         : thunderbird, sandbox.thunderbird, uat.thunderbird
  obmgr.gcsoc         : obmgr.gcsoc, stg.obmgr.gcsoc
  self-service.gcsoc  : self-service.gcsoc, stg.self-service.gcsoc
  automation.deep     : automation-stg.deep, automation.stg.deep
```

Two observations beyond SMU's. First, several of these exist in **production**,
not just dev/stg — `temporal-ui.butler.tech.gov.sg` has no environment label,
so the workflow console is exposed in prod too. Second, `automation-stg.deep`
alongside `automation.stg.deep` shows **two different conventions for the same
thing**, which means the ladder is not centrally governed — useful for guessing
names, and a small governance finding in its own right.

The probe returns three:

```
2a57j77y7szbjqmukmpdo1m4xmi7shv.adminer.uat-cioapps.tech.gov.sg
2a57j77y7szbjqmukmpdo1m4xmi7shv.govmirrorv3.uat-cioapps.tech.gov.sg
modernisationplaybook.in.tech.gov.sg
```

The third is the false positive — 21 lowercase alphanumeric characters, so it
matches the length rule, but it is an English phrase. Students who cannot
articulate *why* the first two are random and the third is not have not done the
step.

The finding: a **31-character random label** in front of `adminer`. Adminer is a
single-file web-based database administration tool, the lightweight PHP
alternative to phpMyAdmin. A database admin console, on a UAT host, with an
unguessable name in front of it — security through obscurity, protecting
something presumed to have weak or absent authentication.

Then a certificate was issued and the name was published permanently in a log
built to be searched. **Obscurity is not a control when your naming is
authenticated by a system whose entire purpose is public disclosure.** Correct
fix: authentication and network restriction on the host. If the name itself must
stay secret, the certificate has to be a wildcard so the label never enters the
log — which is the step 7 trade-off arriving with teeth.

**Step 3.** ~30 hits, best grouped by platform: `butler` (`dev`, `stg`, `guide.dev`,
`temporal-server.dev`, `temporal-ui` × 3), `thunderbird` (`sandbox`, `uat`),
`developer` (`dev.v2`, `stg.v2`, `dev.preview`, `stg.preview`, `api.console.dev`),
`uat-cioapps` (`adminer`, `govmirrorv3`, both also with the random prefix),
`gcsoc` (`obmgr`, `self-service`, both also `stg.`), plus `bvat-sandbox`,
`gvt-databricks-uat.data`, `workflow-dev.odp`, `sfauat.in`, `automation*.deep`.

The ones that matter are **consoles, not applications**:

- `adminer` — database administration.
- `temporal-ui` — Temporal workflow-engine web UI: visibility into and control
  over running workflows. Present in dev, stg **and prod**.
- `gvt-databricks-uat` — Databricks data platform.
- `gcsoc` — Government Cyber Security Operations Centre tooling (`obmgr`,
  `self-service`), prod and staging.

An application leaks its own data; a console leaks whatever the platform behind
it can reach. `gcsoc` is the one to dwell on: security-operations tooling is a
high-value target precisely because it is where defenders look from.

**Step 4.** GovTech is the **platform provider** — the mirror of SMU's tenancy.
The foreign names are other government bodies riding GovTech-operated
certificates: `moe.gov.sg`, `msf.gov.sg`, `mnd.gov.sg`, `parliament.gov.sg`,
`singaporebudget.gov.sg`, `wsg.gov.sg`, `ecda.gov.sg`,
`cleanenvirosummit.gov.sg`, `icanactagainstscams.gov.sg`,
`infrastructureasia.org`, plus `optical.gov.sg` and `oa.gov.sg`. Mostly as
`www.beta.*` and `www.stg.*`, so each ministry's **staging** hostnames come free.

The odd one out is **`frozenclouds.net`** / `staging.frozenclouds.net` — not a
government domain, sharing a certificate (and therefore a private key) with
`on.tc2.airbase.tech.gov.sg` and `mofbudget.staging.optical.gov.sg` (Ministry of
Finance budget, staging). Good answers flag it and propose the *question* rather
than a conclusion: a developer's personal domain onboarded to a government
platform, a test tenant never removed, or a legitimate contractor? Whichever it
is, it shares a key with an MOF staging host and somebody should be able to say
which. That is a high-value finding stated at the correct confidence.

**Step 5.** The `airbase` series:

```
2025-09-09    1        2025-10-11   13
2025-09-09    4        2025-10-11   15
2025-09-09    5        2025-10-14   17
2025-09-12    6        2025-10-24   21
2025-10-01    7        2025-11-03   22
2025-10-07    9        2025-11-05   24
2025-10-07   10        2025-11-06   27
2025-10-08   11        2025-11-12   28
```

One name to twenty-eight in nine weeks: **a platform launch watched from outside
in real time**, each reissue naming the tenants added since the last and dating
each onboarding to the day. Parliament appears 2025-10-24; InfrastructureAsia
2025-11-05; MSF 2025-11-06.

The strongest finding in the set and the one that generalises best: an
organisation's roadmap, customer list and delivery cadence reconstructed from
certificate reissues.

**Step 6.** Zero revoked. Two readings:

- *Flattering:* clean key hygiene, no incidents in this window — a platform team
  with solid automated certificate management.
- *Unflattering:* revocation is nearly useless (PKI lab Discussion 2), so many
  mature operators **do not bother** — they let a short-lived certificate expire
  instead. "No revocations" can mean "no incidents" or "incidents handled by
  waiting 90 days."

Distinguishing evidence: names that appear once and never reissue (quiet
decommission, or an unremediated incident) versus names reissued on a clean
cadence; and certificate lifetimes, since a 90-day ACME shop has far less need to
revoke than a shop with 1-year certificates. And the capture is truncated, so
"zero" is zero **in this sample**. A student who writes "GovTech has never
revoked a certificate" has fallen into the pagination trap — mark it down.

**Step 7.** 15 wildcard / 64 exact — 19%, against SMU's 4%. Both explanations
have merit and the best answers hold them together: partly deliberate (a
security-engineering-led organisation that understands CT disclosure), partly
structural (a multi-tenant platform with `*.app.oobee`, `*.bvat`, `*.cioapps`,
`*.designsystem` naturally issues per-zone wildcards regardless of disclosure).

The cost is the step 7 trade-off at platform scale: every host behind
`*.cioapps.tech.gov.sg` is invisible in CT **to GovTech's own security team as
well**. For an organisation hosting other ministries, losing CT as a shadow-IT
detection channel across your own estate is a significant and under-appreciated
price — and the `adminer` host is exactly the sort of thing that goes unnoticed
inside such a zone.

**Step 8.** Expect the Part A measures correctly re-aimed. The distinguishing
insight is that GovTech's largest disclosure is about its **tenants**, so a good
answer includes something like *per-tenant certificates, or at minimum not
co-locating one ministry's staging hostnames with another's* — cost: many more
certificates to automate and renew, precisely the cost Coursedog and Imperva
both declined to pay in Part A. Also creditable: a platform provider's
obligation to tell tenants what onboarding discloses, and an answer for
`frozenclouds.net`.

**Closing paragraph.** No single right answer, but the argument must run on
capability, not count. SMU has more hostnames (96 vs 79) and a richer
non-production surface for its size. GovTech has fewer names but far
higher-value ones — database, workflow and **security-operations** consoles, an
MOF staging host sharing a key with an unexplained third-party domain, and a
blast radius extending to a dozen other government bodies. The strongest
submissions notice that **SMU's exposure is bounded by SMU, while GovTech's
exposure is other people's**, and that this, not the hostname count, is what
makes a platform provider the more consequential target.

<!-- ========================= END INSTRUCTOR SECTION ========================= -->

---

> **Ethics.** Everything above reads a public, append-only log. No packet reaches
> the target, no system is accessed, and nothing here is unlawful — that is
> exactly what makes CT worth understanding, from both sides. `fetch` is the only
> command that uses the network, and it talks to Cert Spotter, not to the target.
> Resolving, scanning or connecting to the hosts you find is a different act with
> a different legal status: do that only against systems you own or have written
> authorisation to test. The named organisations appear here because their logs
> are public and their engineering is good; the findings are ordinary and would
> look much the same for almost any large domain, including your own.
