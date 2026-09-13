# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""
ct_osint.py  --  Certificate Transparency OSINT toolkit. Standard library only.

Every certificate issued for a domain since 2018 is published in a public,
append-only, cryptographically-verifiable log. This tool reads those logs and
turns them into an attack-surface map -- without sending a single packet to
the target.

Each subcommand is one step of the lab. Run them in order, or use `all`.

Commands
  uv run ct_osint.py fetch     <domain>   download the CT log (the only network call)
  uv run ct_osint.py names     <domain>   step 0: every hostname belonging to the target
  uv run ct_osint.py surface   <domain>   step 1: measure the attack surface
  uv run ct_osint.py naming    <domain>   step 2: read the naming convention
  uv run ct_osint.py nonprod   <domain>   step 3: non-production and admin hosts
  uv run ct_osint.py shared    <domain>   step 4: who else is on these certificates
  uv run ct_osint.py timeline  <domain>   step 5: watch a certificate grow over time
  uv run ct_osint.py revoked   <domain>   step 6: read the revocations
  uv run ct_osint.py wildcards <domain>   step 7: wildcards vs exact names
  uv run ct_osint.py all       <domain>   steps 1-7 in sequence

Add --brief to any command to drop the explanations and print only the data.

-------------------------------------------------------------------------------
HOW THIS FILE IS ORGANISED   (search for an ALL-CAPS tag to jump straight to it)
-------------------------------------------------------------------------------
  SECTION 1  OUTPUT HELPERS   pretty-printing only -- skip on a first read
  SECTION 2  DATA HELPERS     load the log; the name-parsing used by every step
  SECTION 3  THE STEPS        one function per lab step, each tagged "STEP n"
  SECTION 4  CLI PLUMBING     main() -- argument parsing

Each README step maps 1:1 to a subcommand and a function (search the tag):

  README step        command      function          search tag
  -----------------  -----------  ----------------  ----------
  (download)         fetch        cmd_fetch         COMMAND: fetch
  (raw list)         names        cmd_names         STEP 0
  1  surface         surface      cmd_surface       STEP 1
  2  naming          naming       cmd_naming        STEP 2
  3  non-prod        nonprod      cmd_nonprod       STEP 3
  4  shared cert     shared       cmd_shared        STEP 4
  5  timeline        timeline     cmd_timeline      STEP 5
  6  revoked         revoked      cmd_revoked       STEP 6
  7  wildcards       wildcards    cmd_wildcards     STEP 7
  (run all)          all          cmd_all           COMMAND: all

So `grep -n "STEP 4" ct_osint.py` jumps to the code behind README step 4.

Author: Kee Hock (CS440 AY26T1 supplementary material)
"""

import argparse
import json
import sys
import textwrap
from collections import Counter, defaultdict
from pathlib import Path

WIDTH = 78
API = "https://api.certspotter.com/v1/issuances"

# Hostnames that hint at a non-production or administrative system. Keyword
# matching is a first pass, never a verdict -- see the warning in cmd_nonprod.
NONPROD_KEYWORDS = ["dev", "test", "uat", "qa", "stag", "sandbox", "demo",
                    "beta", "admin", "intranet", "internal", "preview"]

# Two-label public suffixes we care about, so "ccms.smu.edu.sg" reduces to
# "smu.edu.sg" and not "edu.sg". Not a full Public Suffix List -- that would
# need a dependency, and this covers the academic/government domains in scope.
TWO_LABEL_SUFFIXES = {
    "edu.sg", "gov.sg", "com.sg", "org.sg", "net.sg", "edu.au", "gov.au",
    "com.au", "org.au", "ac.uk", "co.uk", "gov.uk", "org.uk", "edu.hk",
    "gov.hk", "com.hk", "edu.my", "gov.my", "com.my", "ac.nz", "govt.nz",
    "co.nz", "edu.in", "gov.in", "co.in", "edu.cn", "gov.cn", "com.cn",
}


# =============================================================================
# SECTION 1  --  OUTPUT HELPERS
# Pure presentation: format the console transcript so it reads top to bottom.
# None of this affects the analysis; skip it on a first read.
# =============================================================================
def header(title: str) -> None:
    print()
    print("=" * WIDTH)
    print(f" {title}")
    print("=" * WIDTH)


def datablock(label: str, value, indent: int = 2) -> None:
    pad, col = " " * indent, 24
    lines = textwrap.wrap(str(value), width=WIDTH - col - indent) or [""]
    print(f"{pad}{label:<{col - 2}}: {lines[0]}")
    for line in lines[1:]:
        print(f"{pad}{'':<{col - 2}}  {line}")


def explain(text: str, brief: bool = False) -> None:
    if brief:
        return
    print()
    for para in text.strip().split("\n\n"):
        for line in textwrap.wrap(" ".join(para.split()), width=WIDTH - 4):
            print(f"    {line}")
        print()


def columns(items: list[str], width: int = WIDTH - 4, gutter: int = 2) -> None:
    """Print a sorted list in as many aligned columns as will fit."""
    if not items:
        print("    (none)")
        return
    w = max(len(i) for i in items) + gutter
    ncol = max(1, width // w)
    rows = (len(items) + ncol - 1) // ncol
    for r in range(rows):
        line = "".join(items[r + c * rows].ljust(w)
                       for c in range(ncol) if r + c * rows < len(items))
        print("    " + line.rstrip())


# =============================================================================
# SECTION 2  --  DATA HELPERS
# Load the capture, and the name-parsing every step leans on:
#   own_names()   -- names belonging to the target      (used by STEP 1)
#   registrable() -- reduce a host to its registrable domain (foreign grouping)
#   family_of()   -- strip env markers to group a service ladder (STEP 2)
#   is_wildcard() -- tell "*.x" from an exact name       (used by STEP 7)
# =============================================================================
def logfile(domain: str) -> Path:
    return Path(f"{domain}.ct.logs")


def load(domain: str) -> list[dict]:
    path = logfile(domain)
    if not path.exists():
        raise SystemExit(
            f"No capture found at {path}.\n"
            f"Either run:  uv run ct_osint.py fetch {domain}\n"
            f"or cd into week-5/osint-challenge-with-cert where the captures live.")
    entries = json.loads(path.read_bytes())
    if not isinstance(entries, list):
        raise SystemExit(f"{path} is not a Cert Spotter issuance array.")
    return entries


def all_names(entries: list[dict]) -> set[str]:
    return {n for e in entries for n in e.get("dns_names", [])}


def own_names(entries: list[dict], domain: str) -> set[str]:
    """Names belonging to the target: the apex itself, or anything under it."""
    suffix = "." + domain
    return {n for n in all_names(entries) if n == domain or n.endswith(suffix)}


def label_of(name: str, domain: str) -> str:
    """'elearndev.smu.edu.sg' -> 'elearndev'; strips a leading wildcard."""
    stem = name[: -len("." + domain)] if name.endswith("." + domain) else name
    return stem[2:] if stem.startswith("*.") else stem


def registrable(name: str) -> str:
    """Reduce a hostname to its registrable domain, e.g. 'smu.edu.sg'."""
    parts = name.lstrip("*.").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_LABEL_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


ENV_WORDS = ["staging", "sandbox", "preview", "prod", "beta", "demo", "test",
             "stg", "uat", "dev", "qa"]   # longest first: 'staging' before 'stg'


def family_of(label_path: str) -> str:
    """
    Strip environment markers from a label path to get its service family.

    Handles both naming styles seen in the wild: a suffix on the leading label
    ('elearndev' -> 'elearn') and a separate label anywhere in the path
    ('dev.v2.developer' -> 'v2.developer'), so flat and deeply-nested estates
    group the same way.
    """
    kept = [l for l in label_path.split(".") if l not in ENV_WORDS]
    if not kept:
        return label_path
    head = kept[0]
    for e in ENV_WORDS:
        for form in (f"-{e}", f"_{e}", e):
            if head.endswith(form) and len(head) > len(form):
                return ".".join([head[: -len(form)].rstrip("-_")] + kept[1:])
    return ".".join(kept)


def is_wildcard(name: str) -> bool:
    return name.startswith("*.")


# =============================================================================
# SECTION 3  --  THE STEPS   (one function per lab step; search "STEP n")
# Each cmd_* below is exactly one README step. They are ordered as the lab runs
# them. `fetch` and `all` are commands, not numbered steps.
# =============================================================================

# ---- COMMAND: fetch -- download the CT log (the ONLY command using the network)
def cmd_fetch(args) -> int:
    import urllib.request  # imported here: every other command is offline

    domain, out = args.domain, logfile(args.domain)
    if out.exists() and not args.force:
        raise SystemExit(f"{out} already exists; pass --force to overwrite.")

    header(f"FETCH: certificate transparency log for {domain}")
    collected: list[dict] = []
    after = None
    for page in range(1, args.max_pages + 1):
        url = (f"{API}?domain={domain}&include_subdomains=true"
               f"&expand=dns_names&expand=issuer")
        if after:
            url += f"&after={after}"
        req = urllib.request.Request(url, headers={"User-Agent": "cs440-ct-osint/1.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            batch = json.loads(r.read())
        datablock(f"page {page}", f"{len(batch)} issuances"
                                  + (f", after={after}" if after else ""))
        if not batch:
            break
        collected += batch
        after = batch[-1]["id"]
        if len(batch) < 100:
            break
    else:
        print(f"\n  Stopped at --max-pages {args.max_pages}; there may be more.")

    out.write_text(json.dumps(collected, indent=1))
    print()
    datablock("Saved", f"{len(collected)} issuances -> {out}")
    explain("""
        That loop is the part everyone gets wrong. Cert Spotter returns at most
        100 issuances per request, so a single un-paged call silently truncates
        your results. You page by handing back the id of the last entry as
        'after='. Until you have paged to an empty response, every "target X
        has no host named Y" conclusion you draw is unsound.
    """, args.brief)
    return 0


# ---- STEP 0 (names) -- every hostname belonging to the target ---------------
def cmd_names(args) -> int:
    entries = load(args.domain)
    names = sorted(own_names(entries, args.domain))
    header(f"NAMES: every {args.domain} hostname in the capture")
    columns(names)
    print()
    datablock("Total", f"{len(names)} distinct hostnames")
    explain("""
        This is the raw material. No packet reached the target to produce it --
        the organisation published every one of these names itself, as a
        side-effect of asking a CA for a certificate.
    """, args.brief)
    return 0


# ---- STEP 1 (surface) -- Measure the surface  (README Part A, Step 1) -------
def cmd_surface(args) -> int:
    entries = load(args.domain)
    every, mine = all_names(entries), own_names(entries, args.domain)
    foreign = every - mine

    header(f"STEP 1 -- SURFACE: {args.domain}")
    datablock("Issuances in capture", len(entries))
    datablock("Distinct names", len(every))
    datablock("Belonging to target", len(mine))
    datablock("Foreign names", f"{len(foreign)} (on certificates the target shares)")
    if entries and len(entries) % 100 == 0:
        datablock("WARNING", f"capture is exactly {len(entries)} issuances, a "
                             f"multiple of the API's 100-per-page limit. It was "
                             f"probably truncated: treat this as a sample, not "
                             f"an inventory.")
    if foreign:
        top = Counter(registrable(n) for n in foreign).most_common(5)
        datablock("Top foreign domains", ", ".join(f"{d} ({c})" for d, c in top))

    explain("""
        Start with the gap between those two numbers, because it is not a
        mistake. You queried one domain, but the API matches a CERTIFICATE if
        any name on it is in scope -- and then hands you EVERY name on that
        certificate. The foreign names belong to organisations you never asked
        about. Step 4 is where that becomes a finding.
    """, args.brief)
    return 0


# ---- STEP 2 (naming) -- Read the naming convention  (README Step 2) ---------
def cmd_naming(args) -> int:
    entries = load(args.domain)
    mine = own_names(entries, args.domain)
    labels = sorted({label_of(n, args.domain) for n in mine})

    header(f"STEP 2 -- NAMING CONVENTION: {args.domain}")

    # Group hosts into service families by removing environment markers.
    families: dict[str, set[str]] = defaultdict(set)
    for lab in labels:
        families[family_of(lab)].add(lab)
    ladders = {b: sorted(v) for b, v in families.items() if len(v) > 1}

    print("  Service families with more than one environment visible:")
    print()
    if ladders:
        for base, members in sorted(ladders.items()):
            datablock(base, ", ".join(members))
    else:
        print("    (none detected)")

    explain("""
        A visible environment ladder is worth more than the hosts it lists,
        because it exposes the RULE. Once you know an organisation spells its
        tiers '-dev', '-qa', 'uat', you can extend the map past the edge of
        your capture: a service you have only seen in production now has
        predictable siblings to try. Remember the capture is truncated -- the
        convention is how you reason about what you did not receive.
    """, args.brief)

    # The obscurity probe.
    obscure = sorted({lab.split(".")[0] for lab in labels
                      if len(lab.split(".")[0]) >= args.min_len
                      and lab.split(".")[0].isalnum()
                      and lab.split(".")[0].islower()})
    print()
    print(f"  Obscurity probe -- labels >= {args.min_len} chars, all lowercase alphanumeric:")
    print()
    if obscure:
        for lab in obscure:
            hosts = [n for n in sorted(mine)
                     if label_of(n, args.domain).split(".")[0] == lab]
            datablock(lab, f"{len(hosts)} host(s)")
            for h in hosts:
                print(f"      - {h}")
    else:
        print("    (none)")

    explain("""
        A long unguessable label means somebody deliberately chose a name they
        hoped nobody would find -- security through obscurity, usually in front
        of something with weak or absent authentication. Then a certificate was
        issued and the name was published, permanently, in a log built to be
        searched.

        Two cautions. This probe finds CANDIDATES: an ordinary long English
        word matches the same rule, so read every hit before you report it. And
        finding nothing is also a result -- it means the organisation is not
        attempting obscurity anywhere, so every host it owns is exactly as
        discoverable as this command makes it.
    """, args.brief)
    return 0


# ---- STEP 3 (nonprod) -- Isolate the non-production and admin hosts (Step 3)-
def cmd_nonprod(args) -> int:
    entries = load(args.domain)
    mine = sorted(own_names(entries, args.domain))

    hits: list[tuple[str, list[str]]] = []
    for n in mine:
        matched = [k for k in NONPROD_KEYWORDS if k in label_of(n, args.domain).lower()]
        if matched:
            hits.append((n, matched))

    header(f"STEP 3 -- NON-PRODUCTION & ADMIN HOSTS: {args.domain}")
    datablock("Keywords", ", ".join(NONPROD_KEYWORDS))
    datablock("Hosts matched", f"{len(hits)} of {len(mine)}")
    print()
    for n, matched in hits:
        print(f"    {n:<52} <- {', '.join(matched)}")

    explain("""
        The right-hand column is the point. It shows WHICH keyword fired, so
        you can see when the match is an accident of spelling rather than a
        real finding -- read each one and decide before it reaches a report.
        Keyword grepping is the correct first pass and it always needs a human
        second pass.

        The quieter error runs the other way: this list also MISSES interesting
        hosts whose names contain none of these words. Compare it against the
        full output of `names` and ask what a keyword list could never catch.
        Recall and precision are both imperfect here.

        Why these hosts matter: non-production systems run debug modes and
        verbose errors, carry stale unpatched builds, hold real data copied
        down from production, use weak or shared credentials, sit outside the
        WAF and monitoring that guard production, and are owned by whoever
        built them rather than by an ops team. Same application, defences off.
    """, args.brief)
    return 0


# ---- STEP 4 (shared) -- Follow the shared certificate  (README Step 4) ------
def cmd_shared(args) -> int:
    entries = load(args.domain)
    big = [e for e in entries if len(e.get("dns_names", [])) >= args.min_names]
    big.sort(key=lambda e: len(e["dns_names"]))

    header(f"STEP 4 -- SHARED CERTIFICATES: {args.domain}")
    datablock("Threshold", f"certificates carrying >= {args.min_names} hostnames")
    datablock("Matching", f"{len(big)} of {len(entries)} issuances")
    if not big:
        print("\n    No shared certificates at this threshold. Try --min-names 5.")
        return 0

    print()
    print(f"    {'names':>5}  {'issued':<12} {'target names on this certificate'}")
    print(f"    {'-----':>5}  {'------':<12} {'-' * 40}")
    seen = set()
    for e in big:
        ours = sorted(n for n in e["dns_names"]
                      if n == args.domain or n.endswith("." + args.domain))
        key = (len(e["dns_names"]), tuple(ours))
        if key in seen:
            continue
        seen.add(key)
        print(f"    {len(e['dns_names']):>5}  {e['not_before'][:10]:<12} "
              f"{', '.join(ours) or '(none)'}")

    widest = big[-1]
    orgs = sorted({registrable(n) for n in widest["dns_names"]})
    print()
    datablock("Widest certificate", f"{len(widest['dns_names'])} names, "
                                    f"{len(orgs)} distinct registrable domains")
    datablock("A sample of them", ", ".join(orgs[:12]) + (" ..." if len(orgs) > 12 else ""))

    explain("""
        A certificate carrying dozens of unrelated organisations is a SaaS
        vendor bundling its tenants onto one certificate. That single fact tells
        you which third party operates the service -- normally
        procurement-confidential information -- and it is actionable, because
        you would now attack the vendor rather than the target. The target's
        perimeter is irrelevant to that path.

        Read the direction of the relationship carefully. Is your target one
        small tenant on somebody else's certificate, or the platform whose
        certificate carries everybody else? The query is identical; the finding
        is the opposite. And note that every organisation on the list has
        disclosed its vendor relationship to all the others, none of whom asked.
    """, args.brief)
    return 0


# ---- STEP 5 (timeline) -- Put the certificates on a timeline  (Step 5) ------
def cmd_timeline(args) -> int:
    entries = load(args.domain)

    match = args.match
    if not match:
        # Pick the busiest "platform": the registrable domain appearing on the
        # most multi-name certificates.
        counter: Counter = Counter()
        for e in entries:
            if len(e.get("dns_names", [])) >= 3:
                for n in set(e["dns_names"]):
                    counter[n] += 1
        if not counter:
            raise SystemExit("No multi-name certificates; pass --match to pick a series.")
        # The most-repeated individual HOSTNAME across multi-name certificates
        # anchors the series. Matching on a registrable domain would just pick
        # the target's own domain, which is on every certificate in the file.
        match = counter.most_common(1)[0][0]

    series = [e for e in entries
              if any(match in n for n in e.get("dns_names", []))]
    series.sort(key=lambda e: e["not_before"])

    header(f"STEP 5 -- TIMELINE: certificates matching '{match}'")
    datablock("Series length", f"{len(series)} issuances")
    if not series:
        print("\n    Nothing matched. Try --match with a platform hostname.")
        return 0

    print()
    print(f"    {'issued':<12} {'names':>5}   {'growth'}")
    print(f"    {'------':<12} {'-----':>5}   {'------'}")
    prev, peak = None, max(len(e["dns_names"]) for e in series)
    span = WIDTH - 34
    for e in series:
        n = len(e["dns_names"])
        delta = "" if prev is None else (f"+{n - prev}" if n > prev
                                         else (str(n - prev) if n < prev else "="))
        bar = "#" * max(1, round(span * n / peak))
        print(f"    {e['not_before'][:10]:<12} {n:>5}   {delta:<4} {bar}")
        prev = n

    first, last = series[0], series[-1]
    added = sorted(set(last["dns_names"]) - set(first["dns_names"]))
    if added:
        print()
        datablock("Names added across the series", f"{len(added)}")
        columns(added[:20])
        if len(added) > 20:
            print(f"    ... and {len(added) - 20} more")

    explain("""
        A CT log is not a snapshot, it is a dated append-only history. When a
        certificate is reissued with more names than last time, you are
        watching a platform onboard customers -- and each reissue dates the
        addition to the day.

        That turns 'when did X start using Y?' into a question a public log
        answers, which is competitive intelligence no press-release discipline
        can conceal. Names disappearing between reissues are just as
        informative: they record churn.
    """, args.brief)
    return 0


# ---- STEP 6 (revoked) -- Read the revocations  (README Step 6) --------------
def cmd_revoked(args) -> int:
    entries = load(args.domain)
    revoked = [e for e in entries if e.get("revoked")]
    revoked.sort(key=lambda e: e["not_before"])

    header(f"STEP 6 -- REVOCATIONS: {args.domain}")
    datablock("Revoked", f"{len(revoked)} of {len(entries)} issuances")

    if revoked:
        print()
        print(f"    {'issued':<12} {'pubkey (first 16)':<18} host(s)")
        print(f"    {'------':<12} {'-' * 17:<18} {'-' * 30}")
        for e in revoked:
            print(f"    {e['not_before'][:10]:<12} {e.get('pubkey_sha256', '?')[:16]:<18} "
                  f"{' '.join(e['dns_names'])}")

        by_date = defaultdict(list)
        for e in revoked:
            by_date[e["not_before"][:10]].append(e)
        clusters = {d: v for d, v in by_date.items() if len(v) > 1}
        if clusters:
            print()
            for d, group in sorted(clusters.items()):
                datablock("Same-day cluster", f"{d}: "
                          + "; ".join(" ".join(e["dns_names"]) for e in group))
            explain("""
                Certificates issued on the same day and revoked together were
                almost certainly revoked for something they SHARED, not for
                anything about either host -- most plausibly a mishandled
                private key, or a mis-issuance that had to be unwound. A
                routine re-key or a decommission does not usually take out
                several hosts in lockstep. Compare the pubkey column: reuse
                across the cluster corroborates the compromise reading.
            """, args.brief)
    else:
        explain("""
            Zero revocations. Interpret that rather than reporting it as
            nothing, and give both readings.

            Flattering: clean key hygiene and no incidents in this window.
            Unflattering: revocation is nearly useless -- clients fail open,
            OCSP is soft-fail, CRLs go stale -- so many mature operators do not
            bother, and simply let a short-lived certificate expire instead.
            'No revocations' can mean 'no incidents' or 'incidents handled by
            waiting 90 days'.

            And this capture may be truncated. Zero here means zero IN THIS
            SAMPLE, which is not the same claim.
        """, args.brief)

    if revoked and not args.brief:
        explain("""
            Remember from the PKI lab that validation is offline and revocation
            checking is unreliable, so a revoked certificate whose key an
            attacker holds may still be accepted by plenty of clients. But the
            greater value to a reader of this log is different: revocation is
            an INCIDENT BEACON. It is the organisation publicly announcing that
            something went wrong with this exact host on this date. Defenders
            should assume their revocations are read as telemetry.
        """)
    return 0


# ---- STEP 7 (wildcards) -- Count wildcards against exact names  (Step 7) ----
def cmd_wildcards(args) -> int:
    entries = load(args.domain)
    mine = own_names(entries, args.domain)
    wild = sorted(n for n in mine if is_wildcard(n))
    exact = sorted(n for n in mine if not is_wildcard(n) and n != args.domain)

    header(f"STEP 7 -- WILDCARDS vs EXACT NAMES: {args.domain}")
    datablock("Wildcard names", len(wild))
    datablock("Exact names", len(exact))
    total = len(wild) + len(exact)
    if total:
        datablock("Wildcard share", f"{100 * len(wild) / total:.0f}%")
    if args.domain in mine:
        datablock("Note", f"the apex '{args.domain}' is counted in neither column")
    print()
    print("  Wildcards:")
    columns(wild)

    explain("""
        A wildcard tells you a zone exists and nothing about what is inside it.
        You would still have to guess or brute-force the labels, which is noisy
        and touches the target. A list of exact names is a finished inventory,
        delivered free and silently. So wildcards genuinely reduce what CT
        discloses.

        The trade-off cuts both ways. One key now secures every host in the
        zone, so a single compromise takes all of them, and the blast radius
        grows silently as hosts are added. Wildcards need the DNS-01 ACME
        challenge, which pushes organisations toward longer-lived, more
        manually handled certificates. And hosts behind a wildcard do not
        appear in CT AT ALL -- so you lose CT as your own detection channel for
        mis-issuance and for shadow IT inside your zone. You are trading
        attacker visibility for defender visibility, which is why 'use
        wildcards everywhere' is not the answer.
    """, args.brief)
    return 0


# ---- COMMAND: all -- run STEP 1..7 in sequence ------------------------------
def cmd_all(args) -> int:
    for fn in (cmd_surface, cmd_naming, cmd_nonprod, cmd_shared,
               cmd_timeline, cmd_revoked, cmd_wildcards):
        fn(args)
    header(f"DONE: {args.domain}")
    explain("""
        Seven steps, no packets sent to the target. Write up what you have: the
        hostnames, the naming rule, the non-production and admin systems, the
        third parties and which direction the relationship runs, the dated
        timeline, the incidents, and how much of it a wildcard would have
        hidden. Then say what you would tell the organisation to do about it.
    """, args.brief)
    return 0


# =============================================================================
# SECTION 4  --  CLI PLUMBING
# Maps each subcommand to its cmd_* function.
# =============================================================================
def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add(nm, fn, help_):
        p = sub.add_parser(nm, help=help_)
        p.add_argument("domain")
        p.add_argument("--brief", action="store_true",
                       help="data only, no explanations")
        p.set_defaults(fn=fn)
        return p

    p = add("fetch", cmd_fetch, "download the CT log (the only network call)")
    p.add_argument("--force", action="store_true", help="overwrite an existing capture")
    p.add_argument("--max-pages", type=int, default=20, help="pagination safety stop")

    add("names", cmd_names, "every hostname belonging to the target")
    add("surface", cmd_surface, "step 1: measure the attack surface")

    p = add("naming", cmd_naming, "step 2: read the naming convention")
    p.add_argument("--min-len", type=int, default=20,
                   help="obscurity probe: minimum label length (default 20)")

    add("nonprod", cmd_nonprod, "step 3: non-production and admin hosts")

    p = add("shared", cmd_shared, "step 4: who else is on these certificates")
    p.add_argument("--min-names", type=int, default=10,
                   help="certificates carrying at least this many names (default 10)")

    p = add("timeline", cmd_timeline, "step 5: watch a certificate grow over time")
    p.add_argument("--match", help="substring picking the certificate series "
                                   "(default: the busiest platform)")

    add("revoked", cmd_revoked, "step 6: read the revocations")
    add("wildcards", cmd_wildcards, "step 7: wildcards vs exact names")

    p = add("all", cmd_all, "steps 1-7 in sequence")
    p.add_argument("--min-len", type=int, default=20)
    p.add_argument("--min-names", type=int, default=10)
    p.add_argument("--match", default=None)

    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
