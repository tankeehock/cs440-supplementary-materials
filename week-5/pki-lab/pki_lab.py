# /// script
# requires-python = ">=3.10"
# dependencies = ["cryptography>=43"]
# ///
"""
pki_lab.py  --  A self-contained Public Key Infrastructure lab. Python only.

You will build a three-tier CA hierarchy (root -> intermediate -> leaf), run
an HTTPS server on it, then act as the client and validate the server's
certificate chain step by step -- the way a browser does. After the healthy
case works, you sabotage the chain in eleven different ways and, for each,
work out WHICH validation step catches it.

Commands
  uv run pki_lab.py init                    build root + intermediate CA
  uv run pki_lab.py serve  <variant>        HTTPS server on :8443 (blocks)
  uv run pki_lab.py verify [--trust FILE]   validate localhost:8443 step by step
  uv run pki_lab.py run    <variant>        serve + verify in one process
  uv run pki_lab.py run    --all            scoreboard of every variant
  uv run pki_lab.py variants                list the sabotage variants

-------------------------------------------------------------------------------
HOW THIS FILE IS ORGANISED   (search an ALL-CAPS tag to jump straight to it)
-------------------------------------------------------------------------------
The file is laid out in README activity order. Code used by several activities
is grouped under "SHARED" banners. Each activity maps to a README section of
the same name -- so `grep -n "ACTIVITY 2" pki_lab.py` lands on the code behind
README activity 2.

  SHARED: OUTPUT HELPERS       pretty-printing only -- skip on a first read
  SHARED: CERTIFICATE TOOLKIT  make_cert() -- the one certificate builder
  ACTIVITY 1  Build the CA hierarchy       `init`      -> cmd_init()
  ACTIVITY 2  The healthy case             `run good`  -> cmd_verify(), STEP 1..7
  ACTIVITY 3  Trust is the client's ...    same cmd_verify() -- the `anchors` logic
  ACTIVITY 4  Break it                     `run <var>` -> build_variant(), VARIANT:
  SHARED: HTTPS SERVER         `serve` -> cmd_serve()   (serves activities 2-4)
  SHARED: RUN / SCOREBOARD     `run`   -> cmd_run()      glue: serve + verify
  SHARED: CLI                  main()                    argument parsing

Search tags:
  ACTIVITY 1..4   -- the code for that README activity
  STEP 1..7       -- the seven checks, inside cmd_verify (ACTIVITY 2)
  VARIANT: <name> -- how each sabotage is built, inside build_variant (ACTIVITY 4)

The seven checks a browser performs (search "STEP 1" ... "STEP 7"):
  STEP 1  hostname matches the SAN        STEP 5  signatures verify
  STEP 2  every cert is inside its dates  STEP 6  leaf is allowed to be a server
  STEP 3  chain builds to a trust anchor  STEP 7  leaf key is strong enough
  STEP 4  every issuer is really a CA

Author: Kee Hock (CS440 AY26T1 supplementary material)
"""

import argparse
import datetime as dt
import http.server
import ipaddress
import os
import socket
import ssl
import sys
import textwrap
import threading
from pathlib import Path

# All the X.509 machinery comes from one library, `cryptography`.
#   x509            -- read/build certificates
#   hashes, serialization, ec/rsa/padding -- keys, signing, PEM/DER encoding
#   *OID            -- the numeric identifiers for name fields and extensions
#   PolicyBuilder, Store -- the library's own "reference" chain verifier (ACTIVITY 2)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID
from cryptography.x509.verification import PolicyBuilder, Store

PKI = Path("pki")                                # everything is written under ./pki/
HOST, PORT = "localhost", 8443                   # the name the leaf is issued for
WIDTH = 78                                       # console wrap width for the printers
NOW = lambda: dt.datetime.now(dt.timezone.utc)   # "now", in UTC   # noqa: E731


# =============================================================================
# SHARED: OUTPUT HELPERS
# Pure presentation: they format the console transcript so it reads top to
# bottom. None of this affects certificate logic; skip it on a first read.
# =============================================================================
def header(title: str) -> None:
    """Print a full-width banner -- one per command or major stage."""
    print()
    print("=" * WIDTH)
    print(f" {title}")
    print("=" * WIDTH)


def datablock(label: str, value, indent: int = 2) -> None:
    """Print a `label : value` line, wrapping long values under the label."""
    pad, col = " " * indent, 22
    lines = textwrap.wrap(str(value), width=WIDTH - col - indent) or [""]
    print(f"{pad}{label:<{col - 2}}: {lines[0]}")
    for line in lines[1:]:
        print(f"{pad}{'':<{col - 2}}  {line}")


def step(n: int, title: str, ok: bool | None, detail: str) -> bool:
    """
    Print one validation step's result and return it as a bool.

    `ok` is True (PASS), False (FAIL) or None (SKIP). This is the line you read
    in activity 4 to see which of the seven checks caught a given sabotage.
    """
    mark = {True: "PASS", False: "FAIL", None: "SKIP"}[ok]
    print(f"  [{mark}] step {n}: {title}")
    for line in textwrap.wrap(detail, width=WIDTH - 10):
        print(f"           {line}")
    return bool(ok)


# =============================================================================
# SHARED: CERTIFICATE TOOLKIT
# The small set of helpers used to build, save and load certificates and keys.
# make_cert() is the important one: every certificate in the lab -- root,
# intermediate, leaf, and every sabotaged leaf -- is produced by this one call.
# Used by ACTIVITY 1 (build the CA) and ACTIVITY 4 (build each sabotaged leaf).
# =============================================================================
def name(cn: str, org: str = "CS440 Lab") -> x509.Name:
    """Build an X.509 distinguished name with an Organisation + Common Name."""
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def write_pem(path: Path, obj) -> None:
    """
    Write a key or certificate to `path` in PEM (Base64) format.

    A private key is serialised with its secret material (PKCS#8, unencrypted --
    fine for a lab, never do this in production); anything else is treated as a
    public certificate. This is why `.key` files are secret and `.pem` are not.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if hasattr(obj, "private_bytes"):
        data = obj.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())
    else:
        data = obj.public_bytes(serialization.Encoding.PEM)
    path.write_bytes(data)


def read_certs(path: Path) -> list[x509.Certificate]:
    """Load every certificate in a PEM file (a chain file holds several)."""
    return x509.load_pem_x509_certificates(path.read_bytes())


def read_key(path: Path):
    """Load a private key from a PEM file (no passphrase in this lab)."""
    return serialization.load_pem_private_key(path.read_bytes(), None)


def make_cert(subject: x509.Name, pub, issuer_cert: x509.Certificate | None,
              issuer_key, *, ca: bool, days: int = 365, start_offset_days: int = -1,
              san: list[str] | None = None, eku=(ExtendedKeyUsageOID.SERVER_AUTH,),
              key_usage: x509.KeyUsage | None = None,
              serial: int | None = None) -> x509.Certificate:
    """
    One builder for every certificate in the lab, CA or leaf.

    Arguments worth understanding, because the sabotage variants work by
    tweaking exactly these:
      subject / pub    -- the name being certified and the public key bound to it
      issuer_cert/_key -- who signs it; pass issuer_cert=None to self-sign (a root)
      ca               -- BasicConstraints CA flag: True = may sign other certs
      days             -- lifetime; combine with start_offset_days for time attacks
      start_offset_days-- notBefore relative to now (-1 = valid since yesterday)
      san              -- Subject Alternative Names (the modern "who is this for")
      eku              -- Extended Key Usage (serverAuth = "may be a TLS server")

    The signature at the end is what binds all of the above together: change any
    byte afterwards and the signature no longer verifies (see STEP 5).
    """
    # A root certificate is self-signed: it is its own issuer.
    issuer_name = issuer_cert.subject if issuer_cert else subject
    issuer_pub = issuer_cert.public_key() if issuer_cert else pub
    start = NOW() + dt.timedelta(days=start_offset_days)
    b = (x509.CertificateBuilder()
         .subject_name(subject).issuer_name(issuer_name).public_key(pub)
         .serial_number(serial or x509.random_serial_number())
         .not_valid_before(start).not_valid_after(start + dt.timedelta(days=days))
         # SKI/AKI are the "fingerprints" that let a verifier match a child to its
         # parent quickly during path building (STEP 3).
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_pub), critical=False)
         # BasicConstraints.ca is THE bit that says "this may sign other certs".
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    # KeyUsage says what the key is ALLOWED to do. x509.KeyUsage takes nine
    # positional booleans, in this fixed order (this is the bit that trips
    # everyone reading the line below):
    #
    #   1 digital_signature  2 content_commitment  3 key_encipherment
    #   4 data_encipherment  5 key_agreement       6 key_cert_sign
    #   7 crl_sign           8 encipher_only        9 decipher_only
    #
    # A CA must be allowed to sign certificates and CRLs -> positions 6 & 7.
    # A leaf just needs to sign during the TLS handshake     -> position 1.
    if key_usage is None:
        key_usage = (
            #             1      2      3      4      5     6(cert) 7(crl) 8      9
            x509.KeyUsage(False, False, False, False, False, True,  True,  False, False) if ca
            #             1(sig) 2      3      4      5      6      7      8      9
            else x509.KeyUsage(True, False, False, False, False, False, False, False, False))
    b = b.add_extension(key_usage, critical=True)
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in san]), critical=False)
    # Only leaves carry an EKU here; CAs are left unrestricted.
    if not ca and eku:
        b = b.add_extension(x509.ExtendedKeyUsage(list(eku)), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


# #############################################################################
# ACTIVITY 1 -- "Build the CA hierarchy"          (command: init)
# Build the two-tier CA and save it under pki/. The leaf is NOT made here; each
# leaf is minted per-run by build_variant() in ACTIVITY 4.
# #############################################################################
def cmd_init(_args) -> int:
    """Create the root and intermediate CAs and write them to pki/."""
    header("INIT: BUILD THE CA HIERARCHY")
    # Root: self-signed (issuer_cert=None), long-lived, the ultimate trust anchor.
    root_key = ec.generate_private_key(ec.SECP384R1())
    root = make_cert(name("CS440 Lab Root CA"), root_key.public_key(), None, root_key,
                     ca=True, days=3650)
    # Intermediate: signed BY the root, still a CA, does the day-to-day issuing.
    int_key = ec.generate_private_key(ec.SECP256R1())
    inter = make_cert(name("CS440 Lab Intermediate CA"), int_key.public_key(), root, root_key,
                      ca=True, days=1825)
    # Four files: two secret .key, two public .pem.
    for fn, obj in [("root.key", root_key), ("root.pem", root),
                    ("intermediate.key", int_key), ("intermediate.pem", inter)]:
        write_pem(PKI / fn, obj)

    datablock("Root CA", root.subject.rfc4514_string())
    datablock("  key", "P-384, self-signed, valid 10 years")
    datablock("  file", "pki/root.pem  (+ root.key -- keep offline in real life)")
    datablock("Intermediate CA", inter.subject.rfc4514_string())
    datablock("  key", "P-256, signed by root, valid 5 years")
    datablock("  file", "pki/intermediate.pem  (+ intermediate.key)")
    return 0


# #############################################################################
# ACTIVITY 2 -- "The healthy case"   &   ACTIVITY 3 -- "Trust is the client's
# decision"                                        (command: verify)
# cmd_verify() connects as the client and runs, by hand, the same seven checks a
# browser runs before it shows a padlock -- search "STEP 1" .. "STEP 7".
#   * ACTIVITY 2 is those seven checks against a good chain.
#   * ACTIVITY 3 is the trust-store question: same certificate, different
#     `anchors` -> different verdict. Search "ACTIVITY 3" inside cmd_verify.
# The five helpers below (fetch_chain / cn_of / verify_signature / ext /
# ski_matches) are the tools those checks lean on.
# #############################################################################
def fetch_chain() -> tuple[list[x509.Certificate], dict]:
    """
    Connect WITHOUT verification and pull the certificates the server sent.

    We deliberately turn verification off here: the whole point is to inspect
    whatever the server presents, including deliberately broken chains, and
    judge it ourselves. Python 3.13+ exposes the raw chain; older versions only
    expose the leaf, so we fall back to the file the server wrote (same bytes).
    """
    # Build a client context that verifies NOTHING: no hostname check, no
    # certificate check. We want the raw certificates, broken or not, to judge
    # ourselves -- so we must not let the handshake reject them first.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")          # accept the weak-key variant's cipher too
    with socket.create_connection((HOST, PORT), timeout=5) as raw, \
            ctx.wrap_socket(raw, server_hostname=HOST) as tls:
        meta = {"tls": tls.version(), "cipher": tls.cipher()[0]}
        if hasattr(tls, "get_unverified_chain"):
            # Python 3.13+ hands us every certificate the server sent, in DER.
            # .get_unverified_chain() may return raw bytes or cert objects
            # depending on the build, so normalise each to DER before parsing.
            # (ssl.ENCODING_DER is 2; getattr guards older builds that lack it.)
            chain = [x509.load_der_x509_certificate(
                         c if isinstance(c, bytes)
                         else c.public_bytes(getattr(ssl, "ENCODING_DER", 2)))
                     for c in tls.get_unverified_chain()]
            meta["source"] = "TLS handshake (ssl.get_unverified_chain)"
        else:
            # Python < 3.13 exposes only the leaf. The issuers the server sent
            # are identical to the chain.pem it just wrote, so read those back
            # and assert the leaf matches, guaranteeing we judge what was served.
            leaf = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
            chain = read_certs(PKI / "served" / "chain.pem")
            assert chain[0] == leaf, "served/chain.pem does not match what the server sent"
            meta["source"] = "leaf from handshake; issuers from pki/served/chain.pem (Python < 3.13)"
    return chain, meta


def cn_of(c: x509.Certificate) -> str:
    """The certificate's Common Name, for display -- falls back to the full DN."""
    try:
        return c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        return c.subject.rfc4514_string()


def verify_signature(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """
    Does `issuer`'s PUBLIC key verify the signature on `cert`? (STEP 5.)

    Note only the issuer's public key is needed -- never a private key. The
    algorithm (RSA vs EC) is chosen from the issuer's key type. Any failure --
    wrong key, tampered bytes -- comes back as False rather than an exception.
    """
    pub = issuer.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(cert.signature, cert.tbs_certificate_bytes,
                       padding.PKCS1v15(), cert.signature_hash_algorithm)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(cert.signature, cert.tbs_certificate_bytes,
                       ec.ECDSA(cert.signature_hash_algorithm))
        else:
            pub.verify(cert.signature, cert.tbs_certificate_bytes)
        return True
    except Exception:
        return False


def ext(cert: x509.Certificate, oid):
    """Return an extension's value by OID, or None if the cert lacks it."""
    try:
        return cert.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None


def ski_matches(candidate: x509.Certificate, aki) -> bool:
    """
    Does this candidate issuer match the child's Authority Key Identifier?

    AKI/SKI is a hint that speeds up path building, not a requirement -- RFC
    5280 lets a chain be valid without it. So a candidate that carries no SKI
    is not disqualified; it just has to be matched on subject name alone.
    """
    if aki is None or aki.key_identifier is None:
        return True
    ski = ext(candidate, ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    return ski is None or ski.digest == aki.key_identifier


def cmd_verify(args) -> int:
    """
    Run the seven checks against localhost:8443 and print three verdicts.

    The trust store comes from --trust (a PEM of roots you have decided to
    trust); `anchors` below is that list, and it is the whole of README
    activity 3 -- change it and the verdict changes though the certificate
    does not. After the manual steps we cross-check against two independent
    verifiers (the `cryptography` library and OpenSSL) to see where real
    implementations draw the line differently.
    """
    # ACTIVITY 3: `anchors` IS the trust store. Everything about the certificate
    # is fixed; the only thing --trust changes is this list, and that alone can
    # flip the verdict (see STEP 3, where the chain must reach one of these).
    trust_path = Path(args.trust) if args.trust else None
    anchors = read_certs(trust_path) if trust_path else []
    chain, meta = fetch_chain()
    leaf, sent_issuers = chain[0], chain[1:]
    now = NOW()
    results: list[bool] = []

    header(f"VERIFY: https://{HOST}:{PORT}  (trust store: {trust_path or 'EMPTY'})")
    datablock("TLS", f"{meta['tls']}, {meta['cipher']}")
    datablock("Chain source", meta["source"])
    datablock("Certs received", f"{len(chain)}: " + " <- ".join(cn_of(c) for c in chain))
    datablock("Trust anchors", ", ".join(cn_of(a) for a in anchors) or "none")
    print()

    # ---- STEP 1 of 7: HOSTNAME
    # Does the leaf's SAN list the exact name we connected to? Modern verifiers
    # ignore the legacy Common Name entirely.  Trips on: wrong-name, cn-only.
    san = ext(leaf, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    names = san.get_values_for_type(x509.DNSName) if san else []
    ok = HOST in names
    results.append(step(1, "hostname matches a Subject Alternative Name",
                        ok, f"SAN dNSNames = {names or 'NONE'}; looking for '{HOST}'. "
                            f"Subject CN is '{cn_of(leaf)}' but browsers ignore CN entirely."))

    # ---- STEP 2 of 7: VALIDITY WINDOW
    # Is EVERY certificate in the chain currently within notBefore..notAfter?
    # Trips on: expired, not-yet-valid.
    bad = [(cn_of(c), c.not_valid_before_utc, c.not_valid_after_utc) for c in chain
           if not (c.not_valid_before_utc <= now <= c.not_valid_after_utc)]
    results.append(step(2, "every certificate is inside its validity window", not bad,
                        "all within window" if not bad else
                        "; ".join(f"{n}: {a:%Y-%m-%d} to {b:%Y-%m-%d}" for n, a, b in bad)
                        + f" (now {now:%Y-%m-%d})"))

    # ---- STEP 3 of 7: PATH BUILDING
    # Walk leaf -> issuer -> issuer ... until we reach a cert in the trust store.
    # `pool` is what we may link through: certs the server sent, plus the anchors.
    # Trips on: no-intermediate, self-signed, untrusted-ca.
    pool = sent_issuers + anchors
    path = [leaf]
    detail = []
    while True:
        cur = path[-1]
        if any(cur == a for a in anchors):        # reached a trusted root: done
            detail.append(f"{cn_of(cur)} is a trust anchor")
            break
        if cur.subject == cur.issuer:             # self-signed and not trusted: dead end
            detail.append(f"{cn_of(cur)} is self-signed and NOT in the trust store")
            break
        aki = ext(cur, ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        # find a parent whose subject == our issuer (and whose SKI matches, if present)
        parent = next((p for p in pool
                       if p.subject == cur.issuer and ski_matches(p, aki)), None)
        if parent is None or parent in path:      # no parent found, or a loop: dead end
            detail.append(f"no certificate found for issuer '{cur.issuer.rfc4514_string()}' "
                          f"(matched by name + AKI/SKI)")
            break
        path.append(parent)
    reached_anchor = bool(anchors) and path[-1] in anchors
    results.append(step(3, "chain builds from leaf to a trusted anchor", reached_anchor,
                        " -> ".join(cn_of(c) for c in path) + ".  " + "; ".join(detail)))

    # ---- STEP 4 of 7: EVERY ISSUER IS REALLY A CA
    # For each parent in the path, BasicConstraints.ca must be True and (if
    # present) KeyUsage must allow keyCertSign. This is what stops any ordinary
    # leaf from signing certificates for other sites.  Trips on: rogue-leaf.
    link_ok, link_detail = True, []
    for child, parent in zip(path, path[1:]):
        bc = ext(parent, ExtensionOID.BASIC_CONSTRAINTS)
        ku = ext(parent, ExtensionOID.KEY_USAGE)
        is_ca = bool(bc and bc.ca) and (ku is None or ku.key_cert_sign)
        link_ok &= is_ca
        link_detail.append(f"{cn_of(parent)}: CA={bc.ca if bc else 'absent'}, "
                           f"keyCertSign={ku.key_cert_sign if ku else 'absent'}")
    results.append(step(4, "every issuer in the path is marked CA:TRUE + keyCertSign",
                        link_ok if len(path) > 1 else False, "; ".join(link_detail) or "no issuer links to check"))

    # ---- STEP 5 of 7: SIGNATURES
    # Each link's signature must verify under its parent's public key. A single
    # leaf on its own can never satisfy this (a self-signature proves nothing).
    # Trips on: tampered (and, structurally, no-intermediate / self-signed).
    sig_ok, sig_detail = True, []
    for child, parent in zip(path, path[1:]):
        v = verify_signature(child, parent)
        sig_ok &= v
        sig_detail.append(f"{cn_of(child)} signed by {cn_of(parent)}: {'valid' if v else 'INVALID'}")
    if len(path) == 1:
        v = verify_signature(leaf, leaf) if leaf.subject == leaf.issuer else False
        sig_ok = False
        sig_detail.append(f"only the leaf; self-signature {'valid' if v else 'n/a'} but proves nothing")
    results.append(step(5, "every signature verifies with the parent's public key", sig_ok,
                        "; ".join(sig_detail)))

    # ---- STEP 6 of 7: LEAF MAY ACT AS A TLS SERVER
    # The leaf must be allowed to be a server: EKU serverAuth (or none),
    # KeyUsage digitalSignature, and it must NOT itself be a CA.  Trips on: bad-eku.
    eku = ext(leaf, ExtensionOID.EXTENDED_KEY_USAGE)
    ku = ext(leaf, ExtensionOID.KEY_USAGE)
    bc = ext(leaf, ExtensionOID.BASIC_CONSTRAINTS)
    ok = (eku is None or ExtendedKeyUsageOID.SERVER_AUTH in eku) and (ku is None or ku.digital_signature) \
        and not (bc and bc.ca)
    results.append(step(6, "leaf is allowed to act as a TLS server", ok,
                        f"EKU = {[e._name for e in eku] if eku else 'absent (any)'}; "
                        f"KU digitalSignature = {ku.digital_signature if ku else 'absent'}; "
                        f"CA = {bc.ca if bc else 'absent'}"))

    # ---- STEP 7 of 7: KEY STRENGTH
    # A policy check, not a structural one: RSA must be >= 2048 bits, EC >= 256.
    # Trips on: weak-key. (Note the library verifier does NOT enforce this.)
    pub = leaf.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        ok, kd = pub.key_size >= 2048, f"RSA-{pub.key_size} (minimum 2048)"
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        ok, kd = pub.key_size >= 256, f"EC {pub.curve.name} ({pub.key_size}-bit, minimum 256)"
    else:
        ok, kd = True, type(pub).__name__
    results.append(step(7, "leaf key meets minimum strength", ok, kd))

    # ---- VERDICT 1: our manual steps ----------------------------------------
    print()
    failed = [i + 1 for i, r in enumerate(results) if not r]
    verdict = "ACCEPT" if not failed else f"REJECT  (failed step{'s' if len(failed) > 1 else ''} {failed})"
    datablock("Manual verdict", verdict)

    # ---- VERDICT 2: the cryptography library's own verifier -----------------
    # An independent implementation. Where it disagrees with our steps is the
    # interesting part (e.g. it does not enforce key size -> weak-key).
    try:
        store = Store(anchors) if anchors else None
        if store is None:
            raise ValueError("empty trust store")
        verifier = (PolicyBuilder().store(store).time(now)
                    .build_server_verifier(x509.DNSName(HOST)))
        verifier.verify(leaf, sent_issuers)
        ref = "ACCEPT"
    except Exception as e:
        ref = f"REJECT  ({str(e).splitlines()[0][:70]})"
    datablock("Library verdict", ref)

    # ---- VERDICT 3: OpenSSL, via Python's ssl module ------------------------
    # NOT the `openssl` command line -- Python's `ssl` module is a binding to the
    # OpenSSL library (libssl). We make a REAL TLS handshake to localhost:8443
    # and let libssl verify the certificate; the error strings below come
    # straight from OpenSSL. This is what many real clients actually use.
    ctx = ssl.create_default_context(cafile=str(trust_path) if trust_path else None)
    try:
        with socket.create_connection((HOST, PORT), timeout=5) as raw, \
                ctx.wrap_socket(raw, server_hostname=HOST):
            ssl_verdict = "ACCEPT"
    except ssl.SSLCertVerificationError as e:
        ssl_verdict = f"REJECT  ({e.verify_message})"
    except ssl.SSLError as e:
        ssl_verdict = f"REJECT  ({e.reason})"
    datablock("OpenSSL (Python ssl)", ssl_verdict)

    # Exit code mirrors the manual verdict: 0 = accepted, 1 = rejected.
    return 0 if not failed else 1


# #############################################################################
# ACTIVITY 4 -- "Break it"                         (command: run <variant>)
# VARIANTS is the catalogue; build_variant() mints the leaf + chain for one of
# them. Each branch below is tagged "VARIANT: <name>" with the STEP (see
# ACTIVITY 2) it should trip -- search a variant name to jump to how it is built.
# #############################################################################
VARIANTS: dict[str, str] = {
    "good":            "correct chain -- everything should pass",
    "expired":         "leaf notAfter is in the past",
    "not-yet-valid":   "leaf notBefore is next week",
    "wrong-name":      "leaf SAN says lab.example, not localhost",
    "cn-only":         "leaf has CN=localhost but NO Subject Alternative Name",
    "no-intermediate": "server sends only the leaf, not the intermediate",
    "rogue-leaf":      "leaf is signed by another LEAF (CA:FALSE), not by a CA",
    "self-signed":     "leaf signed itself; no CA involved at all",
    "untrusted-ca":    "proper chain, but under a root you never trusted",
    "bad-eku":         "leaf EKU is clientAuth only -- not allowed to be a server",
    "weak-key":        "leaf key is RSA-1024",
    "tampered":        "one byte of the leaf was altered AFTER signing",
}


def build_variant(variant: str) -> tuple[Path, Path, Path]:
    """
    Create pki/served/{leaf.pem, leaf.key, chain.pem} for the variant and
    return their paths. chain.pem is exactly what the server will send.

    Read the branches as: start from a correct leaf, then apply the single
    sabotage this variant is named for. The comment on each branch names the
    STEP (see ACTIVITY 2) that should catch it.
    """
    # The healthy starting point every variant mutates: a leaf for `localhost`,
    # signed by the intermediate, 90-day lifetime, chain = [leaf, intermediate].
    inter = read_certs(PKI / "intermediate.pem")[0]
    int_key = read_key(PKI / "intermediate.key")
    served = PKI / "served"
    kw: dict = dict(ca=False, days=90, san=[HOST])
    key = ec.generate_private_key(ec.SECP256R1())
    issuer_cert, issuer_key = inter, int_key
    chain_extra: list[x509.Certificate] = [inter]

    if variant == "expired":
        # VARIANT: expired  -> trips STEP 2 (validity). Issued 100 days ago,
        # 90-day life, so notAfter is already in the past.
        kw.update(start_offset_days=-100, days=90)
    elif variant == "not-yet-valid":
        # VARIANT: not-yet-valid  -> trips STEP 2 (validity). notBefore is a
        # week from now: the other edge of the same window.
        kw.update(start_offset_days=7)
    elif variant == "wrong-name":
        # VARIANT: wrong-name  -> trips STEP 1 (hostname). Valid cert, wrong SAN.
        kw.update(san=["lab.example"])
    elif variant == "cn-only":
        # VARIANT: cn-only  -> trips STEP 1 (hostname). Name is only in the
        # legacy CN, with no SAN at all. Watch the three verifiers disagree.
        kw.update(san=None)
    elif variant == "no-intermediate":
        # VARIANT: no-intermediate  -> trips STEP 3/4/5. Server omits the
        # intermediate, so the chain to the root cannot be built.
        chain_extra = []
    elif variant == "rogue-leaf":
        # VARIANT: rogue-leaf  -> trips STEP 4 (issuer must be a CA).
        # A legitimate leaf, then a second leaf signed by the first one's key.
        # Every signature is valid, but the middle cert is CA:FALSE.
        good_key = ec.generate_private_key(ec.SECP256R1())
        good_leaf = make_cert(name("good-server.lab"), good_key.public_key(), inter, int_key,
                              ca=False, days=90, san=["good-server.lab"])
        issuer_cert, issuer_key = good_leaf, good_key
        chain_extra = [good_leaf, inter]
    elif variant == "self-signed":
        # VARIANT: self-signed  -> trips STEP 3/4/5. Leaf is its own issuer;
        # no CA is involved and nothing chains to the trust store.
        issuer_cert, issuer_key = None, key
        chain_extra = []
    elif variant == "untrusted-ca":
        # VARIANT: untrusted-ca  -> trips STEP 3 (trust anchor). A perfectly
        # formed chain under a root that is simply not in your trust store.
        evil_key = ec.generate_private_key(ec.SECP256R1())
        evil_root = make_cert(name("Totally Legit Root CA", "Evil Corp"), evil_key.public_key(),
                              None, evil_key, ca=True, days=3650)
        issuer_cert, issuer_key = evil_root, evil_key
        chain_extra = [evil_root]
    elif variant == "bad-eku":
        # VARIANT: bad-eku  -> trips STEP 6 (leaf usage). Marked clientAuth
        # only, so it is not permitted to act as a TLS server.
        kw.update(eku=(ExtendedKeyUsageOID.CLIENT_AUTH,))
    elif variant == "weak-key":
        # VARIANT: weak-key  -> trips STEP 7 (key strength). RSA-1024 is below
        # the modern minimum; the maths is fine, the key is just too small.
        key = rsa.generate_private_key(65537, 1024)
    elif variant not in ("good", "tampered"):
        raise SystemExit(f"unknown variant {variant!r}; see: pki_lab.py variants")

    # Mint the leaf with whatever mutations the branch above set up.
    leaf = make_cert(name(HOST), key.public_key(), issuer_cert, issuer_key, **kw)

    if variant == "tampered":
        # VARIANT: tampered  -> trips STEP 5 (signatures). Every other variant
        # changes the certificate BEFORE signing; this one changes it AFTER, to
        # show what a signature actually protects. Steps:
        #   1. dump the finished, signed certificate to raw DER bytes;
        #   2. find the ASCII 'localhost' inside it (the leaf's subject name);
        #   3. flip one bit of its 2nd byte ('o' 0x6F ^ 0x01 = 'n' 0x6E),
        #      turning 'localhost' into 'lncalhost';
        #   4. reload the now-mangled bytes as a certificate.
        # The signature was computed over the original bytes, so it no longer
        # matches -- STEP 5 catches it, while everything else still looks fine.
        der = bytearray(leaf.public_bytes(serialization.Encoding.DER))
        i = der.find(b"localhost")
        der[i + 1] ^= 0x01
        leaf = x509.load_der_x509_certificate(bytes(der))

    # Write what the server will present: leaf first, then any issuers.
    write_pem(served / "leaf.pem", leaf)
    write_pem(served / "leaf.key", key)
    (served / "chain.pem").write_bytes(
        b"".join(c.public_bytes(serialization.Encoding.PEM) for c in [leaf, *chain_extra]))
    (served / "VARIANT").write_text(variant)
    return served / "leaf.pem", served / "leaf.key", served / "chain.pem"


# =============================================================================
# SHARED: HTTPS SERVER   (`uv run pki_lab.py serve <variant>`)
# A minimal HTTPS server that presents pki/served/chain.pem. It exists only to
# give the verify step (ACTIVITY 2/3) and the sabotage runs (ACTIVITY 4)
# something real to connect to over TLS.
# =============================================================================
class Quiet(http.server.SimpleHTTPRequestHandler):
    """Answers any GET with one line naming the variant; logs nothing."""
    def do_GET(self):
        body = f"hello from the {Path('pki/served/VARIANT').read_text()} server\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class QuietServer(http.server.HTTPServer):
    """HTTPServer that swallows handshake errors -- clients abort them on purpose here."""
    def handle_error(self, request, client_address):
        pass   # clients that abort the handshake are expected in this lab


def start_server(variant: str) -> http.server.HTTPServer:
    """Build the variant's chain, then wrap a TCP socket in TLS serving it."""
    _, key_path, chain_path = build_variant(variant)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")   # let the weak-key variant handshake at all
    ctx.load_cert_chain(str(chain_path), str(key_path))
    srv = QuietServer(("127.0.0.1", PORT), Quiet)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


def cmd_serve(args) -> int:
    """Serve one variant and block until Ctrl-C (the two-terminal workflow)."""
    srv = start_server(args.variant)
    header(f"SERVE: variant '{args.variant}' on https://{HOST}:{PORT}")
    datablock("Sabotage", VARIANTS[args.variant])
    datablock("Serving", "pki/served/chain.pem (leaf first, then issuers)")
    datablock("Next", "in another terminal:  uv run pki_lab.py verify --trust pki/root.pem")
    print("\n  Ctrl-C to stop.\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


# =============================================================================
# SHARED: RUN / SCOREBOARD   (`uv run pki_lab.py run <variant> | --all`)
# Convenience glue so one process both serves a variant and verifies it -- this
# is what ACTIVITY 2 and ACTIVITY 4 actually invoke. The server runs on a
# background thread; the main thread is the client.
# =============================================================================
def run_one(variant: str, trust: str | None, quiet: bool) -> int:
    """Serve one variant on a daemon thread, verify it, then shut down."""
    srv = start_server(variant)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        ns = argparse.Namespace(trust=trust, quiet=quiet)
        if not quiet:
            header(f"RUN: variant '{variant}' -- {VARIANTS[variant]}")
        return cmd_verify(ns)
    finally:
        srv.shutdown()
        srv.server_close()


def cmd_run(args) -> int:
    """Run one variant verbosely, or every variant as a one-line scoreboard."""
    if args.all:
        # --all: run each variant quietly, capture its output, and pull out the
        # failed step numbers + OpenSSL's verdict to build a compact table.
        header("SCOREBOARD: every variant against pki/root.pem")
        import contextlib, io
        rows = []
        for v in VARIANTS:
            # Run the full verbose verify for this variant, but capture its
            # printout into `buf` instead of showing it, then scrape two facts
            # out of the captured text:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                run_one(v, args.trust, quiet=True)
            out = buf.getvalue()
            # (1) which steps failed -- every "  [FAIL] step N: ..." line, N pulled
            #     out from between "step " and the ":".
            failed = [ln.split("step ")[1].split(":")[0]
                      for ln in out.splitlines() if ln.strip().startswith("[FAIL]")]
            # (2) OpenSSL's one-line verdict -- the text after the ":" on the
            #     "OpenSSL (Python ssl): ..." line ("?" if somehow absent).
            ossl = next((ln.split(":", 1)[1].strip()
                         for ln in out.splitlines() if ln.strip().startswith("OpenSSL")), "?")
            rows.append((v, ", ".join(failed) or "-", ossl))
        print(f"  {'variant':<16} {'failed steps':<14} openssl")
        print(f"  {'-------':<16} {'------------':<14} -------")
        for v, f, o in rows:
            print(f"  {v:<16} {f:<14} {o[:44]}")
        return 0
    return run_one(args.variant, args.trust, quiet=False)


def cmd_variants(_args) -> int:
    """Print the catalogue of sabotage variants and what each one does."""
    header("VARIANTS")
    for k, v in VARIANTS.items():
        datablock(k, v)
    return 0


# =============================================================================
# SHARED: CLI
# Maps each subcommand to its cmd_* function and guards commands that need a CA.
# =============================================================================
def main() -> int:
    """Parse the subcommand and dispatch to the matching cmd_* function."""
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init").set_defaults(fn=cmd_init)
    s = sub.add_parser("serve"); s.add_argument("variant", choices=VARIANTS); s.set_defaults(fn=cmd_serve)
    s = sub.add_parser("verify"); s.add_argument("--trust", help="PEM file of trusted roots")
    s.add_argument("--quiet", action="store_true"); s.set_defaults(fn=cmd_verify)
    s = sub.add_parser("run"); s.add_argument("variant", nargs="?", choices=VARIANTS)
    s.add_argument("--all", action="store_true"); s.add_argument("--trust", default="pki/root.pem")
    s.set_defaults(fn=cmd_run)
    sub.add_parser("variants").set_defaults(fn=cmd_variants)
    args = ap.parse_args()
    if args.cmd == "run" and not args.all and not args.variant:
        ap.error("run needs a variant or --all")
    # `variants` is a static listing -- it must work before any CA exists,
    # since the walkthrough uses it as the very first smoke test.
    if args.cmd not in ("init", "variants") and not (PKI / "root.pem").exists():
        print("No CA yet -- run:  uv run pki_lab.py init")
        return 1
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
