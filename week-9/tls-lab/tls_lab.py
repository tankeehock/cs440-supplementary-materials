# /// script
# requires-python = ">=3.10"
# dependencies = ["cryptography>=43"]
# ///
"""
tls_lab.py  --  A TLS 1.3 handshake, written out by hand. Python only.

Your browser does a TLS handshake hundreds of times a day and shows you a
padlock. This lab opens the padlock up. You will run a TLS 1.3 client that is
a few hundred readable lines of Python -- every byte of the ClientHello built by hand,
every secret of the key schedule printed -- and watch it complete a real
handshake with OpenSSL (the server is Python's own `ssl` module). Then you
decrypt a captured OpenSSL-to-OpenSSL session with nothing but a key log file,
and finally put an attacker on the wire seven different ways and see which
check stops each one.

Commands
  uv run tls_lab.py init                      build the lab CA + server cert
  uv run tls_lab.py libraries                 which library does which crypto
  uv run tls_lab.py handshake                 hand-written client vs OpenSSL
  uv run tls_lab.py handshake <variant>       ... with an attacker on the wire
  uv run tls_lab.py handshake --all           scoreboard of every variant
  uv run tls_lab.py variants                  list the attack variants
  uv run tls_lab.py keylog                    decrypt OpenSSL<->OpenSSL traffic

Nothing touches the network: client and server run in one process and hand
each other bytes through memory buffers (ssl.MemoryBIO), so every byte that
"crosses the wire" passes through code you can read and tamper with.

-------------------------------------------------------------------------------
HOW THIS FILE IS ORGANISED   (search an ALL-CAPS tag to jump straight to it)
-------------------------------------------------------------------------------
  SHARED: OUTPUT HELPERS       pretty-printing only -- skip on a first read
  SHARED: WIRE FORMAT          bytes in, bytes out: records, handshake messages
  SHARED: KEY SCHEDULE         HKDF, the TLS 1.3 secret tree, Finished MACs
  SHARED: RECORD PROTECTION    AEAD encrypt/decrypt of one record
  SHARED: CERTIFICATES         the lab CA, the server cert, the attacker's CA
  ACTIVITY 1  Meet the libraries       `libraries`  -> cmd_libraries()
  ACTIVITY 2  The handshake by hand    `handshake`  -> run_client(), CHECK 1..5
  ACTIVITY 3  The key log              `keylog`     -> cmd_keylog()
  ACTIVITY 4  Attack the handshake     `handshake <variant>` -> VARIANT: <name>
  SHARED: PEERS                the OpenSSL server, the attacker's fake server
  SHARED: CLI                  main()

The five checks the client makes (search "CHECK 1" ... "CHECK 5"):
  CHECK 1  ServerHello picked something we offered   (version, suite, group)
  CHECK 2  every encrypted record decrypts           (AEAD tag)
  CHECK 3  certificate chains to a trusted root      (PKI -- week 5)
  CHECK 4  CertificateVerify signature is valid      (server holds the key)
  CHECK 5  server Finished MAC is correct            (transcript integrity)

Author: Kee Hock (CS440 AY26T1 supplementary material)
"""

import argparse
import contextlib
import datetime as dt
import hmac
import io
import os
import ssl
import sys
import tempfile
import textwrap
import time
from pathlib import Path

# Every primitive the hand-written client uses comes from `cryptography`
# (ACTIVITY 1 shows which C/Rust code actually runs underneath each one):
#   X25519            -- the ephemeral Diffie-Hellman key exchange
#   HKDFExpand, HMAC  -- the key schedule (HKDF-Extract is just HMAC)
#   AESGCM, ChaCha20Poly1305 -- the AEAD ciphers that protect every record
#   ec / padding      -- verifying the server's CertificateVerify signature
#   x509 + PolicyBuilder -- parsing and validating the certificate chain
import cryptography
from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import hmac as crypto_hmac
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

LAB = Path("tls")                                # everything is written under ./tls/
HOST = "localhost"                               # the name the server cert is issued for
WIDTH = 78
NOW = lambda: dt.datetime.now(dt.timezone.utc)   # noqa: E731


# =============================================================================
# SHARED: OUTPUT HELPERS
# Pure presentation. None of this affects the protocol; skip on a first read.
# =============================================================================
def header(title: str) -> None:
    print()
    print("=" * WIDTH)
    print(f" {title}")
    print("=" * WIDTH)


def sub(title: str) -> None:
    print()
    print(f"--- {title} " + "-" * max(0, WIDTH - len(title) - 5))


def explain(text: str) -> None:
    """A paragraph of commentary, wrapped and indented."""
    for para in textwrap.dedent(text).strip().split("\n\n"):
        for line in textwrap.wrap(" ".join(para.split()), width=WIDTH - 2):
            print(f"  {line}")
        print()


def datablock(label: str, value, indent: int = 2) -> None:
    pad, col = " " * indent, 26
    lines = textwrap.wrap(str(value), width=WIDTH - col - indent) or [""]
    print(f"{pad}{label:<{col - 2}}: {lines[0]}")
    for line in lines[1:]:
        print(f"{pad}{'':<{col - 2}}  {line}")


def hx(b: bytes, limit: int = 32) -> str:
    """Hex, shortened in the middle when long -- enough to recognise a value."""
    h = b.hex()
    return h if len(b) <= limit else f"{h[:24]}...{h[-8:]} ({len(b)} bytes)"


def arrow(direction: str, what: str, nbytes: int) -> None:
    side = {"c2s": "client ──▶ server", "s2c": "client ◀── server"}[direction]
    print(f"\n  [{side}]  {what}  ({nbytes} bytes on the wire)")


def check(n: int, title: str, ok: bool | None, detail: str) -> bool:
    """Print one of the five checks. ok is True (PASS), False (FAIL) or None (SKIP)."""
    mark = {True: "PASS", False: "FAIL", None: "SKIP"}[ok]
    print(f"  [{mark}] CHECK {n}: {title}")
    for line in textwrap.wrap(detail, width=WIDTH - 10):
        print(f"           {line}")
    return bool(ok)


# =============================================================================
# SHARED: WIRE FORMAT
# TLS is a binary protocol. Two layers matter here:
#
#   RECORD    type(1) | legacy_version(2) = 0x0303 | length(2) | body
#   HANDSHAKE msg_type(1) | length(3) | body       (carried inside records)
#
# Every variable-length field is prefixed by its length in 1, 2 or 3 bytes --
# that is the whole encoding. (Note the record version is 0x0303, "TLS 1.2",
# even in TLS 1.3: the real version is negotiated in an extension, because
# middleboxes broke when they saw an unfamiliar number. See CHECK 1.)
# =============================================================================
CT_CCS, CT_ALERT, CT_HANDSHAKE, CT_APPDATA = 20, 21, 22, 23
CONTENT_TYPES = {20: "change_cipher_spec", 21: "alert", 22: "handshake", 23: "application_data"}

HS_TYPES = {1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket", 8: "EncryptedExtensions",
            11: "Certificate", 13: "CertificateRequest", 15: "CertificateVerify", 20: "Finished"}

EXT_NAMES = {0: "server_name", 10: "supported_groups", 13: "signature_algorithms",
             16: "alpn", 22: "encrypt_then_mac", 23: "extended_master_secret",
             35: "session_ticket", 43: "supported_versions", 45: "psk_key_exchange_modes",
             49: "post_handshake_auth", 51: "key_share", 65281: "renegotiation_info"}

GROUPS = {0x001d: "x25519", 0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1",
          0x001e: "x448", 0x0100: "ffdhe2048", 0x11ec: "X25519MLKEM768 (post-quantum hybrid)"}

SIG_SCHEMES = {0x0403: "ecdsa_secp256r1_sha256", 0x0503: "ecdsa_secp384r1_sha384",
               0x0804: "rsa_pss_rsae_sha256", 0x0805: "rsa_pss_rsae_sha384",
               0x0807: "ed25519", 0x0401: "rsa_pkcs1_sha256"}

TLS13 = 0x0304

# A TLS 1.3 cipher suite names exactly two things: the AEAD that protects
# records, and the hash used by HKDF and the transcript. (Key exchange and
# signature are negotiated separately -- that is new in 1.3.)
#            code     name                            hash             AEAD               key bytes
SUITES = {0x1301: ("TLS_AES_128_GCM_SHA256",       hashes.SHA256, AESGCM,            16),
          0x1302: ("TLS_AES_256_GCM_SHA384",       hashes.SHA384, AESGCM,            32),
          0x1303: ("TLS_CHACHA20_POLY1305_SHA256", hashes.SHA256, ChaCha20Poly1305,  32)}


def u8(n: int) -> bytes: return n.to_bytes(1, "big")
def u16(n: int) -> bytes: return n.to_bytes(2, "big")
def u24(n: int) -> bytes: return n.to_bytes(3, "big")
def vec8(b: bytes) -> bytes: return u8(len(b)) + b
def vec16(b: bytes) -> bytes: return u16(len(b)) + b
def vec24(b: bytes) -> bytes: return u24(len(b)) + b


class Reader:
    """Pull fixed- and length-prefixed fields off the front of a byte string."""
    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("truncated message")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int: return self.take(1)[0]
    def u16(self) -> int: return int.from_bytes(self.take(2), "big")
    def u24(self) -> int: return int.from_bytes(self.take(3), "big")
    def vec8(self) -> bytes: return self.take(self.u8())
    def vec16(self) -> bytes: return self.take(self.u16())
    def vec24(self) -> bytes: return self.take(self.u24())
    def done(self) -> bool: return self.pos >= len(self.data)


def record(ctype: int, body: bytes) -> bytes:
    return u8(ctype) + u16(0x0303) + vec16(body)


def split_records(buf: bytes) -> tuple[list[tuple[int, bytes, bytes]], bytes]:
    """Cut a byte stream into (type, 5-byte header, body) records + leftover."""
    out = []
    while len(buf) >= 5:
        n = int.from_bytes(buf[3:5], "big")
        if len(buf) < 5 + n:
            break
        out.append((buf[0], buf[:5], buf[5:5 + n]))
        buf = buf[5 + n:]
    return out, buf


def handshake_msg(msg_type: int, body: bytes) -> bytes:
    return u8(msg_type) + vec24(body)


def split_handshake(buf: bytes) -> tuple[list[tuple[int, bytes]], bytes]:
    """Cut handshake bytes into whole (msg_type, full_message_bytes) + leftover."""
    out = []
    while len(buf) >= 4:
        n = int.from_bytes(buf[1:4], "big")
        if len(buf) < 4 + n:
            break
        out.append((buf[0], buf[:4 + n]))
        buf = buf[4 + n:]
    return out, buf


def parse_extensions(raw: bytes) -> dict[int, bytes]:
    r, out = Reader(raw), {}
    while not r.done():
        etype = r.u16()
        out[etype] = r.vec16()
    return out


def build_client_hello(key_share_pub: bytes, suites: list[int], host: str,
                       client_random: bytes, session_id: bytes) -> bytes:
    """
    The ClientHello, byte by byte. Everything the client proposes is here; the
    server picks one option from each list and says so in its ServerHello.
    """
    ext = b""
    # server_name (SNI): which site we want. Sent in CLEAR -- an observer sees it.
    ext += u16(0) + vec16(vec16(u8(0) + vec16(host.encode())))
    # supported_groups: key-exchange groups we can do. Only x25519 here.
    ext += u16(10) + vec16(vec16(u16(0x001d)))
    # signature_algorithms: how we can verify the server's CertificateVerify.
    ext += u16(13) + vec16(vec16(u16(0x0403) + u16(0x0804) + u16(0x0807)))
    # supported_versions: THIS is where TLS 1.3 is actually negotiated.
    ext += u16(43) + vec16(vec8(u16(TLS13)))
    # key_share: our ephemeral X25519 public key, sent BEFORE the server has
    # answered -- this guess is what makes TLS 1.3 a one-round-trip handshake.
    ext += u16(51) + vec16(vec16(u16(0x001d) + vec16(key_share_pub)))
    body = (u16(0x0303)                          # legacy_version ("TLS 1.2")
            + client_random                      # 32 random bytes
            + vec8(session_id)                   # legacy_session_id (middlebox camouflage)
            + vec16(b"".join(u16(s) for s in suites))
            + vec8(b"\x00")                      # compression: "null" only
            + vec16(ext))
    return handshake_msg(1, body)


def parse_hello(msg: bytes) -> dict:
    """Parse a ClientHello or ServerHello into a dict (enough for this lab)."""
    r = Reader(msg[4:])
    h = {"type": msg[0], "legacy_version": r.u16(), "random": r.take(32), "session_id": r.vec8()}
    if msg[0] == 1:
        cs = r.vec16()
        h["suites"] = [int.from_bytes(cs[i:i + 2], "big") for i in range(0, len(cs), 2)]
        r.vec8()
    else:
        h["suite"] = r.u16()
        r.u8()
    h["extensions"] = parse_extensions(r.vec16())
    return h


# =============================================================================
# SHARED: KEY SCHEDULE
# RFC 8446 section 7.1. Every secret in TLS 1.3 comes out of one tree:
#
#        0 ──▶ HKDF-Extract ──▶ Early Secret
#                                   │ Derive-Secret(., "derived", "")
#                                   ▼
#  (EC)DHE ──▶ HKDF-Extract ──▶ Handshake Secret ──▶ c hs traffic / s hs traffic
#                                   │                 (transcript: CH..SH)
#                                   ▼ Derive-Secret(., "derived", "")
#        0 ──▶ HKDF-Extract ──▶ Master Secret ────▶ c ap traffic / s ap traffic
#                                                    (transcript: CH..server Finished)
#
# Two operations do all the work:
#   HKDF-Extract(salt, ikm)  = HMAC(salt, ikm)           -- "concentrate" entropy
#   HKDF-Expand-Label(secret, label, context, length)    -- "stretch" into named keys
# and every derived secret mixes in a HASH OF THE TRANSCRIPT so far, which is
# why tampering with any earlier message changes every later key (ACTIVITY 4).
# =============================================================================
def hkdf_extract(h, salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract is literally one HMAC with the salt as the key."""
    m = crypto_hmac.HMAC(salt or b"\x00" * h.digest_size, h)
    m.update(ikm)
    return m.finalize()


def hkdf_expand_label(h, secret: bytes, label: str, context: bytes, length: int) -> bytes:
    """
    HKDF-Expand with a TLS 1.3 label. The `info` input is itself TLS-encoded:
        uint16 length | opaque label<"tls13 " + label> | opaque context<hash>
    Prefixing "tls13 " means a key derived for TLS can never collide with a key
    some other protocol derives from the same secret.
    """
    full = b"tls13 " + label.encode()
    info = u16(length) + vec8(full) + vec8(context)
    return HKDFExpand(h, length, info).derive(secret)


def transcript_hash(h, messages: list[bytes]) -> bytes:
    d = hashes.Hash(h)
    for m in messages:
        d.update(m)
    return d.finalize()


def derive_secret(h, secret: bytes, label: str, messages: list[bytes]) -> bytes:
    return hkdf_expand_label(h, secret, label, transcript_hash(h, messages), h.digest_size)


def traffic_keys(suite: int, secret: bytes) -> tuple[bytes, bytes]:
    """A traffic secret is never used directly: it is expanded into key + IV."""
    _, H, _, keylen = SUITES[suite]
    return (hkdf_expand_label(H(), secret, "key", b"", keylen),
            hkdf_expand_label(H(), secret, "iv", b"", 12))


def finished_mac(suite: int, base_secret: bytes, messages: list[bytes]) -> bytes:
    """Finished = HMAC(finished_key, Transcript-Hash(every message so far))."""
    H = SUITES[suite][1]()
    fk = hkdf_expand_label(H, base_secret, "finished", b"", H.digest_size)
    return hmac.new(fk, transcript_hash(H, messages), H.name).digest()


class KeySchedule:
    """Walks the secret tree above, printing every node as it goes."""

    def __init__(self, suite: int, shared_secret: bytes, verbose: bool = True):
        self.suite, self.H = suite, SUITES[suite][1]()
        H, zeros = self.H, b"\x00" * self.H.digest_size
        self.early = hkdf_extract(H, b"", zeros)                       # no PSK -> zeros
        derived = derive_secret(H, self.early, "derived", [])
        self.handshake = hkdf_extract(H, derived, shared_secret)        # ECDHE goes in HERE
        derived2 = derive_secret(H, self.handshake, "derived", [])
        self.master = hkdf_extract(H, derived2, zeros)
        if verbose:
            datablock("early secret", hx(self.early))
            datablock("handshake secret", hx(self.handshake))
            datablock("master secret", hx(self.master))

    def handshake_traffic(self, msgs: list[bytes]) -> tuple[bytes, bytes]:
        return (derive_secret(self.H, self.handshake, "c hs traffic", msgs),
                derive_secret(self.H, self.handshake, "s hs traffic", msgs))

    def application_traffic(self, msgs: list[bytes]) -> tuple[bytes, bytes]:
        return (derive_secret(self.H, self.master, "c ap traffic", msgs),
                derive_secret(self.H, self.master, "s ap traffic", msgs))


# =============================================================================
# SHARED: RECORD PROTECTION
# After the ServerHello, every record is AEAD-encrypted:
#   nonce      = IV XOR sequence_number   (a fresh nonce per record, never sent)
#   AAD        = the 5-byte record header (so the header can't be edited either)
#   plaintext  = content || real_content_type || zero padding
#   outer type = always 23 "application_data" -- an observer can't even tell a
#                Certificate from an HTTP response.
# Decrypt fails (InvalidTag) if ONE bit of ciphertext, header, key or nonce is
# wrong. That single property is CHECK 2.
# =============================================================================
class RecordProtection:
    def __init__(self, suite: int, secret: bytes):
        self.key, self.iv = traffic_keys(suite, secret)
        self.aead = SUITES[suite][2](self.key)
        self.seq = 0

    def _nonce(self) -> bytes:
        n = bytes(a ^ b for a, b in zip(self.iv, self.seq.to_bytes(12, "big")))
        self.seq += 1
        return n

    def seal(self, ctype: int, plaintext: bytes) -> bytes:
        inner = plaintext + u8(ctype)
        hdr = u8(CT_APPDATA) + u16(0x0303) + u16(len(inner) + 16)
        return hdr + self.aead.encrypt(self._nonce(), inner, hdr)

    def open(self, hdr: bytes, body: bytes) -> tuple[int, bytes]:
        inner = self.aead.decrypt(self._nonce(), body, hdr).rstrip(b"\x00")
        return inner[-1], inner[:-1]


# =============================================================================
# SHARED: CERTIFICATES
# A minimal PKI (week 5 builds this properly): one lab root CA that issues the
# server certificate for "localhost", plus a second, ATTACKER-controlled root
# that issues its own "localhost" certificate. Everything is EC P-256 so the
# server signs CertificateVerify with ecdsa_secp256r1_sha256 (0x0403).
# =============================================================================
def make_cert(cn: str, pub, issuer: x509.Certificate | None, issuer_key, *, ca: bool,
              san: str | None = None) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CS440 TLS Lab"),
                         x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer_name = issuer.subject if issuer else subject
    issuer_pub = issuer.public_key() if issuer else pub
    start = NOW() - dt.timedelta(days=1)
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer_name)
         .public_key(pub).serial_number(x509.random_serial_number())
         .not_valid_before(start).not_valid_after(start + dt.timedelta(days=90))
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_pub), critical=False)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    else:
        b = (b.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
             .add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
             .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
    return b.sign(issuer_key, hashes.SHA256())


def write_pem(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if hasattr(obj, "private_bytes"):
        path.write_bytes(obj.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    else:
        path.write_bytes(obj.public_bytes(serialization.Encoding.PEM))


def cmd_init(_args=None, quiet: bool = False) -> int:
    """Create tls/: the lab root CA, the server cert, and the attacker's CA + cert."""
    out = io.StringIO() if quiet else sys.stdout
    with contextlib.redirect_stdout(out):
        header("INIT: BUILD THE LAB PKI")
        for who, root_cn, leaf_cn in (("lab", "CS440 TLS Lab Root CA", "localhost"),
                                      ("evil", "Totally Legit Root CA (attacker)", "localhost")):
            root_key = ec.generate_private_key(ec.SECP256R1())
            root = make_cert(root_cn, root_key.public_key(), None, root_key, ca=True)
            leaf_key = ec.generate_private_key(ec.SECP256R1())
            leaf = make_cert(leaf_cn, leaf_key.public_key(), root, root_key, ca=False, san=HOST)
            write_pem(LAB / who / "root.pem", root)
            write_pem(LAB / who / "leaf.pem", leaf)
            write_pem(LAB / who / "leaf.key", leaf_key)
            datablock(f"{who} root", f"{root_cn}  ->  {LAB / who / 'root.pem'}")
            datablock(f"{who} leaf", f"CN={leaf_cn}, SAN={HOST}, EC P-256  ->  {LAB / who / 'leaf.pem'}")
        print()
        explain("""
            Two complete, internally valid PKIs. The client in this lab trusts only
            the lab root. The attacker's certificate is just as well-formed and
            also says "localhost" -- the ONLY difference between them is which
            root the client happens to have in its trust store (week 5, activity 3).
        """)
    return 0


def ensure_init() -> None:
    if not (LAB / "lab" / "leaf.pem").exists() or not (LAB / "evil" / "leaf.pem").exists():
        cmd_init(quiet=True)


def load_cert(p: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(p.read_bytes())


def load_key(p: Path):
    return serialization.load_pem_private_key(p.read_bytes(), None)


# #############################################################################
# ACTIVITY 1 -- "Meet the libraries"                (command: libraries)
# Which library is actually doing the cryptography when this lab runs? Answer:
# two different copies of OpenSSL, plus some Rust, in one Python process.
# #############################################################################
def cmd_libraries(_args) -> int:
    header("ACTIVITY 1: WHO DOES THE CRYPTOGRAPHY?")
    from cryptography.hazmat.backends.openssl import backend

    sub("The two TLS stacks in this lab")
    datablock("Python", sys.version.split()[0])
    datablock("ssl module links", ssl.OPENSSL_VERSION)
    datablock("cryptography", cryptography.__version__)
    datablock("cryptography links", backend.openssl_version_text())
    print()
    same = ssl.OPENSSL_VERSION == backend.openssl_version_text()
    explain(f"""
        Python's `ssl` module is a thin wrapper around the OpenSSL libssl/libcrypto
        that your Python was built against. `cryptography` ships its OWN copy of
        OpenSSL, statically linked inside its wheel, wrapped in Rust.
        {"Here they happen to be the same version." if same else
         "They are DIFFERENT versions here -- two separate OpenSSLs live in this one process, and each has its own bugs, patches and defaults. Patching one does not patch the other."}
    """)

    sub("What OpenSSL (via `ssl`) offers by default")
    ctx = ssl.create_default_context()
    datablock("TLS 1.3 available", ssl.HAS_TLSv1_3)
    for c in ctx.get_ciphers():
        if c["protocol"] == "TLSv1.3":
            datablock("  TLS 1.3 suite", c["name"])
    tls12 = [c["name"] for c in ctx.get_ciphers() if c["protocol"] != "TLSv1.3"]
    datablock("  TLS 1.2 suites", f"{len(tls12)} more, e.g. {tls12[0]}" if tls12 else "none")
    print()
    explain("""
        TLS 1.3 cut the menu to five suites (three enabled by default), all AEAD,
        all forward-secret. TLS 1.2 had over three hundred registered, which is
        where most historical breakage (RC4, export-grade, CBC padding oracles)
        lived; the 1.2 count above is only what this OpenSSL still enables.
    """)

    sub("Who runs each primitive in the hand-written client (ACTIVITY 2)")
    rows = [
        ("X25519 key exchange", "X25519PrivateKey.exchange", "OpenSSL libcrypto (bundled)"),
        ("HKDF-Extract / HMAC", "hmac.HMAC", "OpenSSL libcrypto (bundled)"),
        ("HKDF-Expand-Label", "HKDFExpand", "Rust loop over OpenSSL HMAC"),
        ("AES-GCM / ChaCha20", "AESGCM / ChaCha20Poly1305", "OpenSSL libcrypto (bundled)"),
        ("ECDSA verify", "EllipticCurvePublicKey.verify", "OpenSSL libcrypto (bundled)"),
        ("X.509 parsing", "x509.load_der_x509_certificate", "Rust (rust-asn1), not OpenSSL"),
        ("chain validation", "PolicyBuilder ... .verify", "Rust, not OpenSSL"),
        ("record framing, state machine", "this file", "you are reading it"),
        ("the SERVER, all of it", "ssl.SSLContext.wrap_bio", ssl.OPENSSL_VERSION),
    ]
    print(f"  {'primitive':<30}{'API called':<32}{'implemented by'}")
    print(f"  {'-' * 29} {'-' * 31} {'-' * 14}")
    for a, b, c in rows:
        print(f"  {a:<30}{b:<32}{c}")
    print()
    explain("""
        The lesson: the protocol logic (what to send, what to check, in which
        order) is small and lives in this file. The primitives are a handful of
        calls into a library you did not write and should never write yourself.
        Most real TLS vulnerabilities live in the protocol logic and parsing --
        Heartbleed, goto fail, SKIP-TLS -- not in AES or X25519.
    """)

    sub("Primitive speed on this machine")
    explain("""
        Why does a server sometimes pick ChaCha20 over AES? AES-GCM is fast only
        with hardware AES instructions (AES-NI on x86, the crypto extensions on
        ARM). Without them ChaCha20-Poly1305 wins, which is why it was added for
        phones. Measure your own machine:
    """)
    data, nonce = os.urandom(1 << 20), os.urandom(12)
    for label, aead in (("AES-128-GCM", AESGCM(os.urandom(16))),
                        ("AES-256-GCM", AESGCM(os.urandom(32))),
                        ("ChaCha20-Poly1305", ChaCha20Poly1305(os.urandom(32)))):
        t0, n = time.perf_counter(), 0
        while time.perf_counter() - t0 < 0.4:
            aead.encrypt(nonce, data, None)
            n += 1
        datablock(label, f"{n / (time.perf_counter() - t0):8.0f} MiB/s")
    for label, gen in (("X25519 key exchange", lambda: X25519PrivateKey.generate().exchange(
                            X25519PrivateKey.generate().public_key())),
                       ("P-256 ECDH key exchange", lambda: ec.generate_private_key(ec.SECP256R1()).exchange(
                            ec.ECDH(), ec.generate_private_key(ec.SECP256R1()).public_key()))):
        t0, n = time.perf_counter(), 0
        while time.perf_counter() - t0 < 0.4:
            gen()
            n += 1
        datablock(label, f"{n / (time.perf_counter() - t0):8.0f} per second (2 keygens + 1 exchange)")
    print()
    explain("""
        Bulk encryption runs at gigabytes per second; the public-key part runs at
        thousands per second. That asymmetry is the reason every secure protocol
        is hybrid: public-key crypto once per connection to agree a key, then a
        symmetric AEAD for every byte after.
    """)
    return 0


# #############################################################################
# ACTIVITY 2 -- "The handshake by hand"             (command: handshake)
# A complete TLS 1.3 client. It builds the ClientHello, does X25519, walks the
# key schedule, decrypts the server's flight, makes the five checks, sends its
# own Finished, then one HTTP request over the encrypted channel.
#
# `peer` is whatever is on the other end of the wire -- the real OpenSSL server
# (honest run) or an attacker (ACTIVITY 4). The client cannot tell which; it
# has only the five checks.
# #############################################################################
class Abort(Exception):
    """The client refuses to continue. `check` says which of the five caught it."""
    def __init__(self, check_no: int, reason: str):
        super().__init__(reason)
        self.check_no, self.reason = check_no, reason


def run_client(peer, trust: list[x509.Certificate], naive: bool = False) -> dict:
    """Run one handshake + one request. Returns {check_no: True/False/None, ...}."""
    result = {n: None for n in range(1, 6)}
    result["response"] = None
    try:
        _client(peer, trust, naive, result)
    except Abort as e:
        check(e.check_no, CHECK_TITLES[e.check_no], False, e.reason)
        result[e.check_no] = False
        print("\n  >>> client aborts the connection. Nothing was sent to the 'server'.")
    return result


CHECK_TITLES = {1: "ServerHello picked something we offered",
                2: "every encrypted record decrypts (AEAD tag)",
                3: "certificate chains to a trusted root, for this host",
                4: "CertificateVerify proves the server holds the cert's key",
                5: "server Finished MAC matches our transcript"}


def _client(peer, trust, naive, result) -> None:
    transcript: list[bytes] = []                 # every handshake message, in order

    # -- FLIGHT 1: ClientHello ------------------------------------------------
    sub("FLIGHT 1  ClientHello  (plaintext)")
    eph = X25519PrivateKey.generate()            # ephemeral: lives for this handshake only
    eph_pub = eph.public_key().public_bytes_raw()
    offered = [0x1301, 0x1302, 0x1303]
    session_id = os.urandom(32)
    ch = build_client_hello(eph_pub, offered, HOST, os.urandom(32), session_id)
    transcript.append(ch)
    datablock("our X25519 private key", hx(eph.private_bytes_raw()) + "  (never sent)")
    datablock("our X25519 public key", hx(eph_pub) + "  (key_share)")
    datablock("cipher suites offered", ", ".join(SUITES[s][0] for s in offered))
    datablock("SNI", f"{HOST}  (visible to anyone on the path)")
    wire = record(CT_HANDSHAKE, ch)
    arrow("c2s", "ClientHello", len(wire))
    print(f"           {hx(wire, 48)}")
    peer.send(wire)

    # -- FLIGHT 2: ServerHello + encrypted server flight ----------------------
    records, leftover = split_records(peer.recv())
    if not records or records[0][0] != CT_HANDSHAKE:
        raise Abort(1, f"expected a plaintext ServerHello, got {records[:1]}")
    sh = records[0][2]
    sub("FLIGHT 2a  ServerHello  (plaintext)")
    arrow("s2c", "ServerHello", 5 + len(sh))
    hello = parse_hello(sh)
    ext = hello["extensions"]
    version = int.from_bytes(ext.get(43, b"\x00\x00"), "big")
    suite = hello["suite"]
    ks = Reader(ext.get(51, b"\x00\x00\x00\x00"))
    group, server_pub = ks.u16(), ks.vec16()
    datablock("selected version", f"0x{version:04x}  (record header still says 0x0303)")
    datablock("selected suite", SUITES.get(suite, (f"unknown 0x{suite:04x}",))[0])
    datablock("server key_share", f"{GROUPS.get(group, hex(group))}: {hx(server_pub)}")
    datablock("server random", hx(hello["random"]))

    # CHECK 1 of 5 -- "Did the server pick from what we offered?"
    # A server cannot invent options: version must be 1.3 (from supported_versions,
    # not the legacy field), the suite and group must be ones WE listed, and the
    # session_id must echo ours. Note what this check CANNOT see: whether an
    # attacker edited our offer before the server read it (variant downgrade-hello).
    if version != TLS13 or suite not in offered or group != 0x001d or hello["session_id"] != session_id:
        raise Abort(1, "server selected parameters we never offered")
    check(1, CHECK_TITLES[1], True, f"TLS 1.3, {SUITES[suite][0]}, x25519.")
    result[1] = True
    transcript.append(sh)

    sub("Key exchange: X25519")
    shared = eph.exchange(X25519PublicKey.from_public_bytes(server_pub))
    datablock("shared secret", hx(shared))
    explain("""
        our private key x server's public key. The server computed the same 32
        bytes from its private key and our public key. Nobody watching the wire
        can: they saw both public keys and neither private key. Both private keys
        are thrown away after this handshake, so stealing the server's long-term
        key next year still cannot recover this secret -- forward secrecy.
    """)

    sub("KEY SCHEDULE (RFC 8446 7.1) -- every secret, from one shared secret")
    sched = KeySchedule(suite, shared)
    c_hs, s_hs = sched.handshake_traffic(transcript)
    datablock("transcript hash CH..SH", hx(transcript_hash(sched.H, transcript)))
    datablock("client hs traffic secret", hx(c_hs))
    datablock("server hs traffic secret", hx(s_hs))
    s_rec = RecordProtection(suite, s_hs)
    datablock("server hs write key", hx(s_rec.key))
    datablock("server hs write IV", hx(s_rec.iv))

    sub("FLIGHT 2b  the rest of the server flight  (encrypted)")
    hs_buf, msgs = b"", []
    for ctype, hdr, body in records[1:]:
        if ctype == CT_CCS:
            arrow("s2c", "ChangeCipherSpec  (dummy, middlebox compatibility; ignored)", 5 + len(body))
            continue
        arrow("s2c", f"record type {ctype} '{CONTENT_TYPES.get(ctype, '?')}'", 5 + len(body))
        # CHECK 2 of 5 -- "Does every record decrypt under the key we derived?"
        # The AEAD tag fails if the ciphertext was edited (flip-record), or if our
        # keys differ from the server's -- different shared secret (swap-keyshare)
        # or different transcript (downgrade-hello). It cannot say WHICH.
        try:
            inner_type, pt = s_rec.open(hdr, body)
        except InvalidTag:
            raise Abort(2, f"record #{s_rec.seq - 1} failed authentication (InvalidTag): "
                           "it was modified, or our keys are not the server's keys")
        print(f"           decrypted -> real type {inner_type} '{CONTENT_TYPES.get(inner_type)}', {len(pt)} bytes")
        hs_buf += pt
        new, hs_buf = split_handshake(hs_buf)
        msgs += new
    check(2, CHECK_TITLES[2], True, f"{s_rec.seq} record(s) authenticated with the server handshake key.")
    result[2] = True

    # Walk the decrypted messages in the ONLY order the protocol allows.
    # A client that accepts messages in any order, or skips one, is the classic
    # state-machine bug (SKIP-TLS, 2015) -- see variant skip-certverify.
    expected = [8, 11, 15, 20]
    for want in expected:
        if not msgs:
            raise Abort(5, "server flight ended early")
        mtype, msg = msgs[0]
        if mtype != want:
            if naive and want == 15:
                print(f"\n  (naive client: expected CertificateVerify, got {HS_TYPES.get(mtype)} -- carrying on anyway)")
                result[4] = None
                continue
            raise Abort({11: 3, 15: 4}.get(want, 5),
                        f"expected {HS_TYPES[want]}, got {HS_TYPES.get(mtype, mtype)}")
        msgs.pop(0)
        body = Reader(msg[4:])
        print(f"\n  >> {HS_TYPES[mtype]} ({len(msg)} bytes)")

        if mtype == 8:
            datablock("extensions", ", ".join(EXT_NAMES.get(e, str(e)) for e in parse_extensions(body.vec16())) or "(none)")
            explain("""
                Everything the server says beyond the bare key exchange is now
                encrypted: ALPN, the certificate, the signature. In TLS 1.2 the
                certificate went in clear -- an observer learned which site you
                were talking to from it.
            """)

        elif mtype == 11:
            body.vec8()                          # certificate_request_context (empty)
            entries, chain = Reader(body.vec24()), []
            while not entries.done():
                chain.append(x509.load_der_x509_certificate(entries.vec24()))
                entries.vec16()                  # per-certificate extensions
            leaf = chain[0]
            datablock("certificates sent", len(chain))
            datablock("leaf subject", leaf.subject.rfc4514_string())
            datablock("leaf issuer", leaf.issuer.rfc4514_string())
            # CHECK 3 of 5 -- "Is this certificate for this host, from a CA we trust?"
            # Delegated to cryptography's verifier -- week 5 took this check apart
            # into seven steps. Note: the certificate is PUBLIC. Passing this check
            # proves nothing about who sent it (variant mitm-stolen-cert).
            try:
                (PolicyBuilder().store(Store(trust)).build_server_verifier(x509.DNSName(HOST))
                 .verify(leaf, chain[1:]))
            except VerificationError as e:
                raise Abort(3, f"chain rejected: {e}")
            check(3, CHECK_TITLES[3], True,
                  f"chains to '{leaf.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}', "
                  f"which is in our trust store; SAN covers {HOST}.")
            result[3] = True

        elif mtype == 15:
            scheme, sig = body.u16(), body.vec16()
            th = transcript_hash(sched.H, transcript)
            # CHECK 4 of 5 -- "Does the sender hold the private key of that certificate?"
            # The server signs a hash of the WHOLE transcript so far (including OUR
            # random key share) with the certificate's private key. A fresh
            # signature over fresh data cannot be replayed from another session.
            signed = b"\x20" * 64 + b"TLS 1.3, server CertificateVerify" + b"\x00" + th
            datablock("signature scheme", SIG_SCHEMES.get(scheme, hex(scheme)))
            datablock("signed content", f"64 spaces | 'TLS 1.3, server CertificateVerify' | 0x00 | {hx(th, 16)}")
            datablock("signature", hx(sig))
            try:
                verify_signature(leaf.public_key(), scheme, sig, signed)
            except (InvalidSignature, ValueError) as e:
                raise Abort(4, f"signature does not verify under the certificate's public key ({type(e).__name__}): "
                               "whoever sent this does not hold the certificate's private key")
            check(4, CHECK_TITLES[4], True, "signature over the transcript verifies with the leaf's public key.")
            result[4] = True

        elif mtype == 20:
            # CHECK 5 of 5 -- "Did the server see exactly the transcript we saw?"
            # HMAC under a key only the two endpoints can derive. In TLS 1.3 the
            # transcript already feeds the keys, so tampering usually fails CHECK 2
            # first -- Finished is key confirmation plus defence in depth.
            want_mac = finished_mac(suite, s_hs, transcript)
            got_mac = body.take(sched.H.digest_size)
            datablock("verify_data received", hx(got_mac))
            datablock("verify_data expected", hx(want_mac))
            if not hmac.compare_digest(got_mac, want_mac):
                raise Abort(5, "Finished MAC mismatch: the transcripts differ")
            check(5, CHECK_TITLES[5], True, "the server saw the same handshake we did.")
            result[5] = True
        transcript.append(msg)

    # -- FLIGHT 3: client Finished + the actual request -----------------------
    sub("Application keys")
    c_ap, s_ap = sched.application_traffic(transcript)
    datablock("transcript hash CH..sFin", hx(transcript_hash(sched.H, transcript)))
    datablock("client ap traffic secret", hx(c_ap))
    datablock("server ap traffic secret", hx(s_ap))

    sub("FLIGHT 3  client Finished + HTTP request  (encrypted)")
    c_rec = RecordProtection(suite, c_hs)
    fin = handshake_msg(20, finished_mac(suite, c_hs, transcript))
    out = c_rec.seal(CT_HANDSHAKE, fin)
    arrow("c2s", "Finished (under client handshake key)", len(out))
    app_out = RecordProtection(suite, c_ap)
    request = f"GET / HTTP/1.1\r\nHost: {HOST}\r\nCookie: session=hunter2\r\n\r\n".encode()
    req = app_out.seal(CT_APPDATA, request)
    arrow("c2s", "HTTP request (under client application key)", len(req))
    print(f"           plaintext : {request!r}")
    print(f"           on the wire: {hx(req, 40)}")
    peer.send(out + req)

    # -- FLIGHT 4: whatever the server sends back -----------------------------
    sub("FLIGHT 4  server -> client  (encrypted under server application key)")
    app_in = RecordProtection(suite, s_ap)
    recs, _ = split_records(peer.recv())
    for ctype, hdr, body in recs:
        try:
            inner_type, pt = app_in.open(hdr, body)
        except InvalidTag:
            raise Abort(2, "application record failed authentication")
        if inner_type == CT_HANDSHAKE:
            for mtype, _m in split_handshake(pt)[0]:
                arrow("s2c", f"{HS_TYPES.get(mtype, mtype)} (for resuming later without a full handshake)", 5 + len(body))
        elif inner_type == CT_APPDATA:
            arrow("s2c", "HTTP response", 5 + len(body))
            print(f"           plaintext : {pt!r}")
            result["response"] = pt
    print()


def verify_signature(pub, scheme: int, sig: bytes, data: bytes) -> None:
    if scheme == 0x0403 and isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
    elif scheme == 0x0804 and isinstance(pub, rsa.RSAPublicKey):
        pub.verify(sig, data, padding.PSS(padding.MGF1(hashes.SHA256()), 32), hashes.SHA256())
    elif scheme == 0x0807 and isinstance(pub, ed25519.Ed25519PublicKey):
        pub.verify(sig, data)
    else:
        raise ValueError(f"scheme {scheme:#06x} does not match the certificate's key type")


# #############################################################################
# ACTIVITY 3 -- "The key log"                       (command: keylog)
# Two OpenSSLs talk to each other. We capture every byte, plus the key log file
# the client writes (the SSLKEYLOGFILE mechanism browsers and Wireshark use).
# Then we decrypt the capture with the SAME HKDF-Expand-Label and
# RecordProtection code from ACTIVITY 2 -- if our key schedule were wrong by a
# single bit, not one record would open.
# #############################################################################
def cmd_keylog(_args) -> int:
    ensure_init()
    header("ACTIVITY 3: DECRYPT OPENSSL <-> OPENSSL WITH A KEY LOG")
    logfile = Path(tempfile.gettempdir()) / f"tls_lab_keylog_{os.getpid()}.txt"

    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cctx.load_verify_locations(LAB / "lab" / "root.pem")
    cctx.minimum_version = ssl.TLSVersion.TLSv1_3
    cctx.keylog_filename = str(logfile)          # <- the whole activity hinges on this line
    server = OpenSSLServer(LAB / "lab")
    cin, cout = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = cctx.wrap_bio(cin, cout, server_hostname=HOST)

    # Pump bytes between the two OpenSSLs, recording each direction separately.
    wire = {"c2s": b"", "s2c": b""}
    for _ in range(10):
        try:
            client.do_handshake()
            break
        except ssl.SSLWantReadError:
            pass
        data = cout.read()
        wire["c2s"] += data
        server.send(data)
        reply = server.recv()
        wire["s2c"] += reply
        cin.write(reply)
    data = cout.read()
    wire["c2s"] += data
    server.send(data)
    client.write(b"GET /secret HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer s3cr3t-t0k3n\r\n\r\n")
    data = cout.read()
    wire["c2s"] += data
    server.send(data)
    reply = server.recv()
    wire["s2c"] += reply
    cin.write(reply)
    with contextlib.suppress(ssl.SSLWantReadError):
        client.read(4096)

    sub("1. What a passive observer captured")
    for d in ("c2s", "s2c"):
        recs, _ = split_records(wire[d])
        print(f"  {d}: " + "  ".join(f"[{CONTENT_TYPES[t][:9]} {len(b)}B]" for t, _, b in recs))
    print()
    explain("""
        Only the two Hellos are readable. Everything else -- certificate, request,
        response, the bearer token -- is 'application_data' of various sizes.
        (The sizes themselves leak something; that is traffic analysis.)
    """)

    sub("2. The key log file the client wrote")
    keys = {}
    for line in logfile.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        label, crandom, secret = line.split()
        keys[label] = bytes.fromhex(secret)
        print(f"  {label:<34} {crandom[:12]}...  {secret[:24]}...")
    logfile.unlink()
    print()
    explain("""
        Format: LABEL  client_random  secret. The client_random column says WHICH
        connection the line belongs to -- match it against the ClientHello. These
        are the traffic secrets, the leaves of the key schedule. Anyone holding
        this file plus a packet capture reads the session. Browsers write it when
        the SSLKEYLOGFILE environment variable is set; Wireshark reads it.
    """)

    sub("3. Decrypt the capture with our own code")
    s_recs, _ = split_records(wire["s2c"])
    c_recs, _ = split_records(wire["c2s"])
    sh = parse_hello(s_recs[0][2])
    suite = sh["suite"]
    ch_random = parse_hello(c_recs[0][2])["random"]
    datablock("matching client_random", hx(ch_random, 12) + "  (from the captured ClientHello)")
    datablock("suite from ServerHello", SUITES[suite][0])
    for direction, recs, hs_label, ap_label in (
            ("s2c", s_recs, "SERVER_HANDSHAKE_TRAFFIC_SECRET", "SERVER_TRAFFIC_SECRET_0"),
            ("c2s", c_recs, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0")):
        print(f"\n  {direction}:")
        prot, on_app_keys = RecordProtection(suite, keys[hs_label]), False
        for ctype, hdr, body in recs:
            if ctype != CT_APPDATA:
                what = HS_TYPES[body[0]] if ctype == CT_HANDSHAKE else "dummy"
                print(f"    [{CONTENT_TYPES[ctype]}]  {what} -- sent in clear, nothing to decrypt")
                continue
            itype, pt = prot.open(hdr, body)
            if itype == CT_HANDSHAKE:
                types = [m for m, _ in split_handshake(pt)[0]]
                print(f"    [handshake]  {', '.join(HS_TYPES.get(m, str(m)) for m in types)}")
                if 20 in types and not on_app_keys:    # after Finished, switch to the app keys
                    prot, on_app_keys = RecordProtection(suite, keys[ap_label]), True
            else:
                print(f"    [{CONTENT_TYPES[itype]}]  {pt!r}")
    print()
    explain("""
        Every record opened, using keys derived by hkdf_expand_label() -- the same
        ten lines ACTIVITY 2 uses. Our key schedule agrees with OpenSSL's bit for
        bit. And the bearer token is now plaintext, without ever touching the
        server's private key: in TLS 1.3 the private key only SIGNS; it is not
        involved in deriving the session keys at all.
    """)
    server.close()
    return 0


# #############################################################################
# ACTIVITY 4 -- "Attack the handshake"     (command: handshake <variant>)
# Each variant puts an attacker on the wire between our client and the server.
# Predict which of the five checks catches it BEFORE you run it. Two kinds:
#   - an on-path TAMPERER sits between our client and the real OpenSSL server
#     and edits bytes in flight (it never learns any keys);
#   - an IMPERSONATOR answers the client itself, running its own fake TLS
#     server (AttackerServer below), with whatever certificate it can get.
# #############################################################################
VARIANTS = {
    "honest":          "no attacker -- our client vs the real OpenSSL server",
    "flip-record":     "on-path: flip one bit inside the server's encrypted Certificate record",
    "swap-keyshare":   "on-path: replace the server's X25519 public key with the attacker's",
    "downgrade-hello": "on-path: strip all but one cipher suite from our ClientHello",
    "mitm-stolen-cert": "impersonator: sends the REAL server certificate, signs with its own key",
    "mitm-own-cert":   "impersonator: its own 'localhost' certificate from its own CA",
    "skip-certverify": "impersonator: real certificate, simply omits CertificateVerify",
    "mitm-trusted-ca": "impersonator: own CA, which the client has been made to trust",
}


def build_variant(variant: str):
    """Return (peer, trust_store) for one variant. Read AFTER you predict."""
    lab_root = load_cert(LAB / "lab" / "root.pem")
    evil_root = load_cert(LAB / "evil" / "root.pem")
    trust = [lab_root]

    if variant == "honest":
        return OpenSSLServer(LAB / "lab"), trust

    if variant == "flip-record":
        # VARIANT: flip-record -- one bit, in ciphertext the attacker can't read.
        def hook(direction, data):
            if direction != "s2c":
                return data
            recs, _ = split_records(data)
            out, n_app = b"", 0
            for ctype, hdr, body in recs:
                if ctype == CT_APPDATA:
                    n_app += 1
                    if n_app == 2:               # usually the Certificate record
                        body = body[:20] + bytes([body[20] ^ 0x01]) + body[21:]
                out += hdr + body
            return out
        return Tamperer(OpenSSLServer(LAB / "lab"), hook), trust

    if variant == "swap-keyshare":
        # VARIANT: swap-keyshare -- the attacker substitutes its own DH public
        # key, hoping to share a secret with the client. Same length, so the
        # message still parses perfectly.
        attacker_pub = X25519PrivateKey.generate().public_key().public_bytes_raw()

        def hook(direction, data):
            if direction != "s2c" or data[:1] != bytes([CT_HANDSHAKE]):
                return data
            (_, _, sh), *_ = split_records(data)[0]
            h = parse_hello(sh)
            h["extensions"][51] = u16(0x001d) + vec16(attacker_pub)
            ext = b"".join(u16(k) + vec16(v) for k, v in h["extensions"].items())
            forged = handshake_msg(2, u16(0x0303) + h["random"] + vec8(h["session_id"])
                                   + u16(h["suite"]) + u8(0) + vec16(ext))
            return record(CT_HANDSHAKE, forged) + data[5 + len(sh):]
        return Tamperer(OpenSSLServer(LAB / "lab"), hook), trust

    if variant == "downgrade-hello":
        # VARIANT: downgrade-hello -- rewrite the client's offer to one suite.
        # Every suite in TLS 1.3 is strong, so this "downgrade" is harmless in
        # itself; the point is whether the client NOTICES its offer was edited.
        # (In TLS 1.2 and earlier, FREAK and Logjam did exactly this, to export-
        # grade crypto, and succeeded.)
        def hook(direction, data):
            if direction != "c2s" or data[:1] != bytes([CT_HANDSHAKE]):
                return data
            ch = data[5:]
            r = Reader(ch[4:])
            r.take(2 + 32)
            r.vec8()
            start = 4 + r.pos
            old = r.vec16()
            new_ch_body = ch[4:start] + vec16(u16(0x1301)) + ch[4 + r.pos:]
            print(f"  [attacker] cipher_suites {old.hex()} -> 1301")
            return record(CT_HANDSHAKE, handshake_msg(1, new_ch_body))
        return Tamperer(OpenSSLServer(LAB / "lab"), hook), trust

    if variant == "mitm-stolen-cert":
        # VARIANT: mitm-stolen-cert -- certificates are public; anyone can copy
        # one from a real handshake. The attacker can't copy the private key, so
        # it signs CertificateVerify with a key of its own.
        return AttackerServer(cert=load_cert(LAB / "lab" / "leaf.pem"),
                              key=ec.generate_private_key(ec.SECP256R1())), trust

    if variant == "mitm-own-cert":
        # VARIANT: mitm-own-cert -- a perfectly valid cert, key and all, for
        # "localhost". Issued by a CA the client has never heard of.
        return AttackerServer(cert=load_cert(LAB / "evil" / "leaf.pem"),
                              key=load_key(LAB / "evil" / "leaf.key")), trust

    if variant == "skip-certverify":
        # VARIANT: skip-certverify -- real cert, no proof of the key: just leave
        # the proof out and hope the client's state machine doesn't notice.
        return AttackerServer(cert=load_cert(LAB / "lab" / "leaf.pem"),
                              key=ec.generate_private_key(ec.SECP256R1()), skip_cv=True), trust

    if variant == "mitm-trusted-ca":
        # VARIANT: mitm-trusted-ca -- identical to mitm-own-cert, except the
        # attacker's root is in the client's trust store. Corporate "TLS
        # inspection" proxies, some antivirus, and stalkerware all work this way.
        return AttackerServer(cert=load_cert(LAB / "evil" / "leaf.pem"),
                              key=load_key(LAB / "evil" / "leaf.key")), trust + [evil_root]

    raise SystemExit(f"unknown variant {variant!r}; try: uv run tls_lab.py variants")


def run_variant(variant: str, naive: bool) -> dict:
    header(f"ACTIVITY {'2' if variant == 'honest' else '4'}: HANDSHAKE -- variant '{variant}'")
    datablock("scenario", VARIANTS[variant])
    peer, trust = build_variant(variant)
    datablock("client trusts", ", ".join(c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                                         for c in trust))
    if naive:
        datablock("client mode", "NAIVE -- does not enforce message order")
    res = run_client(peer, trust, naive=naive)
    res["attacker_saw"] = getattr(peer, "stolen", None)
    sub("Outcome")
    if res["response"] is not None and res["attacker_saw"]:
        print(f"  ATTACKER WINS. It decrypted our request: {res['attacker_saw']!r}")
    elif res["response"] is not None:
        print("  Secure connection. Request sent and response received.")
    else:
        print("  Handshake refused -- the attacker learned nothing and our request was never sent.")
    peer.close()
    return res


def cmd_handshake(args) -> int:
    ensure_init()
    if not args.all:
        run_variant(args.variant, args.naive)
        return 0
    rows = []
    for v in VARIANTS:
        for naive in ((False, True) if v == "skip-certverify" else (False,)):
            with contextlib.redirect_stdout(io.StringIO()):
                r = run_variant(v, naive)
            rows.append((v + (" --naive" if naive else ""), r))
    header("ACTIVITY 4: SCOREBOARD")
    print(f"  {'variant':<26} C1   C2   C3   C4   C5   outcome")
    print(f"  {'-' * 25} " + "---- " * 5 + "-" * 18)
    mark = {True: "ok ", False: "FAIL", None: " -  "}
    for v, r in rows:
        outcome = ("ATTACKER READS" if r["attacker_saw"] and r["response"] is not None
                   else "secure" if r["response"] is not None else "refused")
        print(f"  {v:<26} " + " ".join(f"{mark[r[n]]:<4}" for n in range(1, 6)) + f" {outcome}")
    print()
    print("  ok = check passed   FAIL = the check that stopped the handshake   - = never reached")
    return 0


# =============================================================================
# SHARED: PEERS
# Whatever the client is talking to. All three expose send(bytes) / recv() and
# move bytes through memory -- no sockets, no threads, fully deterministic.
# =============================================================================
class OpenSSLServer:
    """The honest server: Python's ssl module, i.e. OpenSSL, driven through MemoryBIO."""

    def __init__(self, pki_dir: Path):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(pki_dir / "leaf.pem", pki_dir / "leaf.key")
        self.inbio, self.outbio = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = ctx.wrap_bio(self.inbio, self.outbio, server_side=True)
        self.done = False

    def send(self, data: bytes) -> None:
        self.inbio.write(data)
        try:
            if not self.done:
                self.tls.do_handshake()
                self.done = True
            req = self.tls.read(4096)
            if req:
                self.tls.write(b"HTTP/1.1 200 OK\r\nContent-Length: 19\r\n\r\nhello from OpenSSL\n")
        except ssl.SSLWantReadError:
            pass
        except ssl.SSLError as e:
            # The server gives up too (e.g. it can't decrypt our Finished). In real
            # life it would send an alert; here we just note it.
            print(f"  [OpenSSL server] {e.reason or e}")

    def recv(self) -> bytes:
        return self.outbio.read()

    def close(self) -> None:
        pass


class Tamperer:
    """An on-path attacker: forwards bytes, calling hook(direction, data) on each flight."""

    def __init__(self, inner, hook):
        self.inner, self.hook = inner, hook
        self.stolen = None

    def send(self, data: bytes) -> None:
        self.inner.send(self.hook("c2s", data))

    def recv(self) -> bytes:
        return self.hook("s2c", self.inner.recv())

    def close(self) -> None:
        self.inner.close()


class AttackerServer:
    """
    A fake TLS 1.3 server -- the server half of ACTIVITY 2, written for the
    attacker. It speaks the protocol perfectly; all it lacks is whatever
    credential its certificate/key pair can't provide.
    """

    def __init__(self, cert: x509.Certificate, key, skip_cv: bool = False):
        self.cert, self.key, self.skip_cv = cert, key, skip_cv
        self.out = b""
        self.stolen = None
        self.state = "hello"

    def send(self, data: bytes) -> None:
        if self.state == "hello":
            self._respond_to_hello(data)
        elif self.state == "finished":
            self._read_client(data)

    def recv(self) -> bytes:
        out, self.out = self.out, b""
        return out

    def close(self) -> None:
        pass

    def _respond_to_hello(self, data: bytes) -> None:
        (_, _, body), *_ = split_records(data)[0]
        ch = parse_hello(body)
        shares = Reader(Reader(ch["extensions"][51]).vec16())
        shares.u16()                                    # group: x25519
        client_pub = shares.vec16()
        self.suite = suite = 0x1301
        eph = X25519PrivateKey.generate()
        ext = (u16(43) + vec16(u16(TLS13))
               + u16(51) + vec16(u16(0x001d) + vec16(eph.public_key().public_bytes_raw())))
        sh = handshake_msg(2, u16(0x0303) + os.urandom(32) + vec8(ch["session_id"]) + u16(suite) + u8(0) + vec16(ext))
        self.transcript = [body, sh]
        self.sched = KeySchedule(suite, eph.exchange(X25519PublicKey.from_public_bytes(client_pub)), verbose=False)
        self.c_hs, s_hs = self.sched.handshake_traffic(self.transcript)
        prot = RecordProtection(suite, s_hs)
        der = self.cert.public_bytes(serialization.Encoding.DER)
        flight = [handshake_msg(8, vec16(b"")),
                  handshake_msg(11, vec8(b"") + vec24(vec24(der) + vec16(b"")))]
        self.transcript += flight
        if not self.skip_cv:
            th = transcript_hash(self.sched.H, self.transcript)
            sig = self.key.sign(b"\x20" * 64 + b"TLS 1.3, server CertificateVerify\x00" + th, ec.ECDSA(hashes.SHA256()))
            cv = handshake_msg(15, u16(0x0403) + vec16(sig))
            flight.append(cv)
            self.transcript.append(cv)
        fin = handshake_msg(20, finished_mac(suite, s_hs, self.transcript))
        flight.append(fin)
        self.transcript.append(fin)
        self.out = record(CT_HANDSHAKE, sh) + b"".join(prot.seal(CT_HANDSHAKE, m) for m in flight)
        self.state = "finished"

    def _read_client(self, data: bytes) -> None:
        c_ap, s_ap = self.sched.application_traffic(self.transcript)
        hs_in, ap_in = RecordProtection(self.suite, self.c_hs), RecordProtection(self.suite, c_ap)
        recs, _ = split_records(data)
        hs_in.open(recs[0][1], recs[0][2])              # client Finished
        for _, hdr, body in recs[1:]:
            _, self.stolen = ap_in.open(hdr, body)
        self.out = RecordProtection(self.suite, s_ap).seal(
            CT_APPDATA, b"HTTP/1.1 200 OK\r\nContent-Length: 24\r\n\r\nhello from the attacker\n")
        print(f"\n  [attacker] decrypted the client's request: {self.stolen!r}")


# =============================================================================
# SHARED: CLI
# =============================================================================
def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(AttributeError):
            stream.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    s = p.add_subparsers(dest="cmd", required=True)
    s.add_parser("init", help="build the lab CA, server cert and attacker CA under ./tls/")
    s.add_parser("libraries", help="ACTIVITY 1: which library runs which primitive")
    h = s.add_parser("handshake", help="ACTIVITY 2/4: hand-written TLS 1.3 client")
    h.add_argument("variant", nargs="?", default="honest", choices=list(VARIANTS))
    h.add_argument("--all", action="store_true", help="run every variant, print a scoreboard")
    h.add_argument("--naive", action="store_true", help="client does not enforce message order")
    s.add_parser("variants", help="list the attack variants")
    s.add_parser("keylog", help="ACTIVITY 3: decrypt OpenSSL<->OpenSSL with a key log")
    args = p.parse_args()

    if args.cmd == "variants":
        for k, v in VARIANTS.items():
            print(f"  {k:<18} {v}")
        return 0
    return {"init": cmd_init, "libraries": cmd_libraries, "handshake": cmd_handshake,
            "keylog": cmd_keylog}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
