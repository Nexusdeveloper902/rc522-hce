"""Reference backend for RC522-HCE protocol v2 (zero dependencies, stdlib only).

Implements the server side of docs/API.md §11 exactly as documented:
MAC verification (constant-time), v2 ChaCha20-Poly1305 key unwrap, and
proof-of-possession enrollment — plus an atomic per-credential replay
table backed by SQLite (UNIQUE constraint, so concurrent duplicate
claims cannot both succeed).

This is a *reference*: correct and tested, not hardened for scale.
Production backends SHOULD use a vetted AEAD/TLS/database stack
(e.g. the `cryptography` package instead of the pure-Python AEAD below)
and MUST still pass the shared interop vector in test_hce_backend.py.

Wire constants mirror src/HceProtocol.h TestVector — keep them in sync.
"""

import hashlib
import hmac
import sqlite3

PROTOCOL_VERSION = 2  # must match rc522hce::PROTOCOL_VERSION
NONCE_BYTES = 16
MAC_BYTES = 32
KEY_BYTES = 32
WRAP_NONCE_BYTES = 12
TAG_BYTES = 16

V2_ENC_LABEL = b"pulse-hce-key-wrap/v2-enc\n"
V2_LABEL = b"pulse-hce-key-wrap/v2\n"


# --- ChaCha20-Poly1305 (RFC 8439, reference-grade pure Python) ----------------
# Straight from the RFC pseudocode (§2.3.1, §2.5.1, §2.8.1). Slow for bulk
# data, instant for 32-byte keys. Production: swap for `cryptography`.

def _rotl(v, n):
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def _quarter_round(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] ^= x[a]
    x[d] = _rotl(x[d], 16)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] ^= x[c]
    x[b] = _rotl(x[b], 12)
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] ^= x[a]
    x[d] = _rotl(x[d], 8)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] ^= x[c]
    x[b] = _rotl(x[b], 7)


def chacha_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    assert len(key) == 32 and len(nonce) == 12
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state += [int.from_bytes(key[i:i + 4], "little") for i in range(0, 32, 4)]
    state += [counter]
    state += [int.from_bytes(nonce[i:i + 4], "little") for i in range(0, 12, 4)]
    work = list(state)
    for _ in range(10):
        _quarter_round(work, 0, 4, 8, 12)
        _quarter_round(work, 1, 5, 9, 13)
        _quarter_round(work, 2, 6, 10, 14)
        _quarter_round(work, 3, 7, 11, 15)
        _quarter_round(work, 0, 5, 10, 15)
        _quarter_round(work, 1, 6, 11, 12)
        _quarter_round(work, 2, 7, 8, 13)
        _quarter_round(work, 3, 4, 9, 14)
    out = b""
    for a, b in zip(state, work):
        out += ((a + b) & 0xFFFFFFFF).to_bytes(4, "little")
    return out


def _chacha_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = chacha_block(key, counter, nonce)
        counter += 1
        chunk = data[i:i + 64]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
    return bytes(out)


def _poly1305(key: bytes, msg: bytes) -> bytes:
    prime = (1 << 130) - 5
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        n = int.from_bytes(block, "little") + (1 << (8 * len(block)))
        acc = ((acc + n) * r) % prime
    return ((acc + s) % (1 << 128)).to_bytes(16, "little")


def aead_encrypt(key: bytes, nonce: bytes, aad: bytes, pt: bytes):
    """Returns (ciphertext, tag). Nonce MUST be fresh per call."""
    otk = chacha_block(key, 0, nonce)[:32]
    ct = _chacha_xor(key, 1, nonce, pt)

    def pad16(b):
        return b if len(b) % 16 == 0 else b + bytes(16 - len(b) % 16)

    mac_data = pad16(aad) + pad16(ct)
    mac_data += len(aad).to_bytes(8, "little") + len(ct).to_bytes(8, "little")
    return ct, _poly1305(otk, mac_data)


def aead_decrypt(key: bytes, nonce: bytes, aad: bytes, ct: bytes, tag: bytes):
    """Returns plaintext, or None when the tag does not verify."""
    otk = chacha_block(key, 0, nonce)[:32]

    def pad16(b):
        return b if len(b) % 16 == 0 else b + bytes(16 - len(b) % 16)

    mac_data = pad16(aad) + pad16(ct)
    mac_data += len(aad).to_bytes(8, "little") + len(ct).to_bytes(8, "little")
    if not hmac.compare_digest(_poly1305(otk, mac_data), tag):
        return None
    return _chacha_xor(key, 1, nonce, ct)


# --- Operation taps ------------------------------------------------------------

def verify_proof(cred_id: str, nonce_hex: str, mac_hex: str, key: bytes) -> bool:
    """Cryptographic validity ONLY (mirrors HceReader::verifyProof).

    True means right key + untampered MAC + well-formed transcript. It
    does NOT mean fresh (see NonceStore) and NOT authorized.
    """
    try:
        nonce = bytes.fromhex(nonce_hex)
        mac = bytes.fromhex(mac_hex)
    except ValueError:
        return False
    if len(nonce) != NONCE_BYTES or len(mac) != MAC_BYTES:
        return False
    if not cred_id or len(cred_id.encode()) > 32 or len(key) != KEY_BYTES:
        return False
    expected = hmac.new(key, cred_id.encode() + nonce, hashlib.sha256).digest()
    return hmac.compare_digest(expected, mac)


class NonceStore:
    """Atomic per-credential single-use claim (the replay table).

    claim() returns True on first use, False on replay. The UNIQUE
    constraint makes check-and-insert atomic — concurrent duplicates
    cannot both succeed (docs/SECURITY.md §3).
    """

    def __init__(self, path=":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS seen_nonces("
            "credential_id TEXT NOT NULL, nonce_hex CHAR(32) NOT NULL, "
            "seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
            "PRIMARY KEY (credential_id, nonce_hex))")

    def claim(self, cred_id: str, nonce_hex: str) -> bool:
        try:
            with self.db:
                self.db.execute(
                    "INSERT INTO seen_nonces(credential_id, nonce_hex) VALUES(?,?)",
                    (cred_id, nonce_hex))
            return True
        except sqlite3.IntegrityError:
            return False  # replay


# --- Enrollment ----------------------------------------------------------------

def derive_ke(reader_secret: bytes, cred_id: str) -> bytes:
    return hmac.new(reader_secret, V2_ENC_LABEL + cred_id.encode(),
                    hashlib.sha256).digest()


def unwrap_key(reader_secret: bytes, cred_id: str, key_nonce_hex: str,
               wrapped_hex: str):
    """Returns the candidate K_cred, or None on bad shape / tag failure
    (wrong secret or any tampering — fail closed)."""
    try:
        raw = bytes.fromhex(wrapped_hex)
        key_nonce = bytes.fromhex(key_nonce_hex)
    except ValueError:
        return None
    if len(key_nonce) != WRAP_NONCE_BYTES or len(raw) != WRAP_NONCE_BYTES + KEY_BYTES + TAG_BYTES:
        return None
    if raw[:WRAP_NONCE_BYTES] != key_nonce:
        return None  # spliced wrap
    ke = derive_ke(reader_secret, cred_id)
    aad = V2_LABEL + cred_id.encode() + b"\n" + key_nonce_hex.encode()
    ct, tag = raw[12:44], raw[44:]
    return aead_decrypt(ke, key_nonce, aad, ct, tag)


def enroll(reader_secret: bytes, cred_id: str, nonce_hex: str, mac_hex: str,
           key_nonce_hex: str, wrapped_hex: str, store: dict):
    """Enrollment accept path. Returns the stored key.

    Order is mandatory: unwrap to a *candidate*, require the same tap's
    CHALLENGE proof under the candidate (proof of possession), and only
    then store/rotate. Raises ValueError otherwise.
    """
    candidate = unwrap_key(reader_secret, cred_id, key_nonce_hex, wrapped_hex)
    if candidate is None:
        raise ValueError("unwrap failed: wrong secret or tampered wrap")
    if not verify_proof(cred_id, nonce_hex, mac_hex, candidate):
        raise ValueError("proof of possession failed: key does not match credential")
    store[cred_id] = candidate  # rotate on re-enrollment
    return candidate
