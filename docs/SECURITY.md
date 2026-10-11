# RC522-HCE Security Model

Authoritative security contract for the RC522-HCE credential system
(protocol v2). The API reference (`API.md`) and wire spec
(`HCE_PROTOCOL.md`) describe *what* the bytes are; this document describes
*what is and is not guaranteed* and what deployers and backend authors must
do. When in doubt, this document wins.

> Scope: native unit tests (106 host-side, incl. RFC 8439 vectors) pin behavior, not security.
> They prove byte compatibility and fail-closed parsing — not resistance to
> offline guessing, relay, or implementation bugs. The next major milestone
> for high-assurance use is independent protocol and implementation review.

## 1. What a tap proves (three separate decisions)

Every accepted tap passes through three distinct checks owned by three
different parties. Do not conflate them.

| # | Decision | Owner | Question answered |
|---|---|---|---|
| 1 | Cryptographic validity | `verifyProof()` (any layer) | Does this MAC equal `HMAC-SHA256(K_cred, credId \|\| nonce)` for the claimed id? |
| 2 | Freshness + single-use | Backend nonce table, claimed **atomically** | Has this `(credentialId, nonce)` pair never been accepted before? |
| 3 | Authorization | Application policy | Given 1+2, is the requested operation allowed now? |

`verifyProof()` returning `true` means decision 1 only. It does **not** mean
the transcript is fresh, the holder is nearby, or the operation is
authorized. The same valid transcript verifies twice — replay rejection is
the backend's job (§3).

Physical MIFARE taps never reach decision 1: a UID is a compatibility
identifier (clonable, no cryptography). Treat it as a lower-assurance path,
never as equivalent to a verified HCE proof.

## 2. Key model

- `K_cred` is per credential, generated and stored by the phone (Android
  Keystore). The reader never holds it and verifies nothing.
- The server holds the only other copy per credential (HSM/KMS; never in
  logs). Its database is the trust root of the symmetric scheme.
- At enrollment the phone releases `K_cred` **once**, inside a
  holder-opened, single-release, short-lived window. The reader wraps it
  under its own secret and wipes the raw copy; the server unwraps,
  requires the same tap's CHALLENGE proof under the candidate (proof of
  possession), then stores/rotates.
- Revocation is key destruction server-side.

## 3. Replay: mandatory backend table, claimed atomically

The 16-byte challenge nonce **enables** replay detection; it is not replay
protection by itself.

Backend rule: maintain a per-credential set of seen `nonceHex` and reject
reused pairs. The check-and-claim must be **atomic** — a separate "check
nonce" followed by "insert nonce" races under concurrency and lets two
requests with the same transcript both pass. Use a unique constraint or
transaction, e.g.:

```sql
CREATE TABLE seen_nonces (
    credential_id TEXT NOT NULL,
    nonce_hex CHAR(16) NOT NULL,
    seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (credential_id, nonce_hex)
);
-- Accept path: verifyProof() first, then INSERT; on conflict => replay => reject.
```

```python
import hmac, hashlib
expected = hmac.new(cred_key, credential_id.encode() + bytes.fromhex(nonce_hex),
                    hashlib.sha256).digest()
if not hmac.compare_digest(expected, bytes.fromhex(mac_hex)):
    reject("bad-mac")
try:
    db.execute("INSERT INTO seen_nonces(credential_id, nonce_hex) VALUES(%s,%s)",
               (credential_id, nonce_hex))
except UniqueViolation:
    reject("replay")
authorize(...)
```

Order: verify MAC first (rejects forgeries without touching the table),
then claim the nonce, then authorize.

## 4. Nonces: 128-bit v2, randomness policy

Protocol v2 uses 16-byte (128-bit) challenge nonces and 12-byte key-wrap
nonces. For independent uniform 128-bit nonces after `n` challenges:

```text
P(collision) ≈ n(n-1) / 2^129
1M challenges ≈ 1.5e-27; 1B challenges ≈ 1.5e-21 — negligible at any
plausible fleet scale.
```

The length itself is no longer the binding constraint; the random source
is. Any future length change is a **versioned protocol migration** (phone
+ reader + backend + new test vector together), never an isolated constant
change. `PROTOCOL_VERSION == 2` pins the current wire format (v1's 8-byte
nonces were retired in 2.0.0).

### Randomness policy (production requirement)

| Platform | Source | Status |
|---|---|---|
| ESP32 | `esp_random()` (hardware RNG, driver default) | Approved |
| Other chips, hobby/dev | Portable auto-seeded Arduino PRNG fallback | Best-effort only, **not** approved for production credentials |
| Production on RNG-less chips | Explicitly injected `RandomWordFn` from an approved source (TRNG chip, secure element, reviewed radio-noise whitener) | **Required** |

```cpp
uint32_t myNoise() { /* approved source */ return ...; }
rc522hce::Rc522HceReader radio(10, 9, 13, 12, 11, &Serial,
                               rc522hce::Rc522HceOptions(), myNoise);
```

A predictable nonce collapses the freshness argument: refusals, replays,
and pre-play all get easier.

## 5. Enrollment wrap: ChaCha20-Poly1305 AEAD

v2 wrap seals `K_cred` with the vetted ChaCha20-Poly1305 AEAD (RFC 8439,
dependency-free implementation pinned against RFC vectors host-side):

```text
ke          = HMAC-SHA256(readerSecret, "pulse-hce-key-wrap/v2-enc\n" || credId)
aad         = "pulse-hce-key-wrap/v2\n" || credId || "\n" || keyNonceHex
(ct, tag)   = ChaCha20-Poly1305(ke, keyNonce, aad, K_cred)
wrappedHex  = keyNonceHex || hex(ct) || hex(tag)   (120 hex chars)
```

plus a CHALLENGE MAC under `K_cred` as proof of possession (binds key to
id, blocks overwriting another credential).

What the AEAD fixes vs v1's XOR-HMAC wrap: malleability is gone (any
modification fails the tag check), the wrap is bound to (credId, nonce) as
associated data, and a wrong secret fails closed at unwrap instead of
silently producing a wrong key. What it does **not** fix: a weak
`readerSecret` remains offline-guessable in principle (guess → derive →
trial-decrypt; the tag is the oracle), only slower than v1's MAC re-check.

Consequences (unchanged):

- `readerSecret` MUST be high-entropy (≥ `WRAP_SECRET_MIN_BYTES` = 16
  random bytes), unique **per device**, stored as a secret, never logged or
  baked into shared firmware images. Human passwords and the
  `"change-me-per-device"` / `"test-secret-…"` placeholders never qualify.
- A secret shared across N readers is a blast-radius multiplier:
  compromising one device or config exposes enrollment traffic from all of
  them. Prefer per-device secrets or a managed key-encryption service.
- v1 (XOR-HMAC wrap) was retired in 2.0.0 — no v1 wrap code remains.

Server unwrap order (mandatory): derive candidate → require the same tap's
CHALLENGE proof under the candidate → only then store/rotate. The library
exposes both directions (`wrapKeyHex` / `unwrapKeyHex`) so backends share
one implementation instead of hand-rolling the pad.

## 6. What a valid MAC does not prove

- **Not proximity.** A valid MAC proves possession of `K_cred` (assuming
  the key is protected and all three sides implement the protocol
  correctly). It does not prove the phone is next to the reader: NFC
  exchanges can be relayed to a phone elsewhere. Settle windows, RX gain,
  and WTX handling are communication reliability, not distance bounding.
  Acceptable for hobby/classroom/controlled prototypes; explicit limitation
  for valuable assets or high-assurance access.
- **Not reader authenticity.** Phones do not authenticate the reader
  (unilateral authentication, reader-chosen nonce). A skimmed transcript
  can be pre-played once before the credential's next legitimate tap; the
  nonce table refuses it after first use.
- **Not key confidentiality at enrollment.** `K_cred` crosses NFC in clear
  once, inside the holder-opened window. Mitigations: short single-use
  window, immediate wrap-and-wipe, re-enrollment rotates.

## 7. Operational checklist

- [ ] `selfCheckVector()` passes before hardware debug; new phone/backend
      ports recompute the vector independently.
- [ ] Backend: `verifyProof()` → atomic nonce claim → authorize; constant-time
      compare; reject empty/>32-B ids before DB lookup.
- [ ] `readerSecret`: per-device CSPRNG output, stored securely, rotated on
      suspicion; enrollment armed only by operator action, disarmed after.
- [ ] RNG: ESP32 default or injected approved source in production.
- [ ] `healthy() == false` surfaces "radio degraded", never "system OK".
- [ ] Heap stability measured over long tap loops incl. failures/enrollment
      on the target board; keys/buffers wiped on every exit path (the
      driver wipes raw keys, ENROLL frames, pads, and MAC message buffers).
- [ ] Physical-UID policy documented as lower-assurance; no application
      treats a UID as equivalent to a verified proof.
- [ ] Independent review scheduled before high-assurance deployment.

## 8. Allocation discipline (embedded)

- Facade strings (`credentialId`, hex transcripts) are acceptable at the
  application layer (HTTP/JSON integration).
- Hot-path protocol bytes use caller-owned buffers and explicit capacities;
  builders return `0` instead of truncating; parsers are exact-length.
  Nonce/MAC/wrapped-key sizes are fixed (8/32/32 B) — no unbounded storage
  internally.
- Measure before optimizing: profile heap over prolonged operation on the
  target; extend the buffer discipline inward only if allocation proves to
  be a real problem.
