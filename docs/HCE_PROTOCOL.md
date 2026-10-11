# HCE Credential Protocol (v2 — per-credential keys, PROTOCOL_VERSION 2)

> Wire stability: v2 bytes are frozen. Any future incompatible change ships
> as a versioned v3 with its own test vector — phone, reader, and backend
> migrate together. v1 (8-byte nonces, XOR-HMAC wrap) was retired in 2.0.0.
> See `SECURITY.md`.

Phone-as-credential over NFC for any microcontroller + RC522. Deliberately
tiny: two APDUs per tap, plus a third, one-time APDU (ENROLL) at enrollment.

> **Key model.** The SELECT and CHALLENGE bytes never change. What matters
> is the key: there is **no shared secret anywhere**. Every phone credential
> has its own 256-bit key, stored in that phone's secure storage; the server
> holds the only other copy. The **reader holds no HCE key and verifies
> nothing**: it relays its nonce and the phone's MAC, and **the server
> verifies** them with that credential's key. Additive pieces are the
> `ENROLL` APDU (enrollment only) and the `6A88` status word (no key on
> the phone).

```text
NFC-A
  ↓  anticollision + SELECT (SAK bit 6 set => T=CL supported)
ISO-DEP (ISO/IEC 14443-4)
  ↓  RATS / ATS, I-blocks via the MFRC522 driver
APDU
  ↓  SELECT AID -> CHALLENGE [-> ENROLL, enrollment only]
Application identity
  ↓  credential_id + nonce + mac (+ wrapped key at enrollment) → server
Server
  ↓  HMAC-SHA256(K_cred, credId || nonce) == mac ? (constant time, nonce single-use)
```

No MIFARE Classic anywhere on this path: Android HCE cannot emulate it, so
the phone presents an ISO-DEP target instead. Physical cards keep their own
untouched path (RF UID).

## RF layer

| Layer | Detail |
|---|---|
| RF | NFC-A, 106 kbit/s |
| Anticollision | Standard cascade SELECT; SAK `0x20` = ISO-DEP (HCE) target |
| Activation | RATS → ATS; no PPS (106 kbit/s is mandatory and plenty for <70 B exchanges) |
| Framing | ISO-DEP I-blocks, CID = 0, no NAD |
| Limits | RC522 FIFO = 64 B, so one I-block carries ≤ ~57 B of APDU payload |
| Driver | `MFRC522Extended` (same `MFRC522` Arduino library, no extra dependency) |

## Application layer

- Phone AID: **`F0010203040506`** (7 bytes, proprietary `F…` category).
- Credential id: variable-length ASCII, 1–32 bytes.
- Challenge nonce: 16 bytes (128-bit), fresh per tap (`esp_random` on ESP32;
  approved CSPRNG required in production — see `SECURITY.md`).
- **The phone's NFC UID is random per tap on Android HCE** — the reader
  logs only its length (discovery proof) and NEVER uses it as identity.
  The server never receives it.

## APDU 1 — SELECT AID

Request (12 bytes, `Le` omitted):

```text
CLA | INS | P1 | P2 | Lc | AID (7 bytes)
 00 | A4  | 04 | 00 | 07 | F0 01 02 03 04 05 06
```

Response, AID matched:

```text
48 43 45 2D 4F 4B ("HCE-OK") | 90 00
```

Response, AID not matched: `6A 82`. Session becomes "selected" only on
match; it resets on RF deactivation.

## APDU 2 — CHALLENGE (challenge-response)

Request (21 bytes, `Le` omitted):

```text
CLA | INS | P1 | P2 | Lc | nonce (16 bytes, fresh per tap)
 80 | 10  | 00 | 00 | 10 | NN NN NN NN NN NN NN NN NN NN NN NN NN NN NN NN
```

Response:

```text
credLen (1) | credId (1-32, ASCII) | HMAC-SHA256 (32) | 90 00
MAC = HMAC-SHA256(key = K_cred, msg = credId || nonce)
```

`K_cred` is **this credential's own key**. A phone with no usable key
answers **`6A88`** instead of a MAC.

The reader does **not** verify the MAC — it has no key. It sends the
credential id, its own nonce (32 hex) and the phone's MAC (64 hex) to the
server, which recomputes the MAC with that credential's stored key,
compares in constant time, and claims each nonce atomically (unique
constraint) — replay if already seen. Validity, freshness, and
authorization are three separate decisions (see `SECURITY.md` §1).
The nonce and MAC are safe to log; key material never is.

## APDU 3 — ENROLL (enrollment only, one-time key hand-off)

Sent by a reader in **enrollment mode only**, right after CHALLENGE in the
same session. Request (5 bytes):

```text
CLA | INS | P1 | P2 | Le
 80 | 20  | 00 | 00 | 20
```

Response, only while the holder has opened the phone's **enrollment
window**, and **only once** per window:

```text
K_cred (32) | 90 00          (34 bytes: fits one RC522 I-block)
```

Otherwise `6985` (window closed, expired, already released, or not
SELECTed).

The reader never sends `K_cred` in clear over the network. It seals it
with the ChaCha20-Poly1305 AEAD (RFC 8439) under a key derived from its
own secret, with a fresh 12-byte nonce per enrollment:

```text
ke          = HMAC-SHA256(readerSecret, "pulse-hce-key-wrap/v2-enc\n" || credId)
key_nonce   = 24 hex chars = 12 fresh random bytes
aad         = "pulse-hce-key-wrap/v2\n" || credId || "\n" || key_nonce
(ct, tag)   = ChaCha20-Poly1305(ke, key_nonce, aad, K_cred)
key_wrapped = key_nonce || hex(ct) || hex(tag)   (120 hex chars)
```

The server unwraps with `unwrapKeyHex` (tag failure = wrong secret or any
tampering → 0, fail closed), requires the same tap's CHALLENGE proof to
verify under the candidate (proof of possession — mandatory, never store
first), then stores it. The raw key is wiped from the reader's RAM right
after wrapping and is never logged. `readerSecret` must still be
high-entropy and per-device (see `SECURITY.md` §5).

## Shared test vector (pin in every implementation)

| Item | Value |
|---|---|
| `K_cred` | `000102…1f` (bytes 0..31) |
| `credId` | `PLS-K3Y7V3CT0R5Z` |
| `nonce` | `000102030405060708090a0b0c0d0e0f` (16 bytes) |
| `MAC` | `70f32d7b458139d8f5f522a7314c31205eca50619a5d26dc466d7d5b60aab154` |
| CHALLENGE response | `10` `504c532d4b335937563343543052355a` `70f3…b154` `9000` |
| `readerSecret` | `test-secret-000000000000000001` |
| `key_nonce` | `000102030405060708090a0b` (12 bytes) |
| `key_wrapped` | `000102030405060708090a0b` `d525…99ee` `6974…6530e` (24 + 64 + 32 hex; full value in `TestVector`) |

Computed outside every implementation (Python `hmac`); pinned in
`test/test_hce_apdu.cpp` and `test/test_hce_crypto.cpp`. Each suite also
pins RFC 4231 HMAC vectors. Verify a new phone app or server against this
table before debugging on hardware.

## Status words

| SW | Meaning | When |
|---|---|---|
| `9000` | Success | SELECT matched / CHALLENGE answered |
| `6A82` | App not found | SELECT with any other AID |
| `6985` | Conditions not satisfied | CHALLENGE/ENROLL before SELECT; ENROLL with no open enrollment window |
| `6A88` | Referenced data not found | CHALLENGE on a phone with no usable key |
| `6700` | Wrong length | `Lc` ≠ 7 (SELECT) / ≠ 8 (CHALLENGE), ENROLL with data, truncated APDU |
| `6D00` | INS unknown | Known CLA, unknown instruction |
| `6E00` | CLA unknown | First byte not `00`/`80` |

## Maximum lengths

| Item | Max |
|---|---|
| SELECT request | 13 bytes (with optional Le) |
| SELECT response | 8 bytes |
| CHALLENGE request | 22 bytes (21 + optional Le) |
| CHALLENGE response | up to 67 bytes (1 + 32 + 32 + 2) |
| ENROLL request / response | 5 bytes / 34 bytes |

## Reader diagnostics

`HCE SELECT failed` (no I-block reply) · `HCE SELECT rejected (unknown
AID)` (`6A82`) · `HCE CHALLENGE timeout` · `HCE phone has NO key yet
(6A88)` · `HCE CHALLENGE answer malformed` · `HCE ENROLL refused`
(enrollment: the phone's window is not open). A wrong key is no longer a
reader-side error: the tap reaches the server and is refused there.

Every status word on the wire is decodable from the public API —
`HceReader::statusWordName(sw1, sw2)` returns the operator-facing text
(`9000`, `6A82`, `6A88`, `6985`, `6700`, `6D00`, `6E00`), so applications
do not hardcode their own table of these.

Protocol builders, parsers, the HMAC/key-wrap primitives and the backend
verification of a relayed proof are all part of the public API (see
"API at a glance" in the README); this document is the byte-level
reference they implement. Every failure releases the target and the
device stays responsive; MIFARE taps are never affected (that path never
runs for ISO-DEP targets, and vice versa).

## Timing facts the driver encodes

- Discovery uses anticollision + SELECT with **no RATS and no HaltA**:
  once a phone controller is HaltA'd it answers nothing until field
  re-entry, so every post-halt retry is aimed at a corpse.
- An ISO-DEP sighting parks the untouched selected session for **400 ms
  of radio silence** before the tap's first RATS (the phone's controller
  needs boot time after field entry).
- The driver transmits with a **5 ms RX window** (below the phone's
  fastest measured answer, ~13 ms) so late answers stay in the FIFO for
  the S(WTX)-aware salvage path; the stock 25 ms window is restored for
  the MIFARE path.
- Most taps answer `S(WTX)` ("I need more time") before the real answer:
  the driver grants it and keeps waiting, up to 4 rounds.

## Security boundaries

**Guaranteed (when the backend follows `SECURITY.md`)**
- No shared HCE secret: dumping one app, one reader or one config file
  yields no key that works for any other credential.
- A phone key authenticates only its own credential id (the id is inside
  the MAC, and the server looks the key up by that id).
- Readers cannot forge phone taps: a valid reader message without a
  valid phone proof is refused by `verifyProof()`.
- Replayed transcripts are refused by the backend's atomic
  per-credential nonce table (`verifyProof()` alone verifies twice — it
  never rejects replays by itself).
- Revocation (lost/stolen phone) destroys the server key.
- Enrollment cannot overwrite another credential: only the credential
  being enrolled is accepted (proof-of-possession under the candidate),
  and re-enrollment rotates the key.

**Documented limits (not solved here — see `SECURITY.md` §§4–6)**
- 128-bit v2 nonces with an approved source: collision probability is
  negligible (≈ 1.5e-21 at one billion challenges). Predictable nonces
  still collapse the freshness argument — production on RNG-less chips
  must inject an approved source.
- v2 key wrap is ChaCha20-Poly1305: wrong secrets and any tampering fail
  closed at unwrap (tag check); the wrap is bound to (credId, nonce) as
  associated data. A guessable `readerSecret` remains offline-guessable
  in principle, and a shared secret multiplies blast radius — high-entropy
  per-device secrets are still required.
- Unilateral authentication, reader-chosen nonce: a skimmed transcript
  can be presented once (pre-play) before the phone's next legitimate
  tap. The server refuses it after first use.
- A valid MAC is not proximity proof: relays are out of scope; RF tuning
  is reliability, not distance bounding.
- The key crosses NFC in clear **once**, during the holder-opened,
  single-release enrollment window. Mitigation: the window is short and
  single-use, and re-enrollment rotates the key.
- The server is the trust root: its database exposes every phone key
  (symmetric scheme).
- Physical MIFARE UIDs still have no cryptography (clonable) — a
  lower-assurance compatibility path, never equivalent to a verified
  HCE proof.
