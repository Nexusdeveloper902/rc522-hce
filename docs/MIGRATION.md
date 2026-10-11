# Migration guide: v1 → v2

v2.0.0 changes the wire format. Phone app, reader firmware, and backend
must migrate **together** — a v1 phone cannot talk to a v2 reader and a
v2 wrap cannot be unwrapped by v1 server code. There is no mixed-mode:
flash/update all three sides, then re-verify against the new vector
(`HceReader::selfCheckVector()`, `docs/API.md` §13).

## What changed on the wire

| Item | v1 | v2 |
|---|---|---|
| `CHALLENGE` request | `80 10 00 00 08` + 8 B (13 B) | `80 10 00 00 10` + 16 B (21 B) |
| `NONCE_LEN` / `nonceHex` | 8 B / 16 hex | 16 B / 32 hex |
| `KEY_NONCE_LEN` / `keyNonceHex` | 16 B / 32 hex | 12 B / 24 hex |
| `keyWrappedHex` | 64 hex (XOR-HMAC pad) | 120 hex (24 nonce + 64 ct + 32 tag, ChaCha20-Poly1305) |
| `CHALLENGE` response shape | unchanged (`len + credId + MAC + 9000`) | unchanged |
| `SELECT` / `ENROLL` APDUs | unchanged | unchanged |
| `PROTOCOL_VERSION` / `KEY_WRAP_VERSION` | 1 / 1 | 2 / 2 |

## Per-side checklist

**Phone app**
- Send 16-byte nonces in `CHALLENGE` (was 8); parse `Lc == 0x10`.
- Nothing else changes on the phone path (SELECT/ENROLL/CHALLENGE
  response bytes are identical in shape).
- Re-verify: recompute the new vector MAC
  (`HMAC-SHA256(000102…1f, "PLS-K3Y7V3CT0R5Z" || 000102…0f)` must equal
  `70f3…b154`) before field testing.

**Reader firmware**
- Rebuild against v2.0.0 — `buildChallenge` now emits 21 B; the driver's
  command buffer was enlarged accordingly. No application-code changes
  needed (`reader.read(tap, millis())` is unchanged).
- `tap.proof.nonceHex` is now 32 hex chars; any fixed-width parsing,
  logging columns, or POST schemas assuming 16 must be widened.
- Enrollment taps now carry 120-char `keyWrappedHex` + 24-char
  `keyNonceHex` (were 64 + 32).

**Backend**
- Nonce columns widen: `nonce_hex CHAR(16)` → `CHAR(32)`; replay-table
  unique constraint stays `(credential_id, nonce_hex)`.
- Replace the v1 unwrap (HMAC-pad XOR) with `unwrapKeyHex` semantics:
  **behavior change** — a wrong secret or any tampering now returns
  failure (`0` / exception) instead of silently yielding a wrong key.
  Server code that unwrapped-then-compared must now treat unwrap failure
  as reject (the proof-of-possession check stays mandatory regardless).
- Python reference: `extras/reference-backend/hce_verify.py` implements
  the v2 flow with zero dependencies.
- Re-verify: `wrapKeyHex(kReaderSecret, kCredId, kKeyNonceHex, key)` must
  equal the new `kKeyWrappedHex`; `unwrapKeyHex` must recover `kKeyHex`
  and return `0` for a wrong secret or flipped byte.

## API changes (all backward compatible in v2.0.0)

- Added: `CredentialKind` enum + `NfcReader::kind()` (preferred);
  `lastKind()` string kept as a deprecated shim, `Tap` gains `kind`
  with `isHce` as convenience mirror.
- Added: `unwrapKeyHex`, `chacha20Block`, `chacha20Poly1305Encrypt` /
  `Decrypt`, `AEAD_*_LEN`, `protocolVersion()` / `keyWrapVersion()`.
- Removed: nothing except the v1 wire bytes and v1 wrap construction.
