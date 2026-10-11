# Changelog

All notable changes to this library, in Keep a Changelog format. Versioned
with Semantic Versioning: wire/protocol breaks need a major bump and a
versioned migration (`docs/MIGRATION.md`). The CD workflow releases the
notes under the matching `## [x.y.z]` section when a version is pushed.

## [Unreleased]

### Added

- Fuzz targets for every wire parser (`fuzz/`, libFuzzer + ASan, CI
  60 s each) with seed corpus; null-safety, base-default, and
  prologue-only regression tests (109 native tests, 98% line coverage).
- ASan/UBSan (`native-san`) and coverage-gate (`native-cov`, 90% lines)
  test environments; on-device HIL suite (`test/test_hil_radio.cpp`,
  `esp32test` env) compile-checked in CI, runnable with a wired board.
- Tested zero-dependency Python reference backend
  (`extras/reference-backend/`: verify + atomic SQLite replay table +
  proof-of-possession enrollment, shared vector + RFC 8439 pins).
- `docs/MIGRATION.md` (v1→v2), `keywords.txt`, `CODE_OF_CONDUCT.md`,
  Arduino Lint + zizmor in CI, SHA-pinned Actions, `SECURITY.md`
  reporting channel with private vulnerability reporting enabled.

## [2.0.0] - 2026-10-11

### Changed (breaking — migrate phone + reader + backend together, see `docs/MIGRATION.md`)

- Protocol v2: 16-byte challenge nonces (`CHALLENGE` is now 21 bytes,
  `Lc = 0x10`); `nonceHex` 16 → 32 hex chars.
- Enrollment wrap is now ChaCha20-Poly1305 AEAD (RFC 8439,
  dependency-free): 120-hex output (24 nonce + 64 ct + 32 tag); wrong
  secrets and any tampering fail closed at unwrap. v1 XOR-HMAC wrap
  retired. `keyNonceHex` 32 → 24 hex chars.
- New pinned interop vector (`PROTOCOL_VERSION = 2`).

### Added

- Typed `CredentialKind` enum + `NfcReader::kind()`; `lastKind()` kept as
  a deprecated string shim; `Tap` gains `kind` (`isHce` stays as mirror).
- `unwrapKeyHex` server mirror, `chacha20Block`,
  `chacha20Poly1305Encrypt`/`Decrypt`, `AEAD_*_LEN`, `protocolVersion()` /
  `keyWrapVersion()`, all reachable from `HceReader.h`.
- `docs/SECURITY.md`: authoritative threat model (replay must be an atomic
  backend claim, production RNG policy, per-device secrets, relay limits).
- Fuzz targets (`fuzz/`, libFuzzer, CI 60 s each), ASan/UBSan test env,
  on-device HIL suite (`test/test_hil_radio.cpp`), RFC 8439 vectors in
  the native suite (106 tests).

## [1.2.0] - 2026-10-11

### Added

- Build-flag/board-preset configuration without source edits
  (`Rc522HceConfig.h`), runtime AID override (`setAid`), `CompatNames.h`
  legacy-alias layer, full API reference (`docs/API.md`).

## [1.1.0] - 2026-10-11

### Added

- Whole protocol surface re-exported from `HceReader.h` (one-header API):
  AID, lengths, status words, hex helpers, backend `verifyProof`, shared
  interop test vector.

## [1.0.0] - 2026-10-10

### Added

- Initial release: RC522 + Android-HCE identification over ISO-DEP
  (SELECT AID + HMAC-SHA256 challenge-response), enrollment key wrap,
  tap debounce, mock transport, host-side Unity suite.
