# RC522-HCE API Reference

Complete reference for the RC522-HCE library (v1.2.0): Android-HCE
phone-as-credential identification over ISO-DEP, plus the untouched
MIFARE Classic UID path, as a reusable Arduino / PlatformIO library.

> **Start here if you just want to read taps:** [`HceReader`](#1-hcereader--src_hcereaderh--the-facade)
> — `reader.begin()` once, then `reader.read(tap, millis())` per loop.
> Everything else in this document is a layer below that.
>
> Companion documents:
> [`HCE_PROTOCOL.md`](HCE_PROTOCOL.md) (byte-level wire spec),
> [`WIRING.md`](WIRING.md) (pins, power, tap distance),
> [`../README.md`](../README.md) (install + 30-second example).

- [Architecture](#architecture)
- [1. `HceReader` (`src/HceReader.h`) — the facade](#1-hcereader--srchcereaderh--the-facade)
- [2. `HceProtocol` (`src/HceProtocol.h` / `.cpp`) — wire + crypto](#2-hceprotocol--srchceprotocolh--cpp--wire--crypto)
  - [2.1 Constants](#21-protocol-constants)
  - [2.2 APDU builders](#22-apdu-builders)
  - [2.3 Response classifiers / parsers](#23-response-classifiers--parsers)
  - [2.4 Crypto primitives](#24-crypto-primitives)
  - [2.5 Hex helpers](#25-hex-helpers)
  - [2.6 Backend verification](#26-backend-verification-verifyproof)
  - [2.7 Status words](#27-status-words-statuswordname)
  - [2.8 Shared interop test vector](#28-shared-interop-test-vector-testvector)
  - [2.9 ISO-DEP / RF helpers](#29-iso-dep--rf-helpers-pure)
- [3. `NfcReader` + `HceProof` (`src/NfcReader.h`) — the transport contract](#3-nfcreader--hceproof--srcnfcreaderh--the-transport-contract)
- [4. `Rc522HceReader` (`src/Rc522HceReader.h`) — the radio driver](#4-rc522hcereader--srcrc522hcereaderh--the-radio-driver-device-only)
- [5. `Rc522HceConfig.h` — build-flag configuration](#5-rc522hceconfigh--build-flag-configuration-no-source-edits)
- [6. `CardDebouncer` (`src/CardDebouncer.h`)](#6-carddebouncer--srccarddebouncerh)
- [7. `MockNfcReader` (`src/MockNfcReader.h`)](#7-mocknfcreader--srcmocknfcreaderh)
- [8. `TsLog` (`src/TsLog.h`)](#8-tslog--srctslogh-device-only)
- [9. `CompatNames.h` — legacy aliases](#9-compatnamesh--legacy-aliases-migration-only)
- [10. Return-code and error conventions](#10-return-code-and-error-conventions)
- [11. Backend integration guide](#11-backend-integration-guide-server-side)
- [12. Enrollment lifecycle](#12-enrollment-lifecycle)
- [13. Interop checklist (new phone app / new backend)](#13-interop-checklist-new-phone-app--new-backend)
- [14. Custom transports (implementing `NfcReader`)](#14-custom-transports-implementing-nfcreader)
- [15. Troubleshooting map (log line → meaning → fix)](#15-troubleshooting-map-log-line--meaning--fix)
- [16. Header include map](#16-header-include-map)

All symbols live in namespace `rc522hce` unless noted.
Headers use `#pragma once`. Pure-C++ headers (`HceReader.h`,
`HceProtocol.h`, `NfcReader.h`, `CardDebouncer.h`, `MockNfcReader.h`)
compile on the host (`pio test -e native`); `Rc522HceReader.h` and
`TsLog.h` need an Arduino core + the MFRC522 Arduino library.

---

## Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│ HceReader (src/HceReader.h)          FACADE — your app       │
│   read(tap, millis()) → exactly one event per physical tap  │
│   + debounce + enrollment forwarding + static API surface   │
└──────────────┬──────────────────────────────────────────────┘
               │ owns an NfcReader&
┌──────────────▼──────────────────────────────────────────────┐
│ NfcReader (src/NfcReader.h)          INTERFACE               │
│   poll(idOut) / lastKind() / lastProof() / setEnrollment()  │
│   / healthy() / label() / aid() / setAid()                  │
└───┬───────────────────────────────────────────┬─────────────┘
    │                                           │
┌───▼──────────────────────────────┐ ┌──────────▼────────────┐
│ Rc522HceReader                   │ │ MockNfcReader         │
│ (device only, SPI + MFRC522 +    │ │ (host + device,       │
│  SELECT/CHALLENGE/ENROLL,        │ │  pushTap() then       │
│  RATS/WTX/salvage/resync)        │ │  poll() — no hardware)│
└──────────────────────────────────┘ └───────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│ HceProtocol (HceProtocol.h/.cpp)   PURE C++ — the contract   │
│   APDU builders/parsers + SHA-256/HMAC + key-wrap +         │
│   verifyProof + hex + status words + TestVector +            │
│   ISO-DEP frame predicates (sakPromisesIsoDep, stripIBlock…) │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│ CardDebouncer │ TsLog │ Rc522HceConfig │ CompatNames (opt.)  │
└─────────────────────────────────────────────────────────────┘
```

**Two credential paths, one `poll()` / `read()`** (both layers agree):

| Path | Source of identity | `lastKind()` / `tap.isHce` | `proof` |
|---|---|---|---|
| `physical` | MIFARE Classic UID off the RF layer, uppercase hex | `"physical"` / `false` | cleared (empty) |
| `hce` | Application exchange `SELECT AID → CHALLENGE → len+credId+MAC+9000`; RF UID ignored (Android randomizes it per tap) | `"hce"` / `true` | `nonceHex` + `macHex` relayed; `keyWrappedHex` + `keyNonceHex` only on enrollment taps |

---

## 1. `HceReader` (`src/HceReader.h`) — the facade

The only header a normal app or server needs. It wraps any `NfcReader`
transport plus tap debouncing, and re-exports the whole protocol
surface (AID, lengths, status words, hex, backend verification, test
vector) so `#include <HceReader.h>` is sufficient.

```cpp
#include <HceReader.h>
```

### 1.1 `struct HceReader::Tap`

One identified tap. `proof` carries the server-bound relay data.

```cpp
struct Tap {
    std::string credentialId;  // MIFARE hex UID, or the HCE application id
    bool isHce = false;        // true => identity came from the APDU exchange
    HceProof proof;            // relay transcript (meaningful only when isHce)
};
```

| Field | Set when | Contents |
|---|---|---|
| `credentialId` | every accepted tap | `physical`: uppercase hex UID (e.g. `"04A3B2C1"`); `hce`: ASCII app id (e.g. `"PLS-K3Y7V3CT0R5Z"`, 1–32 bytes) |
| `isHce` | every accepted tap | `true` iff `transport.lastKind() == "hce"` |
| `proof` | `isHce` taps | `nonceHex` (16 hex) + `macHex` (64 hex); enrollment taps additionally `keyWrappedHex` (64 hex) + `keyNonceHex` (32 hex). Cleared for physical taps. |

### 1.2 Construction

```cpp
explicit HceReader(NfcReader& reader, uint32_t debounceMs = 2000);
```

| Parameter | Meaning |
|---|---|
| `reader` | Transport: `Rc522HceReader` on device, `MockNfcReader` in dev/tests. **Must outlive** the `HceReader` (stored by reference). |
| `debounceMs` | Re-tap cooldown for the *same id re-presented after an absence*. A card **resting** on the antenna never re-fires regardless of this value; a **different** id is accepted immediately. Default `2000`. Overridable per build with `-DRC522HCE_DEBOUNCE_MS=…`. |

```cpp
rc522hce::Rc522HceReader radio;      // device transport
rc522hce::HceReader reader(radio);   // or HceReader(radio, 1500)
```

### 1.3 `begin()`

```cpp
bool begin();  // forwards to transport
```

Initializes the underlying hardware. Returns `false` when init fails
(wiring / power — the radio driver logs the pin check). Mock always
returns `true`.

```cpp
if (!reader.begin()) {
    Serial.println("RC522 not responding — check wiring + 3.3 V");
}
```

### 1.4 `read()`

```cpp
bool read(Tap& out, uint32_t nowMs);
```

Poll once per loop. Returns `true` **exactly once per physical tap**
and fills `out`; returns `false` otherwise (no credential, resting
card, or cooldown).

- Pass the current `millis()` on device; scripted timestamps in tests.
  Wrap-safe (`nowMs - lastAccepted` unsigned arithmetic, ~49.7-day wrap).
- **Call unconditionally every loop iteration.** The `false` path is
  what notices the card left (`debouncer_.markAbsent()`), which is what
  arms the next deliberate re-tap.
- On `true` with `isHce == false`, `proof` is cleared — never trust a
  stale proof from a previous HCE tap.

```cpp
void loop() {
    rc522hce::HceReader::Tap tap;
    if (reader.read(tap, millis())) {
        if (tap.isHce) {
            // POST tap.credentialId + tap.proof.nonceHex + tap.proof.macHex
        } else {
            // tap.credentialId is the uppercase hex UID
        }
    }
}
```

Debounce semantics (implemented by `CardDebouncer`, §6):

1. Different id → accept immediately.
2. Same id, never absent since accept → suppress (resting card).
3. Same id, absent seen, cooldown elapsed → accept (deliberate re-tap).

`setEnrollment()` and `setAid()` reset the debouncer, so a mode/AID
switch never eats the next tap.

### 1.5 `setEnrollment()`

```cpp
void setEnrollment(bool on, const std::string& wrapSecret = std::string());
```

Enrollment mode on/off. Forwards to the transport and resets debounce.

- `on == true`: the next HCE taps also send `ENROLL` after `CHALLENGE`,
  fetching the phone's key once and wrapping it with `wrapSecret`
  (**this reader's secret**) into `proof.keyWrappedHex` /
  `proof.keyNonceHex`. The raw key never leaves the driver unwrapped.
- `on == false` (default): normal taps never ask a phone for its key.
- `wrapSecret` is held only while enrolling; passing `on == false`
  clears it. **Never log it.**

```cpp
reader.setEnrollment(true, readerSecret);
// … next tap carries tap.proof.keyWrappedHex / keyNonceHex …
reader.setEnrollment(false);   // back to normal
```

See §12 for the full lifecycle and §11.3 for server-side unwrapping.

### 1.6 `healthy()`, `label()`

```cpp
bool healthy() const;       // transport's last probe answered?
const char* label() const;  // e.g. "RC522 (SPI) + HCE", "MOCK (host input)"
```

`healthy() == false` means the radio stopped answering (failed init or
runtime death); the radio driver is already retrying on its reinit
cadence — use this to show a degraded state, not to reboot:

```cpp
if (!reader.healthy()) {
    Serial.println(F("Reader degraded — retrying…"));
    delay(1000);
}
```

### 1.7 AID accessors (instance)

```cpp
const uint8_t* selectedAid() const;  // AID this reader SELECTs
size_t selectedAidLen() const;
bool setAid(const uint8_t* aid, size_t len);  // 1..MAX_AID_LEN, else false
```

Runtime AID override — no reflash, no source edit. The phone app must
serve the same AID; changing it breaks already-deployed apps, so treat
it as a deployment-time decision, not a per-tap knob. `setAid()`
returns `false` and keeps the previous AID on `nullptr` / length
`0` / length `> MAX_AID_LEN (11)`. A successful change resets
debounce.

```cpp
const uint8_t myAid[] = {0xD1, 0x76, 0x00, 0x00, 0x85};
if (!reader.setAid(myAid, sizeof(myAid))) { /* rejected */ }
```

### 1.8 `transport()`

```cpp
NfcReader& transport();  // direct access for advanced use
```

Escape hatch for `poll(id)` + `lastKind()` / `lastProof()`,
`lastVersion()` (radio only), `setLog()` (radio only). Prefer `read()`
unless you need the lower layers directly.

### 1.9 Static protocol surface (all via `HceReader::`)

Every call below is a thin inline forward to `HceProtocol.h`; the
driver is optional, the protocol is the contract.

| Static call | Returns / does | Canonical value |
|---|---|---|
| `HceReader::aid()` | `const uint8_t*` — AID the phone's HCE app must serve | `F0 01 02 03 04 05 06` |
| `HceReader::aidLen()` | `size_t` | `7` |
| `HceReader::nonceLen()` | challenge nonce bytes | `8` |
| `HceReader::macLen()` | HMAC-SHA256 bytes | `32` |
| `HceReader::minCredentialLen()` | min credential-id bytes | `1` |
| `HceReader::maxCredentialLen()` | max credential-id bytes | `32` |
| `HceReader::keyLen()` | per-credential key bytes | `32` |
| `HceReader::statusWordName(sw1, sw2)` | `const char*` operator text, or `nullptr` when unrecognized (§2.7) | — |
| `HceReader::verifyProof(proof, credId, credKey)` | backend check of a relayed proof, constant-time (§2.6) | `bool` |
| `HceReader::verifyProof(credId, nonceHex, macHex, credKey)` | lower-level form, straight from the wire | `bool` |
| `HceReader::toHex(data, len)` | lowercase hex `std::string` | — |
| `HceReader::fromHex(hex, out, cap)` | bytes written; `0` on bad hex / short buffer (§2.5) | — |
| `HceReader::selfCheckVector()` | `true` when the shared interop vector verifies (§2.8) | `bool` |
| `TestVector::*` | pinned vector: credId, key, nonce, MAC, reader secret, wrapped key | — |

```cpp
// Backend, holding the 32-byte key for tap.credentialId:
if (!rc522hce::HceReader::verifyProof(tap.proof, tap.credentialId, credKey)) {
    // reject — wrong key, tampered MAC, replayed or impossible transcript
}

// Prove a new phone app / backend matches before touching hardware:
if (!rc522hce::HceReader::selfCheckVector()) { /* crypto mismatch */ }
```

---

## 2. `HceProtocol` (`src/HceProtocol.h` / `.cpp`) — wire + crypto

Pure C++ (no Arduino headers). Every builder, parser, crypto primitive
and ISO-DEP frame helper is host-testable (`pio test -e native`). The
RF transport (RATS/ATS, I-blocks, WTX) lives in `Rc522HceReader`, which
owns the MFRC522 driver.

Include directly only for custom transports / backends:

```cpp
#include <HceProtocol.h>   // or just <HceReader.h> — it re-exports all of this
```

### 2.1 Protocol constants

```cpp
static const uint8_t AID[] = {0xF0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
static const size_t AID_LEN = sizeof(AID);   // 7

static const uint8_t CLA_PROTO = 0x00;  // SELECT AID
static const uint8_t INS_SELECT = 0xA4;
static const uint8_t CLA_AUTH = 0x80;   // auth commands
static const uint8_t INS_CHALLENGE = 0x10;
static const uint8_t INS_ENROLL = 0x20; // one-time key hand-off (pairing only)

static const size_t NONCE_LEN = 8;      // reader challenge length
static const size_t HMAC_LEN = 32;      // HMAC-SHA256 length
static const size_t MAX_CRED_LEN = 32;  // longest credential id accepted
static const size_t KEY_LEN = 32;       // per-credential HMAC key
static const size_t KEY_NONCE_LEN = 16; // key-wrap nonce (32 hex chars)

static const size_t MAX_AID_LEN = 11;   // SELECT frame fits 16-B cmd buffer
static const size_t MIN_ISO_DEP_FRAME = 5;
```

Notes:

- Proprietary `'F'`-category AID: valid, collides with nothing
  production. **Changing it breaks every installed phone app.**
- RC522 FIFO = 64 B: every message fits one I-block (~57 B INF), so no
  phone-side chaining is ever needed. `MAX_AID_LEN = 11` keeps
  `5 + AID ≤ 16` (driver command buffer).
- `HceReader::aid()` / `aidLen()` / `nonceLen()` / `macLen()` /
  `maxCredentialLen()` / `keyLen()` expose these without including this
  header.

### 2.2 APDU builders

All builders write into a caller buffer, return **bytes written**,
return `0` on bad args or short buffer. Never throw.

#### `buildSelectAidWith()`

```cpp
size_t buildSelectAidWith(const uint8_t* aid, size_t aidLen,
                          uint8_t* out, size_t cap);
```

Builds a SELECT AID command for an **explicit** AID:
`00 A4 04 00 Lc AID` (no Le). Returns `5 + aidLen`, `0` when
`aid == nullptr`, `aidLen == 0`, `aidLen > MAX_AID_LEN`, or
`cap < 5 + aidLen`.

Default AID (7 B) → 12 bytes:

```text
00 A4 04 00 07  F0 01 02 03 04 05 06
```

#### `buildSelectAid()`

```cpp
size_t buildSelectAid(uint8_t* out, size_t cap);
```

Same, with the compiled-in `AID`. Returns `12`, `0` when short.

```cpp
uint8_t cmd[16];
size_t n = rc522hce::buildSelectAid(cmd, sizeof(cmd));  // 12
```

#### `buildChallenge()`

```cpp
size_t buildChallenge(const uint8_t nonce[NONCE_LEN], uint8_t* out, size_t cap);
```

Builds `80 10 00 00 Lc nonce` (no Le). Returns `13` (`5 + NONCE_LEN`),
`0` on null args or `cap < 13`.

```text
80 10 00 00 08  NN NN NN NN NN NN NN NN
```

Nonce **must be fresh per tap** — generate with `fillRandomBytes()`
(§2.4) from a hardware TRNG where one exists. It travels in the clear;
logging it is safe.

#### `buildEnroll()`

```cpp
size_t buildEnroll(uint8_t* out, size_t cap);
```

Builds `80 20 00 00 20` (Le = 32, no data). Returns `5`, `0` when
short. **Send only in pairing mode, after CHALLENGE, in the same
session.**

```cpp
uint8_t cmd[16];
buildSelectAid(cmd, sizeof(cmd));       // → 12 B
uint8_t nonce[8]; fillRandomBytes(nonce, 8, myRandomWord);
buildChallenge(nonce, cmd, sizeof(cmd)); // → 13 B
buildEnroll(cmd, sizeof(cmd));           // → 5 B (enrollment only)
```

### 2.3 Response classifiers / parsers

All parsers are exact-length, never throw, and never take the RF UID —
identity comes from the APDU layer by construction.

#### `isOk()`

```cpp
bool isOk(const uint8_t* resp, size_t len);
```

`true` when the response ends in `90 00` (at least the status word
present). `false` on `nullptr` or `len < 2`.

#### `parseSelectResponse()` + `SelectOutcome`

```cpp
enum class SelectOutcome { Selected, UnknownAid, Malformed };
SelectOutcome parseSelectResponse(const uint8_t* resp, size_t len);
```

| Outcome | Wire shape | Meaning |
|---|---|---|
| `Selected` | exactly 8 B: `"HCE-OK"` (6 B) + `90 00` | An HCE phone for our AID answered |
| `UnknownAid` | ends in `6A 82` | Something else answered (wrong app / AID mismatch) — app/routing problem, not a framing fault |
| `Malformed` | anything else (truncated, wrong payload, wrong SW, `nullptr`, `len < 2`) | Reader-side framing/read fault |

```cpp
switch (parseSelectResponse(resp, respLen)) {
    case rc522hce::SelectOutcome::Selected:   /* → CHALLENGE */ break;
    case rc522hce::SelectOutcome::UnknownAid: /* 6A82: not our phone */ break;
    default:                                  /* malformed: RF/driver fault */ break;
}
```

#### `parseChallengeResponse()` + `ChallengeResponse`

```cpp
struct ChallengeResponse {
    bool ok = false;
    std::string credId;   // application-level identity (NOT the RF UID)
    uint8_t mac[HMAC_LEN];
};
bool parseChallengeResponse(const uint8_t* resp, size_t len,
                            ChallengeResponse& out);
```

Parses `len(1) + credId(1..32) + HMAC(32) + 9000`. Returns `true` (and
fills `out`) **only** on an exact-length, `9000`-terminated frame:

- `resp == nullptr` → `false`.
- Total shorter than `1 + 1 + 32 + 2` → `false`.
- `credLen = resp[0]`; `0` or `> MAX_CRED_LEN` → `false`.
- `len != 1 + credLen + 32 + 2` → `false` (no trailing garbage, no
  truncation).
- Not ending in `90 00` → `false`.
- On failure `out.ok == false` and `out.credId` is cleared.

Max response: `1 + 32 + 32 + 2 = 67` B.

#### `isKeyMissing()`

```cpp
bool isKeyMissing(const uint8_t* resp, size_t len);
```

`true` for exactly `6A 88`: the phone has no provisioned key (or lost
it — reinstall). **Operator fix is enrollment, not a retry.**

#### `parseEnrollResponse()`

```cpp
bool parseEnrollResponse(const uint8_t* resp, size_t len,
                         uint8_t key[KEY_LEN]);
```

Parses `key(32) + 9000`, exact length (34 B). Fills `key` only on
success. `6985` (enrollment window closed) → `false`. `nullptr` args →
`false`.

### 2.4 Crypto primitives

Compact, dependency-free implementations (SHA-256 per FIPS 180-4; HMAC
per RFC 2104 / RFC 4231). Covered host-side by RFC 4231 + FIPS vectors
plus tamper-property tests.

#### `hmacSha256()`

```cpp
void hmacSha256(const uint8_t* key, size_t keyLen,
                const uint8_t* msg, size_t msgLen,
                uint8_t out[HMAC_LEN]);
```

HMAC-SHA256. Keys longer than 64 B hash down first (RFC 2104); null /
empty key or message is treated as empty (never crashes).

Tap MAC:

```cpp
// MAC = HMAC-SHA256(K_cred, credId || nonce)
uint8_t msg[32 + 8];
memcpy(msg, credId.data(), credId.size());
memcpy(msg + credId.size(), nonce, 8);
uint8_t mac[32];
rc522hce::hmacSha256(key, 32, msg, credId.size() + 8, mac);
```

#### `sha256Bytes()`, `sha256Hex()`

```cpp
void sha256Bytes(const uint8_t* data, size_t len, uint8_t out[HMAC_LEN]);
std::string sha256Hex(const std::string& data);  // hex of the above
```

Raw SHA-256 (fingerprints, body hashes). Null data with `len == 0`
hashes the empty string.

#### `fillRandomBytes()`

```cpp
void fillRandomBytes(uint8_t* out, size_t len, uint32_t (*randomWord)());
```

Fills `len` bytes from a 32-bit random-word source, **little-endian per
word** (first byte out = bits `[7:0]` of the first word). No-op on null
`out` or null source. Never throws.

The caller owns freshness: pass a hardware TRNG where one exists
(`esp_random` on ESP32 — the radio driver does this automatically);
the deterministic-stub pattern makes the byte layout unit-testable on
the host.

```cpp
uint8_t nonce[8];
rc522hce::fillRandomBytes(nonce, sizeof(nonce), myRandomWord);
// myRandomWord e.g.: esp_random on ESP32, or:
// uint32_t myNoise() { /* floating analog pin / RSSI / TRNG */ }
```

#### `wrapKeyHex()`

```cpp
std::string wrapKeyHex(const std::string& readerSecret,
                       const std::string& credId,
                       const std::string& keyNonceHex,
                       const uint8_t key[KEY_LEN]);
```

Wraps a phone key for the pairing request (64 hex chars):

```text
key XOR HMAC-SHA256(readerSecret,
    "pulse-hce-key-wrap/v1\n" || credId || "\n" || keyNonceHex)
```

- `keyNonceHex` must be fresh per pairing (lowercase hex, 32 chars =
  16 B from `fillRandomBytes`).
- Returns empty string on `key == nullptr`.
- The pad is wiped before return; the caller must wipe the raw key.

Unwrap server-side by deriving the same pad and XOR-ing (§11.3).

### 2.5 Hex helpers

```cpp
std::string toHex(const uint8_t* data, size_t len);  // lowercase; empty on nullptr
size_t unhex(const std::string& hex, uint8_t* out, size_t cap);
```

`unhex` decodes lowercase/uppercase hex → bytes. Returns bytes written;
`0` on: `nullptr` out, empty input, odd length, non-hex chars, or
`n > cap` (refuses rather than truncating). `HceReader::fromHex` is the
same function.

```cpp
auto hex = rc522hce::toHex(nonce, 8);          // "0123456789abcdef"
uint8_t raw[8];
size_t n = rc522hce::unhex(hex, raw, sizeof(raw));  // 8; 0 on garbage
```

Wire rule: relay transcripts and wrapped keys travel hex-encoded
(`nonceHex` 16 chars, `macHex` / `keyWrappedHex` 64 chars,
`keyNonceHex` 32 chars).

### 2.6 Backend verification (`verifyProof`)

```cpp
bool verifyProof(const std::string& credId,
                 const std::string& nonceHex,
                 const std::string& macHex,
                 const uint8_t key[KEY_LEN]);
```

Verifies a relayed proof: recomputes
`HMAC-SHA256(K_cred, credId || nonce)` from the hex transcript and
compares against `macHex` in **constant time** (no timing leak).
This is where the per-credential key is used — **never on the reader**.
Reject when it returns `false`.

Fails closed on: `key == nullptr`; `macHex.size() != 64`; empty
`nonceHex`; nonce not decoding to exactly `NONCE_LEN (8)` B; MAC not
decoding to exactly `HMAC_LEN (32)` B; `credId` empty or `> 32` B (a
claim with an impossible id can never verify); MAC mismatch (compared
with `volatile`-accumulated XOR, not `memcmp`).

```cpp
// Server, holding the stored 32-byte key for tap.credentialId:
if (!rc522hce::verifyProof(tap.credentialId, tap.proof.nonceHex,
                           tap.proof.macHex, credKey)) {
    // reject — wrong key, tampered MAC, replayed or impossible transcript
}
// + enforce per-credential nonce single-use (replay table) server-side.
```

The `HceProof`-taking overload (`HceReader::verifyProof(proof, credId,
key)`) forwards to this with `proof.nonceHex` / `proof.macHex`. An
unfilled proof struct never verifies.

### 2.7 Status words (`statusWordName`)

```cpp
const char* statusWordName(uint8_t sw1, uint8_t sw2);  // nullptr if unknown
```

| SW | Text | When |
|---|---|---|
| `9000` | `"9000 (success)"` | SELECT matched / CHALLENGE answered |
| `6A82` | `"6A82 (app/AID not found — no app routed to our AID)"` | SELECT with any other AID |
| `6A88` | `"6A88 (no key provisioned on the phone — enroll it)"` | CHALLENGE on a phone with no usable key |
| `6985` | `"6985 (conditions not satisfied — enrollment window closed)"` | CHALLENGE/ENROLL before SELECT; ENROLL with no open window |
| `6700` | `"6700 (wrong length)"` | `Lc` ≠ 7 (SELECT) / ≠ 8 (CHALLENGE), ENROLL with data, truncated APDU |
| `6D00` | `"6D00 (INS unknown)"` | Known CLA, unknown instruction |
| `6E00` | `"6E00 (CLA unknown)"` | First byte not `00`/`80` |
| other | `nullptr` | Unrecognized — do not display as known |

Use for operator-facing messages instead of hardcoding a table:

```cpp
const char* name = rc522hce::HceReader::statusWordName(sw1, sw2);
Serial.println(name ? name : "unknown status word");
```

### 2.8 Shared interop test vector (`TestVector`)

```cpp
namespace TestVector {
static const char* kCredId       = "PLS-K3Y7V3CT0R5Z";
static const char* kKeyHex       = "000102030405060708090a0b0c0d0e0f"
                                   "101112131415161718191a1b1c1d1e1f";
static const char* kNonceHex     = "0123456789abcdef";
static const char* kMacHex       = "ba6d0fbf5106f79257727819d19a17b7e"
                                   "15abc4b8a0d1bfe71cd76090488a295";
static const char* kReaderSecret = "test-secret-000000000000000001";
static const char* kKeyNonceHex  = "000102030405060708090a0b0c0d0e0f";
static const char* kKeyWrappedHex= "c5bb9fe15dff66a8636366dd4e73e0a3"
                                   "146601e3b3c36472961de142a9a914c2";
}
```

Computed outside every implementation (Python `hmac`) and pinned in
every port (phone app, reader, backend). `MAC = HMAC-SHA256(K_cred,
credId || nonce)` with the bytes above; CHALLENGE response bytes:

```text
10  504C532D4B335937563343543052355A  ba6d…a295  9000
```

`HceReader::selfCheckVector()` unhexes `kKeyHex` and runs
`verifyProof(kCredId, kNonceHex, kMacHex, key)` (wiping the key after).
See §13 for the verify-before-hardware checklist.

### 2.9 ISO-DEP / RF helpers (pure)

Testable predicates encoding the three bench-proven facts behind
HCE-over-RC522, instead of inline bit-twiddling in the driver:

1. SAK bit 6 set + bit 3 clear (`(sak & 0x24) == 0x20`) promises ISO-DEP.
2. A 5-byte CRC-valid answer is ambiguous by length alone: PCB decides
   between a bare-status I-block (app answered, e.g. `6A82`) and
   S(WTX) (phone asks for more time).
3. A salvaged I-block must be stripped to the INF field, and the block
   number resynced from the phone's own answer.

```cpp
bool sakPromisesIsoDep(uint8_t sak);  // (sak & 0x24) == 0x20
bool isIBlock(uint8_t pcb);           // (pcb & 0xC0) == 0x00 — app data
bool isRBlock(uint8_t pcb);           // (pcb & 0xC0) == 0x80 — ACK/NAK
bool isWtxRequest(uint8_t pcb);       // S(WTX): top bits 0xC0 + 0x30
bool isWtxFrame(const uint8_t* frame, size_t len);  // full-frame WTX (≥5 B)

bool stripIBlock(const uint8_t* frame, size_t frameLen, size_t respCap,
                 size_t& infOffsetOut, size_t& infLenOut);
bool nextBlockNumber(uint8_t receivedPcb);  // opposite of bit 0
```

`stripIBlock`: locates the INF field of a raw I-block frame —
`frame[infOffset..infOffset+infLen)` is exactly what `TCL_Transceive`
would have returned. Handles optional CID (bit `0x08`) and NAD (bit
`0x04`), strips trailing 2-B CRC. Rejects non-I-blocks,
prologue+CRC-only frames, and INF larger than `respCap` (mirrors
`STATUS_NO_ROOM`).

`nextBlockNumber`: the phone echoes the block number it received, so
the next block we send is the opposite (`(pcb & 0x01) == 0 → true`).
Self-correcting even after a lost frame — forgets driver state.

---

## 3. `NfcReader` + `HceProof` (`src/NfcReader.h`) — the transport contract

```cpp
#include <NfcReader.h>   // pulls HceProtocol.h for the proof struct
```

### 3.1 `struct HceProof`

What an HCE tap carries to the backend. The reader does **not** verify
the phone (it holds no HCE key): it relays its own challenge nonce and
the phone's MAC, and the server checks them against that credential's
key. Empty for physical cards.

```cpp
struct HceProof {
    std::string nonceHex;       // 16 hex — reader's CHALLENGE nonce
    std::string macHex;         // 64 hex — phone's HMAC, unverified here
    std::string keyWrappedHex;  // 64 hex — enrollment only
    std::string keyNonceHex;    // 32 hex — enrollment only (fresh per pairing)

    bool present() const { return !nonceHex.empty() && !macHex.empty(); }
    bool hasKey() const { return !keyWrappedHex.empty() && !keyNonceHex.empty(); }
    void clear();  // wipes all four fields
};
```

| Field | Length | Safe to log? |
|---|---|---|
| `nonceHex` | 16 hex (8 B) | yes |
| `macHex` | 64 hex (32 B) | yes |
| `keyWrappedHex` | 64 hex (32 B XOR pad) | yes (wrapped — useless without `readerSecret`) |
| `keyNonceHex` | 32 hex (16 B) | yes |

Key material is **never** in this struct raw — only wrapped.

### 3.2 `class NfcReader` (abstract interface)

Concrete drivers (`Rc522HceReader`) and the host mock (`MockNfcReader`)
both implement this, so application logic never knows which is behind
it.

```cpp
class NfcReader {
public:
    virtual ~NfcReader() = default;
    virtual bool begin() = 0;
    virtual bool poll(std::string& idOut) = 0;
    virtual const char* lastKind() const { return "physical"; }
    virtual const HceProof& lastProof() const;   // empty default
    virtual void setEnrollment(bool on, const std::string& wrapSecret) {}
    virtual const char* label() const = 0;
    virtual bool healthy() const { return true; }
    virtual const uint8_t* aid() const { return AID; }
    virtual size_t aidLen() const { return AID_LEN; }
    virtual bool setAid(const uint8_t* aid, size_t len) { return false; }
};
```

| Method | Contract |
|---|---|
| `begin()` | Init hardware. `false` = not talking (wiring/power). |
| `poll(idOut)` | Non-blocking. `true` + `idOut` filled = one credential this call. `false` = none. |
| `lastKind()` | `"physical"` or `"hce"` — how the **last successful** poll's id was captured. |
| `lastProof()` | Relayed HCE transcript of the last successful poll; empty default for physical cards / base class. |
| `setEnrollment(on, wrapSecret)` | Pairing mode. Default no-op (mock); radio fetches+wraps the key while on. |
| `label()` | Short log label (`"RC522 (SPI) + HCE"`, `"MOCK (host input)"`, …). |
| `healthy()` | `true` unless a radio driver revoked it (VersionReg probe). Non-hardware readers always `true`. |
| `aid()` / `aidLen()` | AID this reader SELECTs (protocol default unless overridden). |
| `setAid(aid, len)` | Change selected AID (`1..MAX_AID_LEN`); default ignores and returns `false`. |

---

## 4. `Rc522HceReader` (`src/Rc522HceReader.h`) — the radio driver (device only)

```cpp
#include <Rc522HceReader.h>   // needs Arduino core + MFRC522 library
```

Concrete `NfcReader`: MFRC522 over SPI (`miguelbalboa/rfid`
`MFRC522Extended`) plus the application-level HCE exchange. Portable
across microcontrollers — the only chip-specific dependency is the
random source (injected; ESP32 defaults to `esp_random`).

### 4.1 Construction

```cpp
explicit Rc522HceReader(uint8_t ssPin = kDefaultSsPin,   // RC522HCE_SS_PIN
                        uint8_t rstPin = kDefaultRstPin, // RC522HCE_RST_PIN
                        uint8_t sckPin = kDefaultSckPin,
                        uint8_t misoPin = kDefaultMisoPin,
                        uint8_t mosiPin = kDefaultMosiPin,
                        Print* log = nullptr,
                        Rc522HceOptions options = Rc522HceOptions(),
                        RandomWordFn randomWord = defaultRandomWord);
```

Pin defaults come from `Rc522HceConfig.h` (build flag → board preset →
default), so `Rc522HceReader radio;` is correctly wired with no args.
`rstPin = 255` (`MFRC522 UNUSED_PIN`) = RST strapped to 3V3 (soft reset
only, no pin driven).

```cpp
// ESP32 DevKit: defaults are correct
rc522hce::Rc522HceReader radio;
// UNO/Nano hardware SPI:
rc522hce::Rc522HceReader radio(10, 9, 13, 12, 11);
// ESP32-CAM custom wiring + logging + timings + RNG:
rc522hce::Rc522HceOptions opts;
opts.reinitIntervalMs = 5000;
opts.hceSettleMs = 400;
rc522hce::Rc522HceReader radio(13, 255, 14, 2, 15, &Serial, opts);
```

SPI routing note: ESP32 honors all five pins; other cores use fixed
hardware-SPI SCK/MISO/MOSI (only SS freely choosable). See
[`WIRING.md`](WIRING.md).

### 4.2 `Rc522HceOptions`

```cpp
struct Rc522HceOptions {
    uint32_t reinitIntervalMs = 5000;  // PCD retry + runtime probe cadence
    uint32_t hceSettleMs = 400;        // park-and-activate settle window
};
```

| Field | Meaning | Build-flag default |
|---|---|---|
| `reinitIntervalMs` | Dead-reader retry cadence + VersionReg health-probe period (non-blocking, wrap-safe) | `RC522HCE_REINIT_INTERVAL_MS` (5000) |
| `hceSettleMs` | Radio-silence window after an ISO-DEP sighting before the tap's first RATS (phone controller boot time) | `RC522HCE_HCE_SETTLE_MS` (400) |

### 4.3 `RandomWordFn` / `defaultRandomWord`

```cpp
using RandomWordFn = uint32_t (*)();
inline uint32_t defaultRandomWord();  // ESP32: esp_random()
```

32-bit random-word source for per-tap CHALLENGE nonces and per-enrollment
key-wrap nonces. Plain function pointer (every Arduino core, no
`std::function`).

- ESP32: `esp_random()` hardware RNG, automatic.
- Others: best-effort auto-seeded fallback (`micros() ^ millis()` +
  `analogRead(A0)` once, then Arduino PRNG). Fine for hobby nonces.
- **Production on RNG-less chips: inject your own.**

```cpp
uint32_t myNoise() { /* floating analog pin / RSSI / TRNG chip */ return ...; }
rc522hce::Rc522HceReader radio(10, 9, 13, 12, 11, &Serial,
                               rc522hce::Rc522HceOptions(), myNoise);
```

Byte order out of `fillRandomBytes` is little-endian per word
(§2.4) — relevant only if you assert exact nonce bytes in tests.

### 4.4 Methods

| Method | Signature | Behavior |
|---|---|---|
| `begin()` | `bool begin() override` | `SPI.begin(...)` (ESP32 explicit pins; others fixed HW-SPI + `pinMode(SS)`), then `reinit(millis())`. |
| `poll()` | `bool poll(std::string& idOut) override` | Full flow below. `true` = one credential. |
| `setAid()` | `bool setAid(const uint8_t*, size_t) override` | `1..MAX_AID_LEN` accepted, else `false` + previous kept. |
| `aid()` / `aidLen()` | `const uint8_t*` / `size_t` | Currently selected AID (constructor seeds protocol default). |
| `lastKind()` | `const char*` | `"physical"` / `"hce"`. |
| `lastProof()` | `const HceProof&` | Relayed transcript (+ wrapped key in enrollment). |
| `setEnrollment()` | `void setEnrollment(bool, const std::string&) override` | Stores/clears `wrapSecret_`; off clears the secret. |
| `setLog()` | `void setLog(Print* log)` | Diagnostics sink (`Serial`, `TsLog`, …) or `nullptr` for silence. |
| `healthy()` | `bool healthy() const override` | Last VersionReg probe answered. |
| `lastVersion()` | `uint8_t lastVersion() const` | Last PCD firmware byte (`0x91` v1.0, `0x92` v2.0; clones `0x90`/`0x88`; `0` never probed; `0x00`/`0xFF` dead). |
| `label()` | `const char*` | `"RC522 (SPI) + HCE"`. |

`poll()` flow (abridged — full bench rationale is in the header
comments):

1. Unhealthy → retry `reinit()` on the cadence, return `false`.
2. Runtime VersionReg probe on the cadence; `0x00`/`0xFF` revokes
   health (probed at top of `poll()`, never mid-tap).
3. HCE settle window: ISO-DEP sighting parks the untouched session
   (no RATS, no HaltA) for `hceSettleMs` of radio silence (`delay(5)`
   granularity — never spins, watchdog-safe), then fires RATS via
   `adoptAts()`.
4. `PICC_IsNewCardPresent()` + qualified `PICC_Select()` (no RATS, no
   surprise HaltA). Logs `SAK`/`ATS`/`UID-size` per target.
5. `sakPromisesIsoDep(sak)`:
   - ATS present → `pollHce()`: `SELECT` (10 tries × ~15 ms) →
     `CHALLENGE` (6 × ~25 ms) → optional `ENROLL` → `idOut` = app
     credId, `lastKind_ = "hce"`. Any failure releases the target and
     returns `false` (a MIFARE tap is never affected).
   - ATS missing → **failed tap, never a card** (`HaltA`, `false`).
     Reporting the random RF UID as a credential is explicitly refused.
6. Else MIFARE: uppercase hex UID, `HaltA` + `StopCrypto1`, `true`.

Radio robustness facts the driver encodes (do not "fix" without
re-reading the header): first RATS goes out late (~400 ms) on an
undisturbed session; HCE transmit uses a clamped **5 ms** RX window
(phone answers in ~13–16 ms; the stock 25 ms window makes the driver
eat its own WTX); max RX gain (48 dB); 1 MHz SPI; S(WTX) granted up to
4 rounds; FIFO late-answer salvage with CRC gate + `stripIBlock` +
`nextBlockNumber` resync; ENROLL answers redacted from logs and wiped.

### 4.5 Health model

```
begin() ──reinit()──▶ healthy_ = VersionReg ∉ {0x00, 0xFF}
poll() ──probe every reinitIntervalMs──▶ revoke on 0x00/0xFF
unhealthy poll() ──reinit() on cadence──▶ self-heals, logs recovery
```

Apps: check `healthy()` for a degraded banner; the driver already
retries. Never reboot to recover the radio.

---

## 5. `Rc522HceConfig.h` — build-flag configuration (no source edits)

```cpp
#include <Rc522HceConfig.h>   // pulled in by Rc522HceReader.h automatically
```

Resolution order: **build flag → board preset → default**. Applies to
default-constructed readers.

```ini
; platformio.ini
build_flags =
    -DRC522HCE_SS_PIN=13
    -DRC522HCE_RST_PIN=255     ; 255 = RST strapped to 3V3
    -DRC522HCE_SCK_PIN=14
    -DRC522HCE_MISO_PIN=2
    -DRC522HCE_MOSI_PIN=15
    -DRC522HCE_DEBOUNCE_MS=1500
    -DMFRC522_SPICLOCK=1000000u
```

| Knob | Build flag | Default |
|---|---|---|
| SS / RST / SCK / MISO / MOSI | `RC522HCE_{SS,RST,SCK,MISO,MOSI}_PIN` | preset or DevKit pins (5/27/18/19/23) |
| AID bytes (compile-time seed) | `RC522HCE_AID_BYTES=0xF0,…` | `F0010203040506` |
| Re-read suppression window | `RC522HCE_DEBOUNCE_MS` | `2000` |
| PCD retry / health-probe cadence | `RC522HCE_REINIT_INTERVAL_MS` | `5000` |
| Park-and-activate settle window | `RC522HCE_HCE_SETTLE_MS` | `400` |
| SPI clock (read by the MFRC522 lib) | `MFRC522_SPICLOCK` | `1000000u` (1 MHz) |

Board presets (when not overridden; opt out with
`-DRC522HCE_NO_BOARD_PRESET`):

| Board | SS | RST | SCK | MISO | MOSI |
|---|---|---|---|---|---|
| ESP32 DevKit (VSPI) | 5 | 27 | 18 | 19 | 23 |
| Mega (HW SPI) | 53 | 5 | 52 | 50 | 51 |
| UNO/Nano (HW SPI) | 10 | 9 | 13 | 12 | 11 |
| ESP8266 NodeMCU | 15 | 5 | 14 | 12 | 13 |
| RP2040 Pico | 17 | 20 | 18 | 16 | 19 |
| STM32 (SPI1) | PA4 | PB0 | PA5 | PA6 | PA7 |

`RC522HCE_PRESET` is the matched preset name for build banners
(`"defaults (no board preset matched)"` otherwise). Per-loop timings
stay in code (`Rc522HceOptions`, §4.2); the AID can additionally change
at runtime (`setAid`, §1.7).

---

## 6. `CardDebouncer` (`src/CardDebouncer.h`)

Millis()-based re-read suppression, pure C++ (host-tested).

```cpp
#include <CardDebouncer.h>   // or via <HceReader.h> (it owns one)

class CardDebouncer {
public:
    explicit CardDebouncer(uint32_t cooldownMs);
    bool shouldProcess(const std::string& id, uint32_t nowMs);
    void markAbsent();
    void reset();
};
```

Rules:

- Resting card (same id, never absent) → exactly **one** event; never
  re-accepted until removed. Caller must invoke `markAbsent()` on every
  `poll() == false` (the facade does this in `read()`).
- Different id → accepted immediately (previous card must have left).
- Same id after absence → accepted only once the cooldown elapsed
  (deliberate human re-tap).
- `reset()` forgets the last tap (facade calls it on
  `setEnrollment()` / `setAid()`).
- Wrap-safe unsigned `now - then`.

```cpp
rc522hce::CardDebouncer db(2000);
if (radio.poll(id)) {
    if (db.shouldProcess(id, millis())) { /* real tap */ }
} else {
    db.markAbsent();   // arms the next deliberate re-tap
}
```

---

## 7. `MockNfcReader` (`src/MockNfcReader.h`)

Hardware-free transport for dev/tests. Pure C++ — compiles on host and
Arduino alike. Implements `NfcReader`; wrap it in `HceReader` exactly
like the radio.

```cpp
#include <MockNfcReader.h>

class MockNfcReader : public NfcReader {
public:
    bool begin() override;                          // always true
    void pushTap(const std::string& line);          // queue one virtual tap
    void pushLine(const std::string& line);         // alias (original name)
    bool poll(std::string& idOut) override;         // one tap per pushed line
    const char* label() const override;             // "MOCK (host input)"
};
```

- Empty lines ignored; newest push wins (taps are human-paced).
- Each `poll()` consumes at most one tap; empty queue → `false`.
- Reports `lastKind() == "physical"` and empty `lastProof()` (base
  defaults) — for scripted HCE proofs use a fake transport overriding
  those (see `test/test_facade.cpp`).

```cpp
rc522hce::MockNfcReader mock;
rc522hce::HceReader reader(mock);
reader.begin();
mock.pushTap("DEV-CARD");
rc522hce::HceReader::Tap tap;
if (reader.read(tap, millis())) { /* tap.credentialId == "DEV-CARD" */ }
```

---

## 8. `TsLog` (`src/TsLog.h`) — device only

`Print` decorator prefixing `millis()` at each line start. Bench tool
for correlating RF events in time. Wraps any `Print`; single-threaded
`loop()` assumed.

```cpp
#include <TsLog.h>   // Arduino only

rc522hce::TsLog tsLog(Serial);   // [1234] [NFC] RC522 detected …
rc522hce::Rc522HceReader radio(5, 27, 18, 19, 23, &tsLog);
// or: radio.setLog(&tsLog);
```

`write(uint8_t)` prints `[millis] ` at each fresh line, forwards the
byte, re-arms on `'\n'`.

---

## 9. `CompatNames.h` — legacy aliases (migration only)

```cpp
#include <CompatNames.h>   // optional; included by NOTHING
```

Adopting into a codebase that already uses the historical names
(`Presence::Rc522NfcReader`, `Presence::Hce::buildSelectAid`,
`Presence::HceProof`, `Presence::Signer::toHex`): existing call sites
compile unchanged. Pure alias layer — same types, values cross the seam
both ways with no conversion. **Do not include in new code.** Arduino-only
driver aliases guarded so the header still compiles in host tests.

| Old name | Alias of |
|---|---|
| `Presence::HceReader` | `rc522hce::HceReader` |
| `Presence::NfcReader` | `rc522hce::NfcReader` |
| `Presence::HceProof` | `rc522hce::HceProof` |
| `Presence::CardDebouncer` | `rc522hce::CardDebouncer` |
| `Presence::MockNfcReader` / `Presence::MockSerialNfcReader` | `rc522hce::MockNfcReader` |
| `Presence::Rc522HceReader` / `Presence::Rc522NfcReader` (Arduino) | `rc522hce::Rc522HceReader` |
| `Presence::TsLog` (Arduino) | `rc522hce::TsLog` |
| `Presence::Hce::buildSelectAid[With]` / `buildChallenge` / `buildEnroll` | `rc522hce::…` |
| `Presence::Hce::isOk` / `isKeyMissing` | `rc522hce::…` |
| `Presence::Hce::parseSelectResponse` / `parseChallengeResponse` / `parseEnrollResponse` | `rc522hce::…` |
| `Presence::Hce::hmacSha256` / `sha256Bytes` / `wrapKeyHex` | `rc522hce::…` |
| `Presence::Hce::SelectOutcome` / `ChallengeResponse` | `rc522hce::…` |
| `Presence::Hce::AID[AID_LEN, MAX_AID_LEN, NONCE_LEN, HMAC_LEN, MAX_CRED_LEN, KEY_LEN, KEY_NONCE_LEN]` | `rc522hce::…` |
| `Presence::Hce::TestVector` (namespace alias) | `rc522hce::TestVector` |
| `Presence::Signer::toHex` / `sha256Hex` | `rc522hce::toHex` / `sha256Hex` |

---

## 10. Return-code and error conventions

| API | Success | Failure signal | Notes |
|---|---|---|---|
| `build*` | bytes written (`12`/`13`/`5`) | `0` | bad args or short buffer; never partial |
| `parse*` returning `bool` | `true` + `out` filled | `false` + `out` cleared (`ok=false`) | exact-length only |
| `parseSelectResponse` | `Selected` / `UnknownAid` | `Malformed` | `nullptr`/`len<2` → `Malformed` |
| `unhex` / `fromHex` | bytes written | `0` | odd len, bad chars, short cap — refuses, never truncates |
| `setAid` | `true` | `false`, previous kept | `nullptr` / `0` / `> 11` |
| `verifyProof` | `true` | `false` (fail closed) | wrong key/id/nonce/MAC, malformed hex, impossible id |
| `statusWordName` | operator text | `nullptr` | unrecognized SW |
| `HceReader::begin` / `poll` / `read` | `true` | `false` | `read` false also = resting/cooldown (not an error) |
| `selfCheckVector` | `true` | `false` | crypto mismatch — stop and investigate |

Nothing throws. Nothing logs key material (ENROLL answers redacted,
raw keys wiped with `memset` after use).

---

## 11. Backend integration guide (server-side)

The reader holds **no HCE key** and verifies nothing. Your server holds
each credential's 32-byte key and does two jobs: verify operation taps,
unwrap enrollment keys.

### 11.1 Verify an operation tap

Input per tap: `credentialId`, `nonceHex` (16), `macHex` (64).

```cpp
// C++ backend (same implementation as the firmware — one crypto, not three):
uint8_t credKey[32];  // load by credentialId from your DB
loadKey(tap.credentialId, credKey);
bool ok = rc522hce::HceReader::verifyProof(tap.proof, tap.credentialId, credKey);
memset(credKey, 0, sizeof(credKey));
if (!ok) { reject(); }
// + reject reused (credentialId, nonceHex) pairs — replay table, single-use nonces.
```

```python
# Python backend (equivalent):
import hmac, hashlib
cred_key = db.load_key(credential_id)          # 32 bytes
nonce    = bytes.fromhex(nonce_hex)            # 8 bytes
mac      = bytes.fromhex(mac_hex)              # 32 bytes
expected = hmac.new(cred_key, credential_id.encode() + nonce,
                    hashlib.sha256).digest()
if not hmac.compare_digest(expected, mac):     # constant-time!
    reject()
check_and_remember_nonce(credential_id, nonce_hex)  # replay => reject
```

Rules: look the key up **by the claimed id** (the id is inside the
MAC, so a key authenticates only its own id); compare in constant time
(`compare_digest` / the library's volatile-XOR); enforce nonce
single-use per credential; reject empty / >32-B ids without a DB hit.

### 11.2 What to store per credential

| Column | Contents |
|---|---|
| `credential_id` | ASCII, 1–32 B, primary key |
| `key` | 32 B secret (HSM/KMS; never in logs) |
| `seen_nonces` | set of used `nonceHex` per id (replay memory) |
| `revoked` | lost/stolen phone → delete/flag the key (revocation = key destruction) |

### 11.3 Unwrap an enrollment tap

Input: `credentialId`, `nonceHex`, `macHex`, `keyWrappedHex` (64),
`keyNonceHex` (32), plus your `readerSecret` (the string passed to
`setEnrollment(true, readerSecret)` on that reader).

**Order matters — proof of possession first:**

1. Derive the expected key *candidate* from the wrap, **but do not
   store it yet**.
2. Require the same tap's CHALLENGE proof to verify **under the
   candidate** (`verifyProof(credId, nonceHex, macHex, candidate)`).
   Only the credential being enrolled is accepted — this binds the key
   to the id and stops enrollment overwriting another credential.
3. Store (or rotate, on re-enrollment) the candidate.

```python
import hmac, hashlib
label = f"pulse-hce-key-wrap/v1\n{credential_id}\n{key_nonce_hex}".encode()
pad = hmac.new(reader_secret.encode(), label, hashlib.sha256).digest()
wrapped = bytes.fromhex(key_wrapped_hex)
candidate = bytes(a ^ b for a, b in zip(wrapped, pad))
# proof-of-possession under the candidate:
expected = hmac.new(candidate, credential_id.encode()
                    + bytes.fromhex(nonce_hex), hashlib.sha256).digest()
assert hmac.compare_digest(expected, bytes.fromhex(mac_hex))
db.store_key(credential_id, candidate)  # rotate on re-enrollment
```

The C++ unwrap is the mirror image (`hmacSha256` over the same label,
`unhex` the wrap, XOR — see `test/test_public_api.cpp`
`test_enrollment_key_wrap_is_exposed_and_round_trips`).

---

## 12. Enrollment lifecycle

```text
holder opens phone enrollment window (single-release, short-lived)
   │
   ▼  operator arms the reader (button / 'e' / dashboard)
reader.setEnrollment(true, readerSecret)
   │
   ▼  tap: SELECT → CHALLENGE (proof captured) → ENROLL (key fetched)
phone answers K_cred + 9000  (else 6985 → "open the window first")
   │
   ▼  driver wraps at once, wipes raw key + ENROLL frame
tap.proof = { nonceHex, macHex, keyWrappedHex, keyNonceHex }
   │
   ▼  POST all five fields; reader.setEnrollment(false)
server unwraps (§11.3), requires CHALLENGE proof under candidate, stores
```

- Normal taps (mode off) never send `ENROLL` — a sniffed operation
  transcript contains no key.
- `wrapSecret` empty + mode on → enrollment tap fails closed (`collectKey`
  refuses; tap returns `false`, proof cleared).
- `6985` on ENROLL = window closed/expired/released/not SELECTed — the
  operator re-opens the phone window and taps again.
- `6A88` on CHALLENGE = phone has no key — enroll it; do not retry the
  operation path.

---

## 13. Interop checklist (new phone app / new backend)

Prove a new side matches **before** touching hardware:

1. `HceReader::selfCheckVector()` (or `verifyProof(kCredId, kNonceHex,
   kMacHex, unhex(kKeyHex))`) must be `true`.
2. Recompute `MAC = HMAC-SHA256(bytes(kKeyHex), kCredId || bytes(kNonceHex))`
   independently (Python `hmac` one-liner) → must equal `kMacHex`.
3. `wrapKeyHex(kReaderSecret, kCredId, kKeyNonceHex, key)` must equal
   `kKeyWrappedHex`; unwrapping per §11.3 must recover `kKeyHex`.
4. Builders must emit the exact bytes (§2.2); parsers must accept the
   vector CHALLENGE response and reject the `Malformed` shapes
   (`pio test -e native` pins all of these — 95 tests, no board).
5. Only then debug on hardware (`SAK=0x20 ATS=0B` = RF/placement, `6A82`
   = AID/routing, `6A88` = unenrolled, `6985` = window closed).

---

## 14. Custom transports (implementing `NfcReader`)

To run the facade (and the whole static API) on another radio:

```cpp
#include <NfcReader.h>

class MyReader : public rc522hce::NfcReader {
public:
    bool begin() override { /* init */ return true; }
    bool poll(std::string& idOut) override {
        // physical: idOut = uppercase hex UID, lastKind "physical", proof cleared
        // hce: SELECT+CHALLENGE via §2.2/§2.3, idOut = credId,
        //      lastKind "hce", lastProof = {nonceHex, macHex}
        return false;
    }
    const char* lastKind() const override { return lastKind_; }
    const HceProof& lastProof() const override { return proof_; }
    const char* label() const override { return "MY-RADIO"; }
private:
    const char* lastKind_ = "physical";
    rc522hce::HceProof proof_;
};

MyReader radio;
rc522hce::HceReader reader(radio);   // debounce + API identical
```

Rules: never use the RF UID as an HCE identity; relay unverified
(`verifyProof` is the server's job); fetch the key only in enrollment
mode and wrap it before it leaves the driver; release the target on
every failure so MIFARE taps are unaffected.

---

## 15. Troubleshooting map (log line → meaning → fix)

| Log / symptom | Meaning | Fix |
|---|---|---|
| `RC522 NOT responding (version 0x00/0xFF)` | wiring / power | check SCK/MISO/MOSI/SS + 3.3 V (never 5 V); shorten Duponts; confirm 1 MHz SPI |
| `SAK=0x20 ATS=0B` every phone tap | phone too far / lifted early / rail sag | hold flat 2–3 cm above sensor, steady ~0.5 s; closer; check 3.3 V; metal cases off |
| `SAK=0x08` from a phone | phone not offering ISO-DEP | HCE app engaged? NFC on? device supports HCE? |
| `HCE SELECT failed` | no I-block reply | placement (§above); then signal (gain is already max) |
| `HCE SELECT -> 6A82` | phone routed no app to our AID | AID mismatch (`selectedAid()` vs app manifest) or HCE routing off |
| `HCE CHALLENGE timeout` | session died mid-exchange | keep phone still; check `statusWordName` of salvaged frames |
| `HCE phone has NO key yet (6A88)` | unenrolled phone | enroll (§12), don't retry operation |
| `HCE CHALLENGE answer malformed` | framing fault | RF/driver side, not the phone app's logic |
| `HCE ENROLL refused` | `6985` | open the phone enrollment window first, tap again |
| `Reader degraded — retrying…` | runtime death (ESD/brown-out) | driver self-heals on cadence; check power/ESD |
| Corrupt reads on 5 V boards | level/power | level-shift MOSI/SCK/SS, 1 MHz SPI |
| Cards ok, phones fail (or vice versa) | antenna detuning | metal away from antenna face |

`HceReader::statusWordName(sw1, sw2)` decodes every SW on the wire
(`9000`, `6A82`, `6A88`, `6985`, `6700`, `6D00`, `6E00`).

---

## 16. Header include map

| You need | Include | Notes |
|---|---|---|
| Read taps / verify proofs / AID / hex / vector | `<HceReader.h>` | the whole API; only include most apps need |
| Custom transport / backend without facade | `<HceProtocol.h>` + `<NfcReader.h>` | pure C++, host-testable |
| Debounce standalone | `<CardDebouncer.h>` | pure C++ |
| Hardware-free dev | `<MockNfcReader.h>` | pure C++ |
| Radio driver | `<Rc522HceReader.h>` | Arduino + MFRC522 |
| Timestamped logs | `<TsLog.h>` | Arduino `Print` |
| Build-flag pins/timings | `<Rc522HceConfig.h>` | auto-pulled by the driver |
| Adopting legacy names | `<CompatNames.h>` | migration only, includes nothing else |

Examples: [`../examples/BasicTap/BasicTap.ino`](../examples/BasicTap/BasicTap.ino)
(minimal tap printer), [`../examples/HceEnroll/HceEnroll.ino`](../examples/HceEnroll/HceEnroll.ino)
(operation + one-shot enrollment). Tests (`../test/`, 95 host-side Unity
tests, `pio test -e native`) pin every contract above — including a
translation unit that includes **only** `HceReader.h`, so this document
cannot promise something the API stops exposing.
