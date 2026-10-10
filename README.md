# ESP32-RC522-HCE

RC522 NFC reader with **Android-HCE phone-as-credential identification**, as a reusable
Arduino / PlatformIO library for **any microcontroller** (ESP32, AVR, STM32, RP2040,
ESP8266 — anything with an Arduino core and SPI). One `poll()` reads two credential kinds:

- **physical** — a MIFARE Classic UID off the RF layer (untouched path);
- **hce** — an Android phone answering as an ISO-DEP target. Identity comes from an
  application-level exchange (never the RF UID, which Android randomizes per tap):
  `SELECT AID F0010203040506` + random 8-byte `CHALLENGE`, answered with
  `len + credId + HMAC-SHA256(K_cred, credId || nonce) + 9000`.

The reader holds **no HCE key** and verifies nothing — it relays its nonce + the
phone's MAC (`lastProof()`) and your server verifies them with that credential's key.
In enrollment mode only, a one-time `ENROLL` APDU collects the phone's key and
`wrapKeyHex()` seals it under the reader's own secret before it touches the network.

This is a bench-hardened driver: park-and-activate RATS timing, S(WTX)
handling, FIFO late-answer salvage, block-number resync, max RX gain, 1 MHz
SPI. The framing rules that make phones actually answer live in pure,
host-tested functions instead of inline driver bit-twiddling.

## Layout

```text
src/
  HceReader.h           THE public API: configure once, then just read()
                        (wraps transport + debounce; pure C++, host-tested)
  HceProtocol.h / .cpp  pure C++: APDU builders/parsers, SHA-256/HMAC,
                        key-wrap, ISO-DEP frame helpers (host-testable)
  NfcReader.h           transport interface + HceProof relay struct
  Rc522HceReader.h      radio driver (MFRC522 over SPI) — device only
  CardDebouncer.h       re-read suppression (pure C++, host-tested)
  MockNfcReader.h       hardware-free transport for dev/tests (pure C++)
test/                   78 host-side Unity tests (`pio test -e native`)
examples/               Arduino sketches (BasicTap, HceEnroll)
docs/                   protocol spec + wiring guide
```

## Install

**PlatformIO** — add to `platformio.ini`:

```ini
lib_deps =
    https://github.com/NexusDeveloper902/esp32-rc522-hce.git
    miguelbalboa/MFRC522@^1.4.11
```

with `-DMFRC522_SPICLOCK=1000000u` in `build_flags` (1 MHz SPI is the
bench-proven setting over Dupont jumpers; see `docs/WIRING.md`).

> **8-bit AVR boards (UNO, Nano, Mega):** the AVR toolchain ships no C++
> standard library, so add one more dependency for `std::string`:
>
> ```ini
> lib_deps =
>     https://github.com/NexusDeveloper902/esp32-rc522-hce.git
>     miguelbalboa/MFRC522@^1.4.11
>     mike-matera/ArduinoSTL@^1.3.3   # 8-bit AVR only
> ```
>
> (Arduino IDE: install `ArduinoSTL` from the Library Manager.)
> 32-bit boards (ESP32, ESP8266, RP2040, STM32, nRF, Teensy) need no shim.
> Note: ATmega328P (UNO/Nano, 2 KB RAM) compiles but its static RAM
> overflows with the full HCE app — use a Mega (verified: 31% RAM) or any
> 32-bit board for real use.

**Arduino IDE** — Sketch → Include Library → Add `.ZIP Library` from a
[release](https://github.com/NexusDeveloper902/esp32-rc522-hce/releases) zip.
Requires the `MFRC522` library (≥ 1.4.11).

## Use — the 30-second version

```cpp
#include <HceReader.h>
#include <Rc522HceReader.h>

#ifdef ESP32
rc522hce::Rc522HceReader radio;                    // DevKit VSPI defaults
#else
rc522hce::Rc522HceReader radio(10, 9, 13, 12, 11); // UNO/Nano hardware SPI
                                                   // (Mega: 53, 5, 52, 50, 51)
#endif
rc522hce::HceReader reader(radio);                 // configure once…

void setup() {
    Serial.begin(115200);
    if (!reader.begin()) {
        Serial.println("RC522 not responding — check wiring + 3.3 V");
    }
}

void loop() {
    rc522hce::HceReader::Tap tap;
    if (reader.read(tap, millis())) {              // …then just read
        if (tap.isHce) {
            // POST tap.credentialId + tap.proof.nonceHex + tap.proof.macHex
            // to your server; it recomputes HMAC-SHA256(K_cred, credId || nonce).
        } else {
            // physical card: tap.credentialId is the uppercase hex UID.
        }
    }
}
```

Enrollment (pairing a new phone) is one call — normal taps never ask the
phone for its key:

```cpp
reader.setEnrollment(true, readerSecret);   // enrollment mode on
// …taps now also fetch + wrap the phone's key into tap.proof…
reader.setEnrollment(false);                // back to normal
```

Need the lower layers directly? `radio.poll(id)` + `radio.lastKind()` /
`radio.lastProof()`, `CardDebouncer`, and `MockNfcReader` (same interface,
`pushTap("...")` then `poll()` — for dev without hardware) are all public.

> **Tap distance:** a phone must sit **2–3 cm above the sensor**, flat and
> steady until the tap registers (~half a second — an HCE tap is a whole
> conversation, not a card blip). Too far, pressed flat against the reader,
> or lifted early are the three most common "it doesn't read" causes. See
> `docs/WIRING.md`.

Custom timing:

```cpp
rc522hce::Rc522HceOptions opts;
opts.reinitIntervalMs = 5000;  // PCD retry + runtime probe cadence
opts.hceSettleMs = 400;        // park-and-activate radio-silence window
rc522hce::Rc522HceReader reader(/*ss=*/13, /*rst=*/255 /*3V3-strapped*/,
                                /*sck=*/14, /*miso=*/2, /*mosi=*/15,
                                &Serial, opts);
```

Randomness per board: on ESP32 the driver uses the hardware RNG
(`esp_random`) automatically. Other chips use a best-effort auto-seeded
fallback, and production firmware should inject its own noise source:

```cpp
uint32_t myNoise() { /* floating analog pin, radio RSSI, TRNG chip… */ return ...; }
rc522hce::Rc522HceReader reader(10, 9, 13, 12, 11, &Serial,
                                rc522hce::Rc522HceOptions(), myNoise);
```

The protocol, framing, debounce and retry logic is chip-independent pure C++
and behaves identically on every board — only pins and the RNG source vary.

Without hardware (dev/tests): `rc522hce::MockNfcReader` implements the same
`NfcReader` interface — wrap it in `HceReader` exactly like the radio.

## Phone-app contract

Your Android HCE app must implement `docs/HCE_PROTOCOL.md`:

- AID `F0010203040506`, `SELECT` → `HCE-OK 9000` (else `6A82`);
- `CHALLENGE` (`80 10 00 00 08 + nonce`) → `len + credId + MAC + 9000`,
  with `MAC = HMAC-SHA256(K_cred, credId || nonce)`;
- `ENROLL` (`80 20 00 00 20`) → `K_cred + 9000`, only inside the holder-opened
  enrollment window (else `6985`); no key yet → `6A88` on `CHALLENGE`.

Shared test vector (pinned in `test/` — verify your app against it):

| item | value |
|---|---|
| `K_cred` | `000102…1f` |
| `credId` | `PLS-K3Y7V3CT0R5Z` |
| `nonce` | `0123456789abcdef` |
| `MAC` | `ba6d0fbf5106f79257727819d19a17b7e15abc4b8a0d1bfe71cd76090488a295` |

## Tests

```sh
pio test -e native   # 78 tests, no board needed
```

Six suites: APDU wire contract (byte-exact builders, every parser shape),
crypto trust contract (RFC 4231 + FIPS vectors + tamper properties +
key-wrap + RNG seam), ISO-DEP RF contract (SAK, PCB classes, I-block
stripping, block resync), debounce rules, the transport contract incl.
simulated end-to-end HCE taps, and the facade contract (one read() per
physical tap, proof forwarding, enrollment, health).

## License

Apache License 2.0 — see [LICENSE](LICENSE). Commercial and private use,
modification and distribution allowed; contributions welcome via pull request.
