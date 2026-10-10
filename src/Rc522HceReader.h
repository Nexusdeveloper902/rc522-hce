/**
 * Rc522HceReader.h — RC522 NFC reader with Android-HCE identification.
 *
 * Concrete NfcReader: MFRC522 over SPI (miguelbalboa/rfid Arduino library),
 * plus the application-level HCE exchange that turns an Android phone into
 * an identified credential:
 *   SELECT AID F0010203040506 + random 8-byte CHALLENGE, whose
 *   HMAC-SHA256(K_cred, credId || nonce) answer is RELAYED to the server
 *   (lastProof()) — this reader holds no HCE key. In enrollment mode it
 *   also fetches the phone's key once (ENROLL) and wraps it. The phone's RF
 *   UID is randomized per tap by Android: it is logged only as a length
 *   and NEVER used as identity — lastKind() reports "hce" and poll()
 *   returns the application-level credential id instead.
 *
 * Two credential paths, one poll():
 *   physical — a MIFARE Classic UID read off the RF layer;
 *   hce      — ISO-DEP phone, identity from the APDU exchange.
 *
 * Robustness: the reader tracks its own health. A failed init (wiring,
 * power) or a reader that dies at runtime is retried on the reinit
 * cadence — non-blocking, so the device self-heals without a reboot.
 * Diagnostic events go to the injected Print stream (Serial in production)
 * or nowhere if none is injected.
 *
 * Device-only (needs an Arduino core + the MFRC522 Arduino library). Not
 * compiled by the host tests by design; all protocol bytes it speaks are
 * covered host-side via HceProtocol.
 *
 * Portable across microcontrollers: the ONLY chip-specific dependency ever
 * was the random source (originally ESP32 esp_random). Randomness is now an
 * injected 32-bit-word function — ESP32 boards default to esp_random(),
 * every other Arduino core defaults to a best-effort portable fallback
 * (auto-seeded Arduino PRNG), and production firmware on RNG-less chips
 * should inject its own noise source (floating analog pin, radio RSSI,
 * dedicated TRNG — see RandomWordFn). Protocol, framing, debounce and
 * retry logic are chip-independent pure C++ and behave identically
 * everywhere.
 *
 * Bench-proven constraints (read before touching the HCE path):
 *  1. Once THIS controller is HaltA'd it answers NOTHING (RATS, WUPA, even
 *     REQA) until field re-entry. Every post-halt retry is aimed at a corpse.
 *  2. Discovery NEVER uses ReadCardSerial (it fires RATS microseconds after
 *     SELECT and HaltAs on timeout, poisoning the tap's only winnable
 *     chance): the qualified base Select does anticollision + SELECT with
 *     NO RATS and NO surprise HaltA.
 *  3. Hence: the FIRST RATS of a tap goes out LATE (~400 ms after
 *     discovery), on an undisturbed selected session, with no HaltA before
 *     it. If the controller needs boot time after field entry, this is
 *     where it gets it.
 *  4. The driver's stock 25 ms RX timer is load-bearing-short: it makes the
 *     driver bail BEFORE a late S(WTX) arrives, leaving the frame to the
 *     S-block-aware salvage path. Widening it makes the driver consume and
 *     mangle the WTX itself (0% SELECT). The HCE exchange therefore clamps
 *     the window to 5 ms (transmit-only driver; reception is ours).
 *  5. Max receiver gain (48 dB) is THE standard RC522-vs-phone fix: plenty
 *     for cards, required for a phone's weak load modulation.
 *  6. SPI at 1 MHz, not the library's 4 MHz default, over Dupont jumpers
 *     on a rail that sags during RF TX (-DMFRC522_SPICLOCK=1000000u).
 *
 * All wiring and timing is explicit constructor parameters with
 * ESP32-VSPI-compatible defaults, so any board/app can use it.
 */
#pragma once

#include <Arduino.h>

#include <MFRC522Extended.h>
#include <SPI.h>
#include <cstring>       // memcpy/memset — ISO-DEP frame stripping

#ifdef ESP32
#include <esp_system.h>  // esp_random() — hardware RNG, ESP32 default only
#endif

#include "HceProtocol.h"
#include "NfcReader.h"

// There is NO HCE secret on the reader. Each phone has its own key
// (Android Keystore) and the server verifies the relayed transcript
// with it.

namespace rc522hce {

// Default pins match the classic ESP32 DevKit VSPI wiring. Pass your own
// pins for any other board (e.g. UNO: SS 10, RST 9, SCK 13, MISO 12,
// MOSI 11 — see docs/WIRING.md).
static const uint8_t kDefaultSsPin = 5;
static const uint8_t kDefaultRstPin = 27;  // pass 255 (UNUSED_PIN) when RST is strapped to 3V3
static const uint8_t kDefaultSckPin = 18;
static const uint8_t kDefaultMisoPin = 19;
static const uint8_t kDefaultMosiPin = 23;

struct Rc522HceOptions {
    uint32_t reinitIntervalMs = 5000;  // PCD retry + runtime probe cadence
    uint32_t hceSettleMs = 400;        // park-and-activate radio-silence window
};

/**
 * 32-bit random-word source. The driver needs fresh nonces per tap
 * (CHALLENGE) and per enrollment (key-wrap): inject whatever trustworthy
 * noise the board has — esp_random on ESP32, radio RSSI, a floating
 * analog pin folded in by the app, a dedicated TRNG chip. Signature is a
 * plain function pointer so it works on every Arduino core (no std::function).
 */
using RandomWordFn = uint32_t (*)();

#ifdef ESP32
inline uint32_t defaultRandomWord() { return esp_random(); }
#else
inline uint32_t defaultRandomWord() {
    // Portable best-effort fallback: Arduino PRNG, auto-seeded once from
    // timing jitter + floating-pin noise. Fine for nonces on hobby builds;
    // production firmware on RNG-less chips should inject a stronger source.
    static bool seeded = false;
    if (!seeded) {
        seeded = true;
        uint32_t seed = micros() ^ (static_cast<uint32_t>(millis()) << 16);
#ifdef A0
        seed ^= static_cast<uint32_t>(analogRead(A0));
        seed = seed * 1664525u + 1013904223u;  // mix the slow-moving ADC bits
#endif
        randomSeed(seed);
    }
    return (static_cast<uint32_t>(random(0, 0x7FFF)) << 17) ^
           (static_cast<uint32_t>(random(0, 0x7FFF)) << 2) ^
           static_cast<uint32_t>(random(0, 4));
}
#endif

class Rc522HceReader : public NfcReader {
public:
    // rstPin of 255 (MFRC522 UNUSED_PIN) means RST is strapped to 3V3 —
    // PCD_Init then uses soft reset only, no pin driven.
    explicit Rc522HceReader(uint8_t ssPin = kDefaultSsPin,
                            uint8_t rstPin = kDefaultRstPin,
                            uint8_t sckPin = kDefaultSckPin,
                            uint8_t misoPin = kDefaultMisoPin,
                            uint8_t mosiPin = kDefaultMosiPin,
                            Print* log = nullptr,
                            Rc522HceOptions options = Rc522HceOptions(),
                            RandomWordFn randomWord = defaultRandomWord)
        : mfrc522_(ssPin, rstPin),
          sckPin_(sckPin),
          misoPin_(misoPin),
          mosiPin_(mosiPin),
          ssPin_(ssPin),
          log_(log),
          options_(options),
          randomWord_(randomWord != nullptr ? randomWord : defaultRandomWord) {}

    void setLog(Print* log) { log_ = log; }

    bool begin() override {
#ifdef ESP32
        // Explicit pins: non-default wiring is changed at construction.
        SPI.begin(sckPin_, misoPin_, mosiPin_, ssPin_);
#else
        // Other cores use their fixed hardware-SPI pins (arbitrary
        // SCK/MOSI/MISO routing is an ESP32 feature); SS stays freely
        // choosable and is driven by the MFRC522 driver.
        pinMode(ssPin_, OUTPUT);
        SPI.begin();
#endif
        return reinit(millis());
    }

    bool poll(std::string& idOut) override {
        if (!healthy_) {
            // Reader not talking (failed init, or died later: wiring
            // glitch, ESD, brown-out). Retry on the configured cadence —
            // non-blocking, wrap-safe unsigned arithmetic.
            const uint32_t now = millis();
            if (now - lastInitAttemptMs_ >= options_.reinitIntervalMs) {
                reinit(now);  // logs the recovery when it succeeds
            }
            return false;
        }

        // Runtime health probe: "healthy" is only meaningful if it can be
        // REVOKED. A VersionReg read is one register transaction: every
        // reinitIntervalMs it re-verifies the chip, and a dead chip flips
        // healthy_ so the reinit branch above takes over. Probed at the TOP
        // of poll() — never between IsNewCardPresent and ReadCardSerial.
        const uint32_t now = millis();
        if (now - lastProbeMs_ >= options_.reinitIntervalMs) {
            lastProbeMs_ = now;
            version_ = mfrc522_.PCD_ReadRegister(MFRC522::PCD_Register::VersionReg);
            if (version_ == 0x00 || version_ == 0xFF) {
                healthy_ = false;  // chip stopped answering — reinit cadence engages
                if (log_) {
                    log_->println("[NFC] RC522 stopped responding at runtime — retrying");
                }
                return false;
            }
        }

        if (hceSettling_) {
            if (millis() - hceSeenMs_ < options_.hceSettleMs) {
                // Radio silence till settle ends — but NEVER spin: this
                // branch does zero RF and zero delay, and a ~100 kHz
                // no-yield spin trips the task watchdog (observed
                // TG1WDT_SYS_RESET mid-settle on the bench). delay()
                // yields; 5 ms granularity is plenty for a 400 ms window.
                delay(5);
                return false;
            }
            hceSettling_ = false;
            // Reset-locator: adoptAts() calls PICC_RequestATS BEFORE it logs
            // anything, so a TG1WDT reset between "spotted" and the RATS
            // verdict is ambiguous without this line — it splits the settle
            // loop from the vendor driver's RATS.
            if (log_) {
                log_->println("[NFC] settle elapsed — firing RATS now");
            }
            adoptAts(options_.hceSettleMs);
        } else {
            if (!mfrc522_.PICC_IsNewCardPresent()) {
                return false;
            }
            if (mfrc522_.MFRC522::PICC_Select(&mfrc522_.tag.uid) != MFRC522::STATUS_OK) {
                return false;
            }
            if (sakPromisesIsoDep(mfrc522_.tag.uid.sak) && atsMissing()) {
                // ISO-DEP sighted. Park it UNTOUCHED (no RATS yet, no
                // HaltA — both would end the session before it starts):
                // the target stays selected while its controller finishes
                // booting HCE routing. A card tapped during these ~ms
                // waits one settle window — bounded, rare, accepted.
                hceSeenMs_ = millis();
                hceSettling_ = true;
                if (log_) {
                    log_->print("[NFC] HCE target spotted, settling ");
                    log_->print(options_.hceSettleMs);
                    log_->println(" ms (radio silence till then)");
                }
                return false;
            }
        }

        // One line per target BEFORE branching, so a failed phone tap tells
        // which side failed without guessing:
        //   SAK=0x08 ATS=0B → the phone is not offering ISO-DEP at all
        //     (HCE service not engaged: app state, NFC, or device support).
        //   SAK=0x20 ATS=0B → RATS adoption failed (read the RATS status
        //     lines above: TIMEOUT = phone mute/halted, else signal).
        // SAK=0x20 + ATS>0 continues into the HCE branch below.
        if (log_) {
            log_->print("[NFC] target SAK=0x");
            if (mfrc522_.tag.uid.sak < 0x10) {
                log_->print('0');
            }
            log_->print(mfrc522_.tag.uid.sak, HEX);
            log_->print(" ATS=");
            log_->print(mfrc522_.tag.ats.size);
            log_->print("B UID=");
            log_->print(mfrc522_.tag.uid.size);
            log_->println("B");
        }

        // HCE: SAK bit 6 set + ATS present means an ISO-DEP target (an
        // Android HCE phone) — the APDU exchange decides the identity,
        // never the RF UID below. The SAK test mirrors the driver's own
        // ((sak & 0x24) == 0x20): T=CL offered AND UID complete.
        if (sakPromisesIsoDep(mfrc522_.tag.uid.sak)) {
            if (atsMissing()) {
                // A SAK=0x20 target whose RATS failed used to FALL THROUGH
                // to the MIFARE branch below, which hexes tag.uid and
                // reports it as a real tap. On an Android phone that UID is
                // an OS-assigned RANDOM id (08-prefixed NFC Forum random-ID
                // range): a different value every tap, meaningless as a
                // credential. A phone that did not activate is a FAILED TAP,
                // never a card.
                if (log_) {
                    log_->println("[NFC] ISO-DEP target but no ATS (RATS failed) — failed tap, not a card");
                }
                mfrc522_.PICC_HaltA();
                return false;
            }
            return pollHce(idOut);
        }

        // Physical card: hex the UID off the RF layer.
        idOut.clear();
        idOut.reserve(mfrc522_.tag.uid.size * 2);
        static const char* hex = "0123456789ABCDEF";
        for (byte i = 0; i < mfrc522_.tag.uid.size; ++i) {
            idOut += hex[mfrc522_.tag.uid.uidByte[i] >> 4];
            idOut += hex[mfrc522_.tag.uid.uidByte[i] & 0x0F];
        }
        lastKind_ = "physical";
        lastProof_.clear();

        // Release the card and stop any crypto session so the next tap works.
        mfrc522_.PICC_HaltA();
        mfrc522_.PCD_StopCrypto1();
        return true;
    }

    const char* label() const override { return "RC522 (SPI) + HCE"; }

    const char* lastKind() const override { return lastKind_; }

    const HceProof& lastProof() const override { return lastProof_; }

    void setEnrollment(bool on, const std::string& wrapSecret) override {
        enrollment_ = on;
        wrapSecret_ = on ? wrapSecret : std::string();
    }

    /** True when the last VersionReg probe answered. */
    bool healthy() const override { return healthy_; }

    /** Last PCD firmware-version byte seen (0 when never probed). */
    uint8_t lastVersion() const { return version_; }

private:
    /**
     * HCE tap: SELECT the AID, challenge the phone with a fresh random
     * nonce, and capture its len + credId + MAC answer as the relay proof
     * (lastProof_). NOT verified here — the reader holds no key; the server
     * checks it with the credential's own key. In enrollment mode, ENROLL
     * then fetches the phone's key, which is wrapped under this reader's
     * secret and wiped from RAM. On success idOut holds the
     * application-level credential id and lastKind_ is "hce". Any failure
     * releases the target and returns false — a MIFARE tap is never
     * affected (that path never runs here).
     */
    bool pollHce(std::string& idOut) {
        // The phone randomizes its RF UID per tap (Android HCE): log the
        // length only, to prove discovery while proving nothing uses it.
        if (log_) {
            log_->print("[NFC] ISO-DEP target, UID ");
            log_->print(mfrc522_.tag.uid.size);
            log_->println(" bytes (random per tap on HCE, ignored as identity)");
        }

        // From here the driver TRANSMITS ONLY — we own every byte received.
        setPcdTimeoutMs(kHceTxOnlyTimeoutMs);

        uint8_t cmd[16], resp[64];
        uint8_t respLen = sizeof(resp);
        const uint8_t cmdLen = static_cast<uint8_t>(buildSelectAid(cmd, sizeof(cmd)));
        // BEWARE the mutual-timeout race (bench-proven): our RX window is
        // only ~10 ms, while a warm app answer takes several ms via
        // controller → DH → app → DH → controller — and the PHONE runs
        // its own frame-wait timer, tearing the session down if our next
        // block is late. So retries go TIGHT (~15 ms apart): continuous RX
        // coverage for slow answers AND each arrival resets the phone's
        // timer, keeping the session alive. Safe by driver construction:
        // the block number toggles ONLY on success, so a timed-out attempt
        // reuses the number the phone expects; and our SELECT is idempotent
        // app-side anyway.
        MFRC522::StatusCode sc =
            tclWithRetries(cmd, cmdLen, resp, &respLen, sizeof(resp), 10, 15, "SELECT");
        if (sc != MFRC522::STATUS_OK) {
            if (log_) {
                log_->print("[NFC] HCE SELECT failed: ");
                log_->println(mfrc522_.GetStatusCodeName(sc));
            }
            releaseHce();
            return false;
        }
        const SelectOutcome outcome = parseSelectResponse(resp, respLen);
        if (outcome != SelectOutcome::Selected) {
            if (log_) {
                // A MALFORMED answer is a reader-side framing/read fault,
                // NOT the phone refusing our AID. Never conflate them.
                if (outcome == SelectOutcome::UnknownAid) {
                    log_->println("[NFC] HCE SELECT -> 6A82: the phone routed no app to our AID (not our phone, or HCE routing off)");
                } else {
                    log_->print("[NFC] HCE SELECT malformed answer (");
                    log_->print(respLen);
                    log_->println("B INF) — reader-side framing fault, not the phone");
                }
            }
            releaseHce();
            return false;
        }

        // Fresh random challenge per tap. The nonce travels in the clear
        // over NFC, so logging it is safe. No key is involved on this side.
        uint8_t nonce[NONCE_LEN];
        fillRandomBytes(nonce, NONCE_LEN, randomWord_);
        if (log_) {
            log_->print("[NFC] HCE challenge nonce: ");
            for (size_t i = 0; i < NONCE_LEN; i++) {
                if (nonce[i] < 0x10) {
                    log_->print('0');
                }
                log_->print(nonce[i], HEX);
                if (i + 1 < NONCE_LEN) {
                    log_->print(' ');
                }
            }
            log_->println();
        }
        const uint8_t chalLen = static_cast<uint8_t>(buildChallenge(nonce, cmd, sizeof(cmd)));
        respLen = sizeof(resp);
        // Same race as SELECT: session is live and warm here, so fewer,
        // slightly wider-spaced attempts suffice.
        sc = tclWithRetries(cmd, chalLen, resp, &respLen, sizeof(resp), 6, 25, "CHALLENGE");
        if (sc != MFRC522::STATUS_OK) {
            if (log_) {
                log_->print("[NFC] HCE CHALLENGE timeout: ");
                log_->println(mfrc522_.GetStatusCodeName(sc));
            }
            releaseHce();
            return false;
        }

        ChallengeResponse answer;
        if (!parseChallengeResponse(resp, respLen, answer)) {
            if (log_) {
                if (isKeyMissing(resp, respLen)) {
                    log_->println("[NFC] HCE phone has NO key yet (6A88) — enroll it first");
                } else {
                    log_->println("[NFC] HCE CHALLENGE answer malformed");
                }
            }
            releaseHce();
            return false;
        }

        lastProof_.clear();
        lastProof_.nonceHex = toHex(nonce, NONCE_LEN);
        lastProof_.macHex = toHex(answer.mac, HMAC_LEN);

        if (enrollment_ && !collectKey(answer.credId, cmd, sizeof(cmd), resp, sizeof(resp))) {
            lastProof_.clear();
            releaseHce();
            return false;
        }

        // Identified (proof relayed, verified server-side): the credential
        // id — never the RF UID — is the tap.
        idOut = answer.credId;
        lastKind_ = "hce";
        if (log_) {
            log_->print("[NFC] HCE credential read (proof relayed to server): ");
            log_->println(idOut.c_str());
        }
        releaseHce();
        return true;
    }

    /** True while no ATS has been adopted yet (tag.ats.size == 0). */
    bool atsMissing() const { return mfrc522_.tag.ats.size == 0; }

    /**
     * Adopt the ATS the driver drops (the actual bench blocker).
     *
     * MFRC522 1.4.12's PICC_Select parses a good ATS into a STACK LOCAL
     * and never stores it in tag — so tag.ats.size is ALWAYS 0 through
     * the driver path, and any `ats.size > 0` gate is dead code with this
     * library version. RATS itself was almost certainly succeeding all
     * along: the phone answers, the driver even PPS-negotiates internally —
     * then throws the bytes away.
     *
     * Fix: re-request RATS on the still-selected target (a legal RATS
     * retransmission) and keep the result in tag.ats ourselves, where
     * TCL_Transceive expects it. The logged status is also the first honest
     * RATS diagnosis on this bench: STATUS_TIMEOUT = phone mute/halted,
     * anything else = signal trouble. Deliberately no PPS: 106 kbit/s is
     * mandatory and plenty for our <70 B exchanges — one less moving part.
     */
    void adoptAts(uint32_t settleMs) {
        MFRC522Extended::Ats ats;
        memset(&ats, 0, sizeof(ats));
        const MFRC522::StatusCode sc = mfrc522_.PICC_RequestATS(&ats);
        if (log_) {
            log_->print("[NFC] RATS (settle ");
            log_->print(settleMs);
            log_->print(" ms) -> ");
            log_->print(mfrc522_.GetStatusCodeName(sc));
            if (sc == MFRC522::STATUS_OK) {
                log_->print(" ATS=");
                log_->print(ats.size);
                log_->print("B");
            }
            log_->println();
        }
        if (sc == MFRC522::STATUS_OK && ats.size > 1) {
            mfrc522_.tag.ats = ats;
            mfrc522_.tag.blockNumber = false;
        }
    }

    /**
     * I-block exchange with bounded same-block retries (see pollHce).
     * Each attempt is logged; only the final outcome decides. MIFARE
     * never calls this (UID path only).
     *
     * Bench fact driving the salvage below: the phone DOES answer SELECT,
     * ~13-16 ms after our TX — just late, after our ~10 ms RX window
     * closed. So on every TCL timeout we wait out the slow answer and
     * harvest it straight from the FIFO with our own CRC check (CRC gates
     * everything: a partial/garbled harvest can never false-accept).
     * Attempts stay tight (~15-25 ms apart) so each arrival also resets
     * the phone's frame-wait timer and the session stays alive.
     */
    MFRC522::StatusCode tclWithRetries(uint8_t* cmd, uint8_t cmdLen,
                                       uint8_t* resp, uint8_t* respLen, uint8_t respCap,
                                       uint8_t attempts, uint16_t retryDelayMs,
                                       const char* what) {
        MFRC522::StatusCode sc = MFRC522::STATUS_TIMEOUT;
        for (uint8_t i = 0; i < attempts; ++i) {
            if (i > 0) {
                delay(retryDelayMs);
            }
            *respLen = respCap;
            sc = mfrc522_.TCL_Transceive(&mfrc522_.tag, cmd, cmdLen, resp, respLen);
            if (sc != MFRC522::STATUS_OK && log_) {
                log_->print("[NFC] HCE ");
                log_->print(what);
                log_->print(" try ");
                log_->print(i + 1);
                log_->print(" -> ");
                log_->println(mfrc522_.GetStatusCodeName(sc));
                dumpRxState();
            }
            if (sc != MFRC522::STATUS_OK) {
                sc = salvageLateAnswer(resp, respLen, respCap, what);
            }
            if (sc == MFRC522::STATUS_OK) {
                break;
            }
        }
        return sc;
    }

    /**
     * Harvest a slow answer that finished arriving after our RX window
     * closed (see tclWithRetries). Waits out the phone's DH/app path,
     * then reads whatever sits in the FIFO and CRC-checks it exactly
     * like the driver would. Returns OK only on a complete,
     * CRC-valid frame — anything else keeps the attempt's verdict.
     * Read-only w.r.t. protocol state (no block-number/sequence side
     * effects); the next retry re-flushes the FIFO regardless.
     *
     * Two bench facts this function exists to handle:
     *  1. The phone answers SELECT correctly but LATE in a full ISO-DEP
     *     frame (PCB + CID + INF + CRC). Harvesting the FIFO ourselves
     *     does not strip prologue/CRC, so we MUST strip them here (see
     *     stripIBlock — host-tested).
     *  2. Most taps answer S(WTX): "I need more time." MFRC522Extended
     *     never answers WTX, so the exchange died there every time. Per
     *     ISO/IEC 14443-4 the PCD must echo an S(WTX) response and keep
     *     waiting — then the app's real answer follows.
     */
    MFRC522::StatusCode salvageLateAnswer(uint8_t* resp, uint8_t* respLen, uint8_t respCap,
                                          const char* what) {
        uint8_t frame[64];
        for (uint8_t round = 0; round < kMaxWtxRounds; ++round) {
            const uint8_t n = awaitFifoFrame(kSalvageBudgetMs);
            if (n < MIN_ISO_DEP_FRAME || n > sizeof(frame)) {
                return MFRC522::STATUS_TIMEOUT;  // nothing (complete) arrived late
            }
            for (uint8_t i = 0; i < n; ++i) {
                frame[i] = mfrc522_.PCD_ReadRegister(MFRC522::FIFODataReg);
            }
            uint8_t check[2];
            if (mfrc522_.PCD_CalculateCRC(frame, n - 2, check) != MFRC522::STATUS_OK ||
                check[0] != frame[n - 2] || check[1] != frame[n - 1]) {
                if (log_) {
                    log_->print("[NFC] HCE ");
                    log_->print(what);
                    log_->print(" salvage ");
                    log_->print(n);
                    log_->println("B arrived late but CRC-failed");
                }
                return MFRC522::STATUS_CRC_WRONG;
            }
            if (log_) {
                log_->print("[NFC] HCE ");
                log_->print(what);
                log_->print(" salvaged ");
                log_->print(n);
                log_->print("B late answer, CRC ok: ");
                if (redactFrames_) {
                    log_->println("<redacted: key material>");  // ENROLL carries the key
                } else {
                    logFrame(frame, n);
                }
            }

            // S(WTX) request: grant it and go round again for the real answer.
            if (isWtxFrame(frame, n)) {
                if (!answerWtx(frame, n)) {
                    return MFRC522::STATUS_ERROR;
                }
                continue;
            }

            // I-block: strip PCB [+ CID] [+ NAD] and trailing CRC (host-tested).
            size_t off = 0, infLen = 0;
            if (!stripIBlock(frame, n, respCap, off, infLen)) {
                return MFRC522::STATUS_TIMEOUT;  // R-block/DESELECT or no room: no app data
            }
            memcpy(resp, &frame[off], infLen);
            *respLen = static_cast<uint8_t>(infLen);
            if (redactFrames_) {
                memset(frame, 0, sizeof(frame));  // key-bearing copy off the stack
            }

            // RESYNC THE BLOCK NUMBER — the bug that made every salvaged
            // tap die at CHALLENGE. TCL_Transceive advances tag.blockNumber
            // ONLY on its own success, so every salvaged frame took its
            // early return with the driver still on block 0 while the phone
            // — having answered SELECT — already expected 1. Resync from the
            // phone's own answer (host-tested nextBlockNumber): it echoes
            // the block number it received, so the next block we send is
            // the opposite. Self-correcting even after a lost frame.
            mfrc522_.tag.blockNumber = nextBlockNumber(frame[0]);
            return MFRC522::STATUS_OK;
        }
        if (log_) {
            log_->println("[NFC] HCE phone kept asking for more time (WTX rounds exhausted)");
        }
        return MFRC522::STATUS_TIMEOUT;
    }

    /**
     * Poll the FIFO until a complete frame has landed, instead of blindly
     * sleeping out the worst case. A level that stops growing across two
     * polls is a finished frame (the CRC check downstream is the real gate).
     */
    uint8_t awaitFifoFrame(uint16_t budgetMs) {
        const uint32_t deadline = millis() + budgetMs;
        uint8_t last = 0;
        uint8_t stable = 0;
        while (static_cast<int32_t>(millis() - deadline) < 0) {
            const uint8_t n = mfrc522_.PCD_ReadRegister(MFRC522::FIFOLevelReg);
            if (n >= MIN_ISO_DEP_FRAME && n == last) {
                if (++stable >= 2) {
                    return n;
                }
            } else {
                stable = 0;
            }
            last = n;
            delay(2);  // yields — never spin (TG1WDT_SYS_RESET, bench-observed)
        }
        return last >= MIN_ISO_DEP_FRAME ? last : 0;
    }

    /**
     * Answer an S(WTX) request (ISO/IEC 14443-4): same PCB, echo the CID
     * when present, return the requested WTXM with power-level bits
     * cleared. The reply is frame-identical to the request for WTXM=1,
     * which is what phones ask for.
     */
    bool answerWtx(const uint8_t* req, uint8_t reqLen) {
        uint8_t out[5];
        uint8_t i = 0;
        out[i++] = req[0];
        uint8_t infIdx = 1;
        if (req[0] & 0x08) {
            out[i++] = req[1];  // echo CID
            infIdx = 2;
        }
        if (infIdx + 2u > reqLen) {
            return false;  // malformed WTX: no INF byte before the CRC
        }
        out[i++] = req[infIdx] & 0x3F;  // WTXM, power-level bits cleared
        if (mfrc522_.PCD_CalculateCRC(out, i, &out[i]) != MFRC522::STATUS_OK) {
            return false;
        }
        i += 2;
        uint8_t back[8];
        uint8_t backLen = sizeof(back);
        mfrc522_.PCD_TransceiveData(out, i, back, &backLen);
        if (log_) {
            log_->print("[NFC] HCE WTX granted (WTXM=");
            log_->print(out[infIdx] & 0x3F);
            log_->println(") — waiting for the app's real answer");
        }
        return true;
    }

    /**
     * Print a raw ISO-DEP frame and NAME its PCB class (ISO/IEC 14443-4).
     * A 5-byte CRC-valid answer is ambiguous by LENGTH ALONE:
     *   PCB + SW1 SW2 + CRC   → bare-status I-block (the phone's APP layer
     *     answered — 6A82 = AID not routed: an app/routing problem).
     *   PCB + CID + WTXM + CRC → S(WTX) request: the phone asks for MORE
     *     TIME (controller→DH→app path is slow, bench-measured 13-16 ms).
     * Both are exactly 5 bytes depending on CID presence, so the bytes
     * decide, never the length.
     */
    void logFrame(const uint8_t* f, uint8_t n) {
        for (uint8_t i = 0; i < n; ++i) {
            if (f[i] < 0x10) {
                log_->print('0');
            }
            log_->print(f[i], HEX);
            if (i + 1 < n) {
                log_->print(' ');
            }
        }
        const uint8_t pcb = f[0];
        if (isIBlock(pcb)) {
            log_->print("  -> I-block, SW=");
            if (f[n - 4] < 0x10) {
                log_->print('0');
            }
            log_->print(f[n - 4], HEX);
            if (f[n - 3] < 0x10) {
                log_->print('0');
            }
            log_->print(f[n - 3], HEX);
            log_->println(" (the phone's APP layer answered — 6A82 = AID not routed)");
        } else if (isRBlock(pcb)) {
            log_->println("  -> R-block (ACK/NAK, carries no app data)");
        } else if (isWtxRequest(pcb)) {
            log_->println("  -> S(WTX): phone asks for MORE TIME — the driver never answers it");
        } else {
            log_->println("  -> S(DESELECT): phone tore the session down");
        }
    }

    /** Post-failure receiver snapshot. Read-only. */
    void dumpRxState() {
        const uint8_t err = mfrc522_.PCD_ReadRegister(MFRC522::ErrorReg);
        const uint8_t irq = mfrc522_.PCD_ReadRegister(MFRC522::ComIrqReg);
        const uint8_t fifo = mfrc522_.PCD_ReadRegister(MFRC522::FIFOLevelReg);
        log_->print("[NFC] RX state ERR=0x");
        if (err < 0x10) {
            log_->print('0');
        }
        log_->print(err, HEX);
        log_->print(" IRQ=0x");
        if (irq < 0x10) {
            log_->print('0');
        }
        log_->print(irq, HEX);
        log_->print(" FIFO=");
        log_->print(fifo);
        log_->println("B");
    }

    /**
     * ENROLLMENT only: ENROLL → the phone's 32-byte key (the phone answers
     * only inside its user-opened enrollment window, else 6985), wrapped
     * at once under this reader's secret with a fresh nonce; the raw key
     * is wiped before return and is never logged.
     */
    bool collectKey(const std::string& credId, uint8_t* cmd, size_t cmdCap,
                    uint8_t* resp, size_t respCap) {
        if (wrapSecret_.empty()) {
            if (log_) {
                log_->println("[NFC] HCE enrollment: no reader secret to wrap with");
            }
            return false;
        }
        const uint8_t enrollLen = static_cast<uint8_t>(buildEnroll(cmd, cmdCap));
        uint8_t respLen = static_cast<uint8_t>(respCap);
        redactFrames_ = true;  // never print the ENROLL answer's bytes
        MFRC522::StatusCode sc = tclWithRetries(cmd, enrollLen, resp, &respLen,
                                                static_cast<uint8_t>(respCap), 6, 25, "ENROLL");
        redactFrames_ = false;
        uint8_t key[KEY_LEN];
        if (sc != MFRC522::STATUS_OK || !parseEnrollResponse(resp, respLen, key)) {
            if (log_) {
                log_->println("[NFC] HCE ENROLL refused — open the phone's enrollment window first, then tap again");
            }
            memset(resp, 0, respCap);
            return false;
        }
        uint8_t keyNonce[KEY_NONCE_LEN];
        fillRandomBytes(keyNonce, KEY_NONCE_LEN, randomWord_);
        lastProof_.keyNonceHex = toHex(keyNonce, KEY_NONCE_LEN);
        lastProof_.keyWrappedHex = wrapKeyHex(wrapSecret_, credId, lastProof_.keyNonceHex, key);
        memset(key, 0, sizeof(key));
        memset(resp, 0, respCap);  // the ENROLL frame held the raw key
        if (log_) {
            log_->println("[NFC] HCE key received and wrapped for pairing (never logged)");
        }
        return true;
    }

    void releaseHce() {
        setPcdTimeoutMs(kStockTimeoutMs);  // MIFARE needs the driver's RX back
        mfrc522_.TCL_Deselect(&mfrc522_.tag);
        mfrc522_.PICC_HaltA();
    }

    /**
     * Set the PCD receive timer (TReloadReg @ the 40 kHz timer PCD_Init
     * configures, so 40 ticks per ms).
     *
     * This is what makes the HCE exchange DETERMINISTIC instead of a coin
     * flip. Clamp the window BELOW the phone's fastest answer (measured
     * 13-16 ms) so the driver ALWAYS times out first and never drains the
     * FIFO — PCD_CommunicateWithPICC returns on the timer IRQ before it
     * ever reads FIFOLevelReg. The driver becomes a pure transmitter;
     * reception is entirely ours, where the S-block logic lives.
     *
     * DO NOT extend the timer to the phone's advertised FWT: the driver
     * then consumes the S(WTX) itself, mangles the frame (no S-block
     * notion) and empties the FIFO — SELECT succeeds on 0% of taps.
     * The library's "too short" timer is load-bearing.
     */
    void setPcdTimeoutMs(uint16_t ms) {
        uint32_t ticks = static_cast<uint32_t>(ms) * 40UL;
        if (ticks > 0xFFFF) {
            ticks = 0xFFFF;
        }
        mfrc522_.PCD_WriteRegister(MFRC522::TReloadRegH, static_cast<uint8_t>(ticks >> 8));
        mfrc522_.PCD_WriteRegister(MFRC522::TReloadRegL, static_cast<uint8_t>(ticks & 0xFF));
    }

    /**
     * (Re)initialize the MFRC522 and probe its VersionReg. Valid versions:
     * 0x91 (v1.0), 0x92 (v2.0); 0x90 / 0x88 show on some clones. 0x00 /
     * 0xFF mean the chip is not answering (wiring or power).
     */
    bool reinit(uint32_t now) {
        lastInitAttemptMs_ = now;
        mfrc522_.PCD_Init();
        // Max receiver gain: PCD_Init leaves the typical 33 dB default,
        // plenty for MIFARE cards but marginal for a phone's weak load
        // modulation (short SAK frames decode while longer ATS frames
        // CRC-fail → SAK=0x20 ATS=0B). 48 dB costs nothing for cards and
        // is THE standard RC522-vs-phone fix. Re-applied after every init
        // (PCD_Init resets the register).
        mfrc522_.PCD_SetAntennaGain(MFRC522::RxGain_max);
        version_ = mfrc522_.PCD_ReadRegister(MFRC522::PCD_Register::VersionReg);
        healthy_ = (version_ != 0x00 && version_ != 0xFF);

        if (log_) {
            if (healthy_) {
                log_->print("[NFC] RC522 detected — firmware version 0x");
                log_->print(version_ < 0x10 ? "0" : "");
                log_->print(version_, HEX);
                log_->println();
            } else {
                log_->print("[NFC] RC522 NOT responding (version 0x");
                log_->print(version_ < 0x10 ? "0" : "");
                log_->print(version_, HEX);
                log_->print(") — check wiring (SCK ");
                log_->print(sckPin_);
                log_->print(" / MISO ");
                log_->print(misoPin_);
                log_->print(" / MOSI ");
                log_->print(mosiPin_);
                log_->print(" / SDA ");
                log_->print(ssPin_);
                log_->print(") + power 3.3 V");
                log_->print(" — retrying every ");
                log_->print(options_.reinitIntervalMs / 1000);
                log_->println(" s");
            }
        }
        return healthy_;
    }

    MFRC522Extended mfrc522_;
    // Late-answer salvage. Budget covers the bench-measured 13-16 ms answer
    // latency with margin; the FIFO poll returns as soon as the frame is
    // complete, so the usual cost is far lower.
    static constexpr uint8_t kMinFrame = 5;
    static constexpr uint16_t kSalvageBudgetMs = 60;
    static constexpr uint8_t kMaxWtxRounds = 4;
    // Driver receive window: 5 ms sits far below the phone's fastest
    // measured answer (13 ms) and above our own ~1 ms frame transmission,
    // so the driver reliably gives up before anything lands. 25 ms is
    // PCD_Init's stock value, restored for the MIFARE path.
    static constexpr uint16_t kHceTxOnlyTimeoutMs = 5;
    static constexpr uint16_t kStockTimeoutMs = 25;
    uint32_t hceSeenMs_ = 0;
    bool hceSettling_ = false;
    uint8_t sckPin_;
    uint8_t misoPin_;
    uint8_t mosiPin_;
    uint8_t ssPin_;
    Print* log_;                 // nullable diagnostics sink
    Rc522HceOptions options_;
    const char* lastKind_ = "physical";
    HceProof lastProof_;         // relayed transcript (+ wrapped key in enrollment)
    bool enrollment_ = false;    // enrollment mode → ENROLL after CHALLENGE
    bool redactFrames_ = false;  // true while an ENROLL (key-bearing) exchange runs
    std::string wrapSecret_;     // this reader's secret, only while enrolling
    RandomWordFn randomWord_;    // nonce source (see RandomWordFn)

    bool healthy_ = false;       // last probe answered?
    uint8_t version_ = 0;        // last VersionReg byte seen
    uint32_t lastInitAttemptMs_ = 0;
    uint32_t lastProbeMs_ = 0;   // last runtime health probe (healthy path)
};

}  // namespace rc522hce
