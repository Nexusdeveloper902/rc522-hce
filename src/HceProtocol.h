/**
 * HceProtocol.h — Android-HCE credential protocol over ISO-DEP (reader side).
 *
 * Byte-exact application layer for phone-as-credential identification with
 * an RC522 reader and an Android HCE app:
 *   SELECT AID F0010203040506, then an 8-byte CHALLENGE answered with
 *   len + credId + HMAC-SHA256(K_cred, credId || nonce) + 9000.
 *
 * Key model (per-credential keys): K_cred belongs to ONE phone credential
 * (Android Keystore on the phone). The reader NEVER holds it and verifies
 * nothing — it relays its nonce + the phone's MAC and the backend verifies
 * them with that credential's key. In pairing/enrollment mode only, the
 * ENROLL APDU collects the phone's key once and wrapKeyHex() seals it
 * under the reader's own secret before it touches the network.
 *
 * Pure C++ (no Arduino headers): every builder, parser, crypto primitive
 * and ISO-DEP frame helper is host-testable. The RF transport (RATS/ATS,
 * I-blocks, WTX) lives in Rc522HceReader, which owns the MFRC522 driver.
 */
#pragma once

#include <cstddef>
#include <stdint.h>
#include <string>

namespace rc522hce {

// --- Application layer ------------------------------------------------------
// Proprietary 'F' category AID: valid, collides with nothing production.
// Changing it breaks every installed phone app.
static const uint8_t AID[] = {0xF0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
static const size_t AID_LEN = sizeof(AID);

static const uint8_t CLA_PROTO = 0x00;  // SELECT AID
static const uint8_t INS_SELECT = 0xA4;
static const uint8_t CLA_AUTH = 0x80;  // auth commands
static const uint8_t INS_CHALLENGE = 0x10;
static const uint8_t INS_ENROLL = 0x20;  // one-time key hand-off (pairing only)

static const size_t NONCE_LEN = 8;      // reader challenge length
static const size_t HMAC_LEN = 32;      // HMAC-SHA256 length
static const size_t MAX_CRED_LEN = 32;  // longest credential id accepted
static const size_t KEY_LEN = 32;       // per-credential HMAC key
static const size_t KEY_NONCE_LEN = 16;  // key-wrap nonce (32 hex chars)

// RC522 FIFO = 64 B: every message below fits one I-block (~57 B INF),
// so no phone-side chaining is ever needed.

/** Builds: 00 A4 04 00 Lc AID (no Le). Returns bytes written (12), 0 when cap is short. */
size_t buildSelectAid(uint8_t* out, size_t cap);

/** Builds: 80 10 00 00 Lc nonce (no Le). Returns bytes written (13), 0 when cap is short. */
size_t buildChallenge(const uint8_t nonce[NONCE_LEN], uint8_t* out, size_t cap);

/**
 * Builds: 80 20 00 00 20 (Le = 32, no data). Returns bytes written (5),
 * 0 when cap is short. Sent ONLY in pairing mode, after CHALLENGE.
 */
size_t buildEnroll(uint8_t* out, size_t cap);

/** True when the response ends in 90 00 (at least the status word present). */
bool isOk(const uint8_t* resp, size_t len);

enum class SelectOutcome {
    Selected,    // "HCE-OK" + 9000: an HCE phone for our AID answered
    UnknownAid,  // 6A82: something else answered (wrong app / AID mismatch)
    Malformed,   // anything else: truncated, wrong payload, wrong SW
};

/** Classifies one SELECT AID response. Never throws. */
SelectOutcome parseSelectResponse(const uint8_t* resp, size_t len);

struct ChallengeResponse {
    bool ok = false;
    std::string credId;  // application-level identity (NOT the RF UID)
    uint8_t mac[HMAC_LEN];
};

/**
 * Parses one CHALLENGE response: len(1) + credId + HMAC(32) + 9000.
 * Returns true (and fills out) only on an exact-length, 9000-terminated
 * frame. The RF UID plays no role here by construction — these parsers
 * do not even take one.
 */
bool parseChallengeResponse(const uint8_t* resp, size_t len, ChallengeResponse& out);

/**
 * True when the phone answered 6A88: it has no provisioned key yet (or
 * lost it — reinstall). The operator fix is enrollment, not a retry.
 */
bool isKeyMissing(const uint8_t* resp, size_t len);

/**
 * Parses one ENROLL response: key(32) + 9000, exact length. Fills key
 * only on success. 6985 = the phone's enrollment window is closed.
 */
bool parseEnrollResponse(const uint8_t* resp, size_t len, uint8_t key[KEY_LEN]);

/** HMAC-SHA256 (compact implementation, no dependencies). */
void hmacSha256(const uint8_t* key, size_t keyLen,
                const uint8_t* msg, size_t msgLen,
                uint8_t out[HMAC_LEN]);

/**
 * Raw SHA-256 of a byte string (same compact implementation the HMAC
 * above is built on).
 */
void sha256Bytes(const uint8_t* data, size_t len, uint8_t out[HMAC_LEN]);

/** Lowercase hex of raw bytes. Never throws. */
std::string toHex(const uint8_t* data, size_t len);

/** sha256hex(bytes) — the hash primitive (fingerprints, body hashes). */
std::string sha256Hex(const std::string& data);

/**
 * Fill `len` bytes from a 32-bit random-word source (portable RNG seam).
 * Little-endian byte order per word: the first byte out is bits [7:0] of
 * the first word. The caller owns freshness — pass a hardware TRNG where
 * one exists (esp_random on ESP32); the deterministic stub below makes the
 * byte layout unit-testable on the host. Never throws; no-op on null out
 * or null source.
 */
void fillRandomBytes(uint8_t* out, size_t len, uint32_t (*randomWord)());

/**
 * Wrap a phone key for the pairing request (hex, 64 chars):
 *   key XOR HMAC-SHA256(readerSecret,
 *       "pulse-hce-key-wrap/v1\n" || credId || "\n" || keyNonceHex)
 * keyNonceHex must be fresh per pairing (lowercase hex, 32 chars).
 */
std::string wrapKeyHex(const std::string& readerSecret,
                       const std::string& credId,
                       const std::string& keyNonceHex,
                       const uint8_t key[KEY_LEN]);

// --- ISO-DEP / RF helpers (pure; bench-proven in Rc522HceReader) -------------
// These encode the three bench-proven facts that make HCE-over-RC522 work, as testable predicates instead of inline
// bit-twiddling inside the Arduino driver:
//
//  1. SAK bit 6 set + bit 3 clear ((sak & 0x24) == 0x20) promises ISO-DEP.
//  2. A 5-byte CRC-valid answer is ambiguous by LENGTH alone: PCB decides
//     between a bare-status I-block (phone's app answered, e.g. 6A82 =
//     AID not routed — an app/routing problem) and S(WTX) (phone asks
//     for MORE time — a reader-side protocol gap to answer).
//  3. A salvaged I-block must be stripped (PCB [+ CID] [+ NAD] + CRC) to
//     the INF field the transport would have returned, and the block
//     number resynced from the phone's own answer.

/** True when SAK promises ISO-DEP: T=CL offered (bit 6) + UID complete (bit 3 clear). */
bool sakPromisesIsoDep(uint8_t sak);

/** ISO-DEP PCB classes (ISO/IEC 14443-4 section 7.1). */
bool isIBlock(uint8_t pcb);       // (pcb & 0xC0) == 0x00 — carries app data
bool isRBlock(uint8_t pcb);       // ACK/NAK, carries no app data
bool isWtxRequest(uint8_t pcb);   // S(WTX): (pcb & 0xC0)==0xC0 && (pcb & 0x30)==0x30

/** True for a full-frame WTX request (PCB [+ CID] + INF + CRC, min 5 B). */
bool isWtxFrame(const uint8_t* frame, size_t len);

/**
 * Locate the INF field of a raw ISO-DEP I-block frame.
 * On success sets infOffset/infLen (frame[infOffset..infOffset+infLen) is
 * exactly what TCL_Transceive would have returned) and returns true.
 * Rejects non-I-blocks, prologue+CRC-only frames, and INF larger than
 * respCap (mirrors STATUS_NO_ROOM).
 */
bool stripIBlock(const uint8_t* frame, size_t frameLen, size_t respCap,
                 size_t& infOffsetOut, size_t& infLenOut);

/**
 * Next block number to SEND after receiving PCB (resync from the phone's
 * own answer: it echoes the block number it received, so ours is the
 * opposite). Forgets driver state — self-correcting even after a lost frame.
 */
bool nextBlockNumber(uint8_t receivedPcb);

/** Shortest frame worth reading: PCB + SW(2) + CRC(2); also an S(WTX) with CID. */
static const size_t MIN_ISO_DEP_FRAME = 5;

}  // namespace rc522hce
