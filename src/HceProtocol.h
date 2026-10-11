/**
 * HceProtocol.h — Android-HCE credential protocol over ISO-DEP (reader side).
 *
 * Byte-exact application layer for phone-as-credential identification with
 * an RC522 reader and an Android HCE app:
 *   SELECT AID F0010203040506, then a 16-byte CHALLENGE answered with
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

// --- Protocol version ---------------------------------------------------------
// v2 is what ships: 16-byte challenge nonces, MAC = HMAC-SHA256(K, id||nonce),
// ChaCha20-Poly1305 key wrap under label pulse-hce-key-wrap/v2. Any future
// incompatible change (nonce length, MAC input, enrollment semantics) MUST
// bump this and ship as a versioned migration — phone app, reader firmware,
// and backend migrate together, with a pinned test vector per version.
// Never change v2 wire bytes in place. (v1: 8-byte nonces + XOR-HMAC wrap,
// retired in 2.0.0 — no v1 code remains.)
static const uint32_t PROTOCOL_VERSION = 2;
static const uint32_t KEY_WRAP_VERSION = 2;
static const char* const KEY_WRAP_LABEL_V2 = "pulse-hce-key-wrap/v2\n";
static const char* const KEY_WRAP_ENC_LABEL_V2 = "pulse-hce-key-wrap/v2-enc\n";

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

static const size_t NONCE_LEN = 16;     // v2 reader challenge length (128-bit; see SECURITY.md)
static const size_t HMAC_LEN = 32;      // HMAC-SHA256 length
static const size_t MAX_CRED_LEN = 32;  // longest credential id accepted
static const size_t KEY_LEN = 32;       // per-credential HMAC key
static const size_t KEY_NONCE_LEN = 12;  // v2 key-wrap nonce, AEAD-standard 96-bit (24 hex chars)
// Minimum high-entropy reader-secret length for the key wrap (bytes of
// entropy, not characters of password). Human passwords NEVER qualify;
// generate per device with a CSPRNG (e.g. 16+ random bytes, hex-encoded).
static const size_t WRAP_SECRET_MIN_BYTES = 16;

// RC522 FIFO = 64 B: every message below fits one I-block (~57 B INF),
// so no phone-side chaining is ever needed.

/** Builds a SELECT AID command for an explicit AID. Returns 0 on bad args/short buffer. */
size_t buildSelectAidWith(const uint8_t* aid, size_t aidLen, uint8_t* out, size_t cap);

/** Builds: 00 A4 04 00 Lc AID (no Le). Returns bytes written (12), 0 when cap is short. */
size_t buildSelectAid(uint8_t* out, size_t cap);

// Longest AID the SELECT frame can carry while fitting the driver's
// command buffer (5-byte header + AID must stay <= 16 bytes).
static const size_t MAX_AID_LEN = 11;

/** Builds: 80 10 00 00 Lc nonce (no Le). Returns bytes written (21), 0 when cap is short. */
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
 * the first word. The caller owns freshness — pass an approved CSPRNG
 * (esp_random on ESP32; see docs/SECURITY.md "Randomness policy"). The
 * deterministic stub below exists ONLY to make the byte layout
 * unit-testable on the host; it is not a production nonce source.
 * Never throws; no-op on null out or null source.
 */
void fillRandomBytes(uint8_t* out, size_t len, uint32_t (*randomWord)());

/**
 * Wrap a phone key for the pairing request (hex, 120 chars) with the
 * vetted ChaCha20-Poly1305 AEAD (RFC 8439):
 *   ke   = HMAC-SHA256(readerSecret, "pulse-hce-key-wrap/v2-enc\n" || credId)
 *   aad  = "pulse-hce-key-wrap/v2\n" || credId || "\n" || keyNonceHex
 *   (ct, tag) = AEAD(ke, keyNonce, aad, key); out = keyNonceHex || hex(ct) || hex(tag)
 * keyNonceHex must be fresh per pairing (hex, 24 chars = 12 bytes).
 *
 * SECURITY (see docs/SECURITY.md):
 *   - readerSecret MUST be high-entropy (>= WRAP_SECRET_MIN_BYTES bytes
 *     from a CSPRNG), unique per reader, stored as a secret (never in
 *     logs/firmware images). AEAD removes v1's malleability and binds
 *     the wrap to (credId, nonce), but a guessable secret remains
 *     offline-guessable in principle — human passwords never qualify.
 *   - A wrong secret or any tampering fails closed at unwrap (tag check).
 * Returns empty string on null key, malformed keyNonceHex, or short entropy.
 */
std::string wrapKeyHex(const std::string& readerSecret,
                       const std::string& credId,
                       const std::string& keyNonceHex,
                       const uint8_t key[KEY_LEN]);

/**
 * Unwrap a v2 wrapped key (the server-side mirror of wrapKeyHex):
 * splits nonce/ct/tag, re-derives ke, AEAD-decrypts. Returns bytes
 * written (KEY_LEN) or 0 on bad shape, bad hex, short buffer, null key,
 * or tag failure (wrong secret or any tampering — fails closed). The
 * caller must still require the same tap's CHALLENGE proof under the
 * candidate before storing it (proof of possession — see
 * docs/SECURITY.md), and wipe the candidate after use. Never throws.
 */
size_t unwrapKeyHex(const std::string& readerSecret,
                    const std::string& credId,
                    const std::string& keyNonceHex,
                    const std::string& wrappedHex,
                    uint8_t keyOut[KEY_LEN]);

// --- ChaCha20-Poly1305 AEAD (RFC 8439, compact, no dependencies) --------------
// The vetted construction behind the v2 key wrap. Exposed so backends
// share one implementation instead of hand-rolling crypto.
static const size_t AEAD_KEY_LEN = 32;
static const size_t AEAD_NONCE_LEN = 12;
static const size_t AEAD_TAG_LEN = 16;

/** ChaCha20 block function (RFC 8439 §2.3): key + counter + 12-byte nonce → 64 bytes. */
void chacha20Block(const uint8_t key[AEAD_KEY_LEN], uint32_t counter,
                   const uint8_t nonce[AEAD_NONCE_LEN], uint8_t out[64]);

/**
 * AEAD encrypt (RFC 8439 §2.8). Writes ct (ptLen bytes) + tag. No-op on
 * null key/nonce/ct/tag (aad/pt may be null iff their length is 0).
 * Never throws. Keystream and one-time-key buffers are wiped.
 */
void chacha20Poly1305Encrypt(const uint8_t key[AEAD_KEY_LEN],
                             const uint8_t nonce[AEAD_NONCE_LEN],
                             const uint8_t* aad, size_t aadLen,
                             const uint8_t* pt, size_t ptLen,
                             uint8_t* ct, uint8_t tag[AEAD_TAG_LEN]);

/**
 * AEAD decrypt: returns true and writes pt (ctLen bytes) only when the
 * tag verifies (constant-time compare); false otherwise, with pt zeroed
 * (ctLen bytes) so callers cannot use unauthenticated plaintext. Never
 * throws.
 */
bool chacha20Poly1305Decrypt(const uint8_t key[AEAD_KEY_LEN],
                             const uint8_t nonce[AEAD_NONCE_LEN],
                             const uint8_t* aad, size_t aadLen,
                             const uint8_t* ct, size_t ctLen,
                             const uint8_t tag[AEAD_TAG_LEN], uint8_t* pt);

// --- Server-side verification of a relayed transcript ------------------------
// The reader holds no HCE key: it relays nonce + MAC and the KEY lives in
// your backend (and on the phone). This is that backend check, so every
// layer of the system shares one implementation of the crypto instead of
// three hand-rolled copies.

/**
 * Verify a relayed proof: recompute HMAC-SHA256(K_cred, credId || nonce)
 * from the hex transcript and compare against macHex in CONSTANT TIME.
 * Also rejects wrong lengths, odd hex, and credential ids out of range
 * (a claim with an impossible id can never verify).
 *
 * Contract (three separate decisions — see docs/SECURITY.md):
 *   - This function establishes CRYPTOGRAPHIC VALIDITY only (right key,
 *     untampered MAC, well-formed transcript).
 *   - The BACKEND establishes FRESHNESS and SINGLE-USE (per-credential
 *     nonce table, claimed atomically — a separate check-then-insert
 *     races under concurrency).
 *   - The APPLICATION authorizes the requested operation.
 * A return of true is NOT proximity proof (NFC relays are out of scope
 * for this check) and NOT an authorization decision.
 */
bool verifyProof(const std::string& credId,
                 const std::string& nonceHex,
                 const std::string& macHex,
                 const uint8_t key[KEY_LEN]);

/** decode lowercase/uppercase hex → bytes. Returns bytes written; 0 on bad hex or short buffer. */
size_t unhex(const std::string& hex, uint8_t* out, size_t cap);

/** Human-readable ISO-DEP status word, or nullptr when unrecognized. */
const char* statusWordName(uint8_t sw1, uint8_t sw2);

// --- Shared interop test vector ----------------------------------------------
// Computed outside this implementation (Python hmac + an independent
// ChaCha20-Poly1305) and pinned in every port (phone app, reader,
// backend). Use it to prove a new side matches BEFORE touching
// hardware: the vector MAC must reproduce, and verifyProof must accept it.
namespace TestVector {
static const char* kCredId = "PLS-K3Y7V3CT0R5Z";
static const char* kKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
static const char* kNonceHex = "000102030405060708090a0b0c0d0e0f";
static const char* kMacHex = "70f32d7b458139d8f5f522a7314c31205eca50619a5d26dc466d7d5b60aab154";
static const char* kReaderSecret = "test-secret-000000000000000001";  // the reader's secret at enrollment
static const char* kKeyNonceHex = "000102030405060708090a0b";
static const char* kKeyWrappedHex = "000102030405060708090a0bd525e39925f68721c72478ce0d25a8078efb99ee6974f2cd8dad8c872882faa4dfcb78880fbc7ee165be05086565530e";
}  // namespace TestVector

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
