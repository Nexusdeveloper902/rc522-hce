/**
 * HceReader.h — the library's public face. Configure once, then just read.
 *
 * HceReader wraps any NfcReader (the RC522 radio driver, or the host-side
 * mock) plus tap debouncing into the three calls a normal app needs:
 *
 *   HceReader reader(nfcDriver);          // or HceReader(driver, 2000) for ms
 *   reader.begin();
 *   HceReader::Tap tap;
 *   if (reader.read(tap, millis())) { ... }   // exactly once per physical tap
 *
 * THIS HEADER IS THE WHOLE API. Everything the system needs beyond read() —
 * the AID a phone must serve, the challenge/MAC lengths, ISO-DEP status
 * words, the shared interop vector, and the backend verification of a
 * relayed proof — is re-exported below (see "One-header protocol surface"),
 * so `#include <HceReader.h>` is the only include an app or server needs.
 *
 * Where the keys live (the hce key model):
 *   - K_cred is PER CREDENTIAL, generated and stored by the phone. Neither
 *     the reader nor this library ever holds it.
 *   - The reader sends its own nonce (AID exchange) and relays the phone's
 *     MAC unverified; YOUR SERVER calls verifyProof() for cryptographic
 *     validity, then claims the nonce atomically (replay table) before
 *     authorizing. verifyProof() alone never rejects replays.
 *   - At enrollment the phone hands over K_cred once, inside the window the
 *     holder opens, and the reader wraps it under the secret YOU pass to
 *     setEnrollment(on, readerSecret) — never raw, never logged. Unwrap it
 *     with unwrapKeyHex(); then the server requires that tap's CHALLENGE
 *     proof to verify under it before storing it.
 *   - Authoritative security contract: docs/SECURITY.md (replay, RNG,
 *     wrap-entropy, relay limits). Host tests pin behavior, not security.
 *
 * Pure C++ (no Arduino headers): time is injected per call, so the whole
 * "one event per tap" contract is host-testable. On device pass millis();
 * in tests pass scripted timestamps.
 */
#pragma once

#include <stdint.h>  // not <cstdint>: some toolchains ship no C++ stdlib
#include <string>
#include <cstring>  // memset — wiping key buffers

#include "CardDebouncer.h"
#include "NfcReader.h"

namespace rc522hce {

class HceReader {
public:
    /** One identified tap. `proof` carries the server-bound relay data. */
    struct Tap {
        std::string credentialId;  // CLAIMED id: MIFARE hex UID, or the HCE application id
        // How the id was captured. isHce is the convenience mirror of
        // (kind == CredentialKind::Hce); prefer kind in new code.
        CredentialKind kind = CredentialKind::Physical;
        bool isHce = false;        // true => identity came from the APDU exchange
        HceProof proof;            // relay transcript (meaningful only when isHce)
    };

    /**
     * @param reader      the transport: Rc522HceReader on device,
     *                    MockNfcReader in dev/tests. Must outlive this object.
     * @param debounceMs  re-tap cooldown; a card resting on the antenna
     *                    never re-fires regardless of this value.
     */
    explicit HceReader(NfcReader& reader, uint32_t debounceMs = 2000)
        : reader_(reader), debouncer_(debounceMs) {}

    /** Initialize the underlying reader hardware. False when init fails. */
    bool begin() { return reader_.begin(); }

    /**
     * Poll once per loop. Returns true exactly once per physical tap and
     * fills `out`; returns false otherwise (no credential, resting card,
     * or cooldown). Call with the current millis() — and call it
     * unconditionally: the false path is what notices the card left.
     *
     * The accepted tap is IDENTIFIED, not authenticated: for HCE taps the
     * credentialId is the phone's claim and proof is the UNVERIFIED relay.
     * The server must verifyProof() + enforce single-use nonces before the
     * app authorizes anything (see docs/SECURITY.md). Physical UIDs are
     * compatibility identifiers (clonable), never equivalent assurance.
     * On false, `out` is left untouched.
     */
    bool read(Tap& out, uint32_t nowMs) {
        std::string id;
        if (!reader_.poll(id)) {
            debouncer_.markAbsent();
            return false;
        }
        if (!debouncer_.shouldProcess(id, nowMs)) {
            return false;
        }
        out.credentialId = id;
        // Preferred: typed kind. Legacy custom transports (pre-2.0) override
        // only the string lastKind(), so fall back to it when kind() still
        // reports Physical.
        CredentialKind kind = reader_.kind();
        if (kind == CredentialKind::Physical && reader_.lastKind() != nullptr &&
            std::string(reader_.lastKind()) == "hce") {
            kind = CredentialKind::Hce;
        }
        out.kind = kind;
        out.isHce = (kind == CredentialKind::Hce);
        out.proof = reader_.lastProof();
        if (!out.isHce) {
            out.proof.clear();
        }
        return true;
    }

    /**
     * Enrollment mode on/off. Only while on does an HCE tap also fetch
     * the phone's key (ENROLL) and wrap it with `wrapSecret` for the
     * pair call. Off = normal taps never ask a phone for its key.
     * Also resets the debounce state so a mode switch never eats a tap.
     *
     * wrapSecret is THIS reader's key-encryption secret: it MUST be
     * high-entropy (>= WRAP_SECRET_MIN_BYTES random bytes), unique per
     * device, and never logged/stored with the wrapped keys. Human
     * passwords do not qualify (offline-guessing weakness — see
     * docs/SECURITY.md). Cleared when turned off.
     */
    void setEnrollment(bool on, const std::string& wrapSecret = std::string()) {
        reader_.setEnrollment(on, wrapSecret);
        debouncer_.reset();
    }

    /**
     * Radio health only: true when the underlying reader's last probe
     * answered. It says nothing about NFC link quality or whether a
     * phone can authenticate — present it as "radio degraded", never as
     * proof the credential system is operational.
     */
    bool healthy() const { return reader_.healthy(); }

    /** Short label of the underlying reader, for the log. */
    const char* label() const { return reader_.label(); }

    /** The AID this reader SELECTs, and its length. Must match the phone app. */
    const uint8_t* selectedAid() const { return reader_.aid(); }
    size_t selectedAidLen() const { return reader_.aidLen(); }

    /**
     * Change the AID this reader SELECTs (1..11 bytes). The phone app must
     * serve the same AID, so this is a deployment-time decision, not a
     * per-tap knob. False = rejected, previous AID kept.
     */
    bool setAid(const uint8_t* aid, size_t len) {
        const bool changed = reader_.setAid(aid, len);
        if (changed) {
            debouncer_.reset();  // a change of identity target starts fresh
        }
        return changed;
    }

    /** Direct access to the wrapped transport, for advanced use. */
    NfcReader& transport() { return reader_; }

    // --- One-header protocol surface -----------------------------------------
    // Re-exported so app/server code gets everything from this one header.
    // (The driver is optional; the protocol is the contract.)

    /** The AID your phone's HCE app must serve, e.g. F0010203040506. */
    static const uint8_t* aid() { return AID; }
    static size_t aidLen() { return AID_LEN; }
    /** Challenge nonce length in bytes (16). */
    static size_t nonceLen() { return NONCE_LEN; }
    /** HMAC-SHA256 length in bytes (32). */
    static size_t macLen() { return HMAC_LEN; }
    /** Credential id length bounds accepted by the protocol (1..32). */
    static size_t minCredentialLen() { return 1; }
    static size_t maxCredentialLen() { return MAX_CRED_LEN; }
    /** Per-credential key length in bytes (32). */
    static size_t keyLen() { return KEY_LEN; }

    /** ISO-DEP status word, human-readable (9000, 6A82, 6A88, 6985, 6700, 6D00, 6E00). */
    static const char* statusWordName(uint8_t sw1, uint8_t sw2) {
        return rc522hce::statusWordName(sw1, sw2);
    }

    /**
     * Backend verification of one relayed HCE proof: recompute
     * HMAC-SHA256(K_cred, credentialId || nonce) and compare in constant
     * time. This is where the per-credential key is used — never on the
     * reader. Reject when it returns false.
     *
     * Establishes cryptographic validity ONLY. Freshness/single-use
     * (replay table, claimed atomically) and the authorization decision
     * are separate backend/app steps — see docs/SECURITY.md. A true
     * result is not proximity proof.
     */
    static bool verifyProof(const HceProof& proof, const std::string& credentialId,
                            const uint8_t credKey[KEY_LEN]) {
        return rc522hce::verifyProof(credentialId, proof.nonceHex, proof.macHex, credKey);
    }

    /** Lower-level form, straight from the wire (hex nonce + hex mac). */
    static bool verifyProof(const std::string& credentialId,
                            const std::string& nonceHex, const std::string& macHex,
                            const uint8_t credKey[KEY_LEN]) {
        return rc522hce::verifyProof(credentialId, nonceHex, macHex, credKey);
    }

    /** Hex helpers (relay transcripts and wrapped keys travel hex-encoded). */
    static std::string toHex(const uint8_t* data, size_t len) {
        return rc522hce::toHex(data, len);
    }
    static size_t fromHex(const std::string& hex, uint8_t* out, size_t cap) {
        return rc522hce::unhex(hex, out, cap);
    }

    /** v1 key-wrap / unwrap (server-side unwrap mirror; see HceProtocol.h). */
    static std::string wrapKeyHex(const std::string& readerSecret,
                                  const std::string& credId,
                                  const std::string& keyNonceHex,
                                  const uint8_t key[KEY_LEN]) {
        return rc522hce::wrapKeyHex(readerSecret, credId, keyNonceHex, key);
    }
    static size_t unwrapKeyHex(const std::string& readerSecret,
                               const std::string& credId,
                               const std::string& keyNonceHex,
                               const std::string& wrappedHex,
                               uint8_t keyOut[KEY_LEN]) {
        return rc522hce::unwrapKeyHex(readerSecret, credId, keyNonceHex, wrappedHex, keyOut);
    }

    /** Protocol/key-wrap versions and wrap-secret entropy floor. */
    static uint32_t protocolVersion() { return PROTOCOL_VERSION; }
    static uint32_t keyWrapVersion() { return KEY_WRAP_VERSION; }
    /** Stable log name for a credential kind ("physical"/"hce"). */
    static const char* kindName(CredentialKind kind) {
        return credentialKindName(kind);
    }

    /** Shared interop test vector — prove a new phone app/backend matches. */
    static bool selfCheckVector() {
        uint8_t key[KEY_LEN];
        if (rc522hce::unhex(TestVector::kKeyHex, key, sizeof(key)) != KEY_LEN) {
            return false;
        }
        const bool ok = rc522hce::verifyProof(TestVector::kCredId, TestVector::kNonceHex,
                                              TestVector::kMacHex, key);
        memset(key, 0, sizeof(key));
        return ok;
    }

private:
    NfcReader& reader_;
    CardDebouncer debouncer_;
};

}  // namespace rc522hce
