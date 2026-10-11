/**
 * NfcReader.h — swappable NFC reader interface.
 *
 * The concrete chip driver (Rc522HceReader over SPI) and the host-side mock
 * both implement this interface, so application logic (modes, HTTP, UI)
 * never knows which one is behind it.
 */
#pragma once

#include <string>
#include <stdint.h>

#include "HceProtocol.h"  // KEY_LEN not needed here; HceProof lives below

namespace rc522hce {

// How a credential was captured. Typed so the compiler catches invalid
// states; the historical string form ("physical"/"hce") survives only as
// the deprecated lastKind() shim for already-deployed custom transports.
enum class CredentialKind : uint8_t {
    Physical = 0,  // MIFARE Classic UID off the RF layer (compatibility path)
    Hce = 1        // Android HCE phone, identity from the APDU exchange
};

/** Stable wire/log name for a kind. Never returns nullptr. */
inline const char* credentialKindName(CredentialKind kind) {
    return kind == CredentialKind::Hce ? "hce" : "physical";
}

/** Parse a kind name. Unknown (including nullptr) maps to Physical. */
inline CredentialKind credentialKindFromString(const char* name) {
    if (name != nullptr && name[0] == 'h' && name[1] == 'c' && name[2] == 'e' &&
        name[3] == '\0') {
        return CredentialKind::Hce;
    }
    return CredentialKind::Physical;
}

// What an HCE tap carries to the backend. The reader does NOT verify the
// phone (it holds no HCE key): it relays its own challenge nonce and the
// phone's MAC, and the server checks them against that credential's key.
// In enrollment/pairing mode the phone's key rides along too — never raw,
// always wrapped under this reader's secret (wrapKeyHex). Empty for
// physical cards.
struct HceProof {
    std::string nonceHex;       // 16 hex — the reader's CHALLENGE nonce
    std::string macHex;         // 64 hex — the phone's HMAC, unverified here
    std::string keyWrappedHex;  // 64 hex — enrollment only
    std::string keyNonceHex;    // 32 hex — enrollment only (fresh per pairing)

    bool present() const { return !nonceHex.empty() && !macHex.empty(); }
    bool hasKey() const { return !keyWrappedHex.empty() && !keyNonceHex.empty(); }
    void clear() {
        nonceHex.clear();
        macHex.clear();
        keyWrappedHex.clear();
        keyNonceHex.clear();
    }
};

class NfcReader {
public:
    virtual ~NfcReader() = default;

    /** Initialize the reader hardware. False when init fails. */
    virtual bool begin() = 0;

    /**
     * Non-blocking poll for a credential.
     * Returns true (and fills idOut) when a credential was read this call.
     *
     * Two credential paths, one poll():
     *   physical — a MIFARE Classic UID read off the RF layer;
     *   hce      — an Android phone answering as an ISO-DEP target: the
     *              application-level credential id from the SELECT AID +
     *              CHALLENGE exchange (never the RF UID, which Android
     *              randomizes per tap). kind() tells which one the last
     *              successful poll returned.
     *
     * Failure/lifetime contract (applies to every transport):
     *   - On false, idOut is left untouched and kind()/lastKind()/
     *     lastProof() still describe the last SUCCESSFUL poll (stale).
     *     Only use them immediately after poll() returns true.
     *   - lastProof() returns a borrowed reference valid until the next
     *     poll(), setEnrollment(), setAid(), or destruction. Copy it if
     *     it must outlive the next poll.
     *   - poll() never throws and never blocks; radio drivers do their
     *     retry/probe work inside the call on a non-blocking cadence.
     */
    virtual bool poll(std::string& idOut) = 0;

    /**
     * HOW the last successful poll's credential was captured.
     * Preferred over the string form below; custom transports written
     * against pre-2.0 code that overrides only lastKind() still work (the facade
     * falls back to the string when kind() reports Physical).
     */
    virtual CredentialKind kind() const { return CredentialKind::Physical; }

    /**
     * HOW the last successful poll's credential was captured.
     * @deprecated Prefer kind(). Kept so pre-2.0 custom transports keep
     * compiling and behaving; new code must override kind() instead.
     * Only meaningful immediately after poll() returns true (otherwise
     * stale — see poll()).
     */
    virtual const char* lastKind() const { return credentialKindName(kind()); }

    /**
     * The relayed HCE transcript of the last successful poll (empty for
     * physical cards). The reader does not verify it — the server does,
     * with that credential's own key. Borrowed reference: valid until the
     * next poll()/setEnrollment()/destruction; copy when it must outlive
     * that. Stale after poll() returns false — see poll().
     */
    virtual const HceProof& lastProof() const {
        static const HceProof kNone;
        return kNone;
    }

    /**
     * Enrollment/pairing mode on/off. Only while on does an HCE poll also
     * request the phone's key (ENROLL) and wrap it with wrapSecret (this
     * reader's secret) for the pair call. Off = normal taps never ask
     * a phone for its key.
     */
    virtual void setEnrollment(bool /*on*/, const std::string& /*wrapSecret*/) {}

    /** Short label for the log. */
    virtual const char* label() const = 0;

    /** True when the reader is responding. Radio drivers probe the chip
     * and can revoke this at runtime; non-hardware readers are always
     * healthy. Used by apps to show a degraded state instead of dying
     * silently when the antenna stops answering.
     */
    virtual bool healthy() const { return true; }

    /**
     * The AID this reader SELECTs (the protocol AID by default). Radio
     * drivers support changing it at runtime via setAid(); the interface
     * only exposes the read side so apps can display/log it and compare it
     * against what a phone app is configured for.
     */
    virtual const uint8_t* aid() const { return AID; }
    virtual size_t aidLen() const { return AID_LEN; }

    /** Change the selected AID (1..MAX_AID_LEN bytes). Default: ignored. */
    virtual bool setAid(const uint8_t* /*aid*/, size_t /*len*/) { return false; }
};

}  // namespace rc522hce
