/**
 * NfcReader.h — swappable NFC reader interface.
 *
 * The concrete chip driver (Rc522HceReader over SPI) and the host-side mock
 * both implement this interface, so application logic (modes, HTTP, UI)
 * never knows which one is behind it.
 */
#pragma once

#include <string>

#include "HceProtocol.h"  // KEY_LEN not needed here; HceProof lives below

namespace rc522hce {

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
     *              randomizes per tap). lastKind() tells which one the last
     *              successful poll returned ("physical" or "hce").
     */
    virtual bool poll(std::string& idOut) = 0;

    /** HOW the last successful poll's credential was captured. */
    virtual const char* lastKind() const { return "physical"; }

    /**
     * The relayed HCE transcript of the last successful poll (empty for
     * physical cards). The reader does not verify it — the server does,
     * with that credential's own key.
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

    /**
     * True when the reader is responding. Radio drivers probe the chip
     * and can revoke this at runtime; non-hardware readers are always
     * healthy. Used by apps to show a degraded state instead of dying
     * silently when the antenna stops answering.
     */
    virtual bool healthy() const { return true; }
};

}  // namespace rc522hce
