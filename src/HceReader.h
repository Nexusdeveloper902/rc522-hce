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
 * Pure C++ (no Arduino headers): time is injected per call, so the whole
 * "one event per tap" contract is host-testable. On device pass millis();
 * in tests pass scripted timestamps.
 */
#pragma once

#include <stdint.h>
#include <string>

#include "CardDebouncer.h"
#include "NfcReader.h"

namespace rc522hce {

class HceReader {
public:
    /** One identified tap. `proof` carries the server-bound relay data. */
    struct Tap {
        std::string credentialId;  // MIFARE hex UID, or the HCE application id
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
        out.isHce = reader_.lastKind() != nullptr &&
                    std::string(reader_.lastKind()) == "hce";
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
     */
    void setEnrollment(bool on, const std::string& wrapSecret = std::string()) {
        reader_.setEnrollment(on, wrapSecret);
        debouncer_.reset();
    }

    /** True when the underlying reader's last probe answered. */
    bool healthy() const { return reader_.healthy(); }

    /** Short label of the underlying reader, for the log. */
    const char* label() const { return reader_.label(); }

    /** Direct access to the wrapped transport, for advanced use. */
    NfcReader& transport() { return reader_; }

private:
    NfcReader& reader_;
    CardDebouncer debouncer_;
};

}  // namespace rc522hce
