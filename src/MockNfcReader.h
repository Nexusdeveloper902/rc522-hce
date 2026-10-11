/**
 * MockNfcReader.h — host-side simulated NFC reader (no hardware).
 *
 * Development and unit tests without the physical board: push console
 * lines / test vectors via pushTap() and poll() behaves exactly like a
 * card tap (one tap per pushed line). Pure C++ — compiles on host and
 * on Arduino alike.
 */
#pragma once

#include <string>

#include "NfcReader.h"

namespace rc522hce {

class MockNfcReader : public NfcReader {
public:
    MockNfcReader() = default;

    bool begin() override {
        // Nothing to initialize on the host.
        return true;
    }

    /**
     * Queue one line as a virtual tap (empty lines are ignored).
     * Takes effect on the next poll().
     */
    void pushTap(const std::string& line) {
        if (!line.empty()) {
            pendingId_ = line;  // newest wins; taps are human-paced
        }
    }

    // Backwards-compatible alias (the original mock was Serial-driven).
    void pushLine(const std::string& line) { pushTap(line); }

    bool poll(std::string& idOut) override {
        if (pendingId_.empty()) {
            return false;
        }
        idOut = pendingId_;
        pendingId_.clear();
        return true;  // exactly one tap per pushed line
    }

    const char* label() const override { return "MOCK (host input)"; }

    CredentialKind kind() const override { return CredentialKind::Physical; }

private:
    std::string pendingId_;
};

}  // namespace rc522hce
