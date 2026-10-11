// Fuzz target: verifyProof (backend-side transcript verification).
// Input bytes are hex-encoded first so the fuzzer reaches past the hex
// gate into HMAC + constant-time compare (raw bytes would bail at unhex).
#include <cstddef>
#include <cstdint>
#include <string>

#include "HceProtocol.h"

using namespace rc522hce;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::string hx = toHex(data, size);
    if (hx.size() < NONCE_LEN * 2 + HMAC_LEN * 2) {
        return 0;
    }
    uint8_t key[KEY_LEN];
    for (size_t i = 0; i < KEY_LEN; i++) {
        key[i] = static_cast<uint8_t>(i);
    }
    verifyProof("PLS-K3Y7V3CT0R5Z", hx.substr(0, NONCE_LEN * 2),
                hx.substr(NONCE_LEN * 2, HMAC_LEN * 2), key);
    return 0;
}
