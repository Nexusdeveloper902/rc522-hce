// Fuzz target: chacha20Poly1305Decrypt (attacker-controlled ct+tag).
// Layout: nonce[12] || ct[...] || tag[16]; key and AAD fixed.
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "HceProtocol.h"

using namespace rc522hce;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < AEAD_NONCE_LEN + AEAD_TAG_LEN + 1) {
        return 0;
    }
    static const uint8_t kKey[AEAD_KEY_LEN] = {0};
    static const uint8_t kAad[] = "pulse-hce-key-wrap/v2\nPLS-K3Y7V3CT0R5Z\n000102030405060708090a0b";
    const size_t ctLen = size - AEAD_NONCE_LEN - AEAD_TAG_LEN;
    if (ctLen > 96) {
        return 0;  // production shapes are 32 B; cap fuzzer allocations
    }
    uint8_t pt[96];
    memset(pt, 0, sizeof(pt));
    chacha20Poly1305Decrypt(kKey, data, kAad, sizeof(kAad) - 1, data + AEAD_NONCE_LEN, ctLen,
                            data + AEAD_NONCE_LEN + ctLen, pt);
    return 0;
}
