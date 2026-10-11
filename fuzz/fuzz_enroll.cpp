// Fuzz target: parseEnrollResponse (phone-controlled ENROLL bytes).
#include <cstddef>
#include <cstdint>

#include "HceProtocol.h"

using namespace rc522hce;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    uint8_t key[KEY_LEN];
    parseEnrollResponse(data, size, key);
    return 0;
}
