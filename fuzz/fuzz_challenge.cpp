// Fuzz target: parseChallengeResponse (phone-controlled CHALLENGE bytes).
#include <cstddef>
#include <cstdint>

#include "HceProtocol.h"

using namespace rc522hce;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    ChallengeResponse out;
    parseChallengeResponse(data, size, out);
    return 0;
}
