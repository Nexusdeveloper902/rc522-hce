// Fuzz target: unhex (hex transcripts off the wire / backend input).
#include <cstddef>
#include <cstdint>
#include <string>

#include "HceProtocol.h"

using namespace rc522hce;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::string hex(reinterpret_cast<const char*>(data), size);
    uint8_t out[80];
    unhex(hex, out, sizeof(out));
    return 0;
}
