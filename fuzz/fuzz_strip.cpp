// Fuzz target: stripIBlock / isWtxFrame (raw ISO-DEP frames off the RF layer).
#include <cstddef>
#include <cstdint>

#include "HceProtocol.h"

using namespace rc522hce;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    isWtxFrame(data, size);
    size_t off = 0, len = 0;
    stripIBlock(data, size, 64, off, len);
    stripIBlock(data, size, 8, off, len);  // small respCap path (STATUS_NO_ROOM)
    return 0;
}
