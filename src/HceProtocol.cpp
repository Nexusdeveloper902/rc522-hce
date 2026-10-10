#include "HceProtocol.h"

#include <cstring>

namespace rc522hce {

size_t buildSelectAid(uint8_t* out, size_t cap) {
    if (out == nullptr || cap < 5 + AID_LEN) {
        return 0;
    }
    out[0] = CLA_PROTO;
    out[1] = INS_SELECT;
    out[2] = 0x04;
    out[3] = 0x00;
    out[4] = static_cast<uint8_t>(AID_LEN);
    memcpy(out + 5, AID, AID_LEN);
    return 5 + AID_LEN;
}

size_t buildChallenge(const uint8_t nonce[NONCE_LEN], uint8_t* out, size_t cap) {
    if (out == nullptr || nonce == nullptr || cap < 5 + NONCE_LEN) {
        return 0;
    }
    out[0] = CLA_AUTH;
    out[1] = INS_CHALLENGE;
    out[2] = 0x00;
    out[3] = 0x00;
    out[4] = static_cast<uint8_t>(NONCE_LEN);
    memcpy(out + 5, nonce, NONCE_LEN);
    return 5 + NONCE_LEN;
}

size_t buildEnroll(uint8_t* out, size_t cap) {
    if (out == nullptr || cap < 5) {
        return 0;
    }
    out[0] = CLA_AUTH;
    out[1] = INS_ENROLL;
    out[2] = 0x00;
    out[3] = 0x00;
    out[4] = static_cast<uint8_t>(KEY_LEN);  // Le
    return 5;
}

bool isOk(const uint8_t* resp, size_t len) {
    return resp != nullptr && len >= 2 && resp[len - 2] == 0x90 && resp[len - 1] == 0x00;
}

SelectOutcome parseSelectResponse(const uint8_t* resp, size_t len) {
    if (resp == nullptr || len < 2) {
        return SelectOutcome::Malformed;
    }
    if (resp[len - 2] == 0x6A && resp[len - 1] == 0x82) {
        return SelectOutcome::UnknownAid;
    }
    // "HCE-OK" (6 bytes) + 9000 — the exact success shape the phone sends.
    static const char kHceOk[] = "HCE-OK";
    if (len == 8 && isOk(resp, len) && memcmp(resp, kHceOk, 6) == 0) {
        return SelectOutcome::Selected;
    }
    return SelectOutcome::Malformed;
}

bool parseChallengeResponse(const uint8_t* resp, size_t len, ChallengeResponse& out) {
    out.ok = false;
    out.credId.clear();
    if (resp == nullptr || len < 1 + 1 + HMAC_LEN + 2) {
        return false;
    }
    const size_t credLen = resp[0];
    if (credLen == 0 || credLen > MAX_CRED_LEN) {
        return false;
    }
    if (len != 1 + credLen + HMAC_LEN + 2) {
        return false;
    }
    if (!isOk(resp, len)) {
        return false;
    }
    out.credId.assign(reinterpret_cast<const char*>(resp + 1), credLen);
    memcpy(out.mac, resp + 1 + credLen, HMAC_LEN);
    out.ok = true;
    return true;
}

bool isKeyMissing(const uint8_t* resp, size_t len) {
    return resp != nullptr && len == 2 && resp[0] == 0x6A && resp[1] == 0x88;
}

bool parseEnrollResponse(const uint8_t* resp, size_t len, uint8_t key[KEY_LEN]) {
    if (resp == nullptr || key == nullptr || len != KEY_LEN + 2 || !isOk(resp, len)) {
        return false;
    }
    memcpy(key, resp, KEY_LEN);
    return true;
}

// --- SHA-256 (FIPS 180-4, compact, public-domain style) -----------------------

namespace {

struct Sha256 {
    uint32_t h[8];
    uint64_t total;
    uint8_t buf[64];
    size_t buflen;
};

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

void sha256Init(Sha256* c) {
    c->h[0] = 0x6a09e667;
    c->h[1] = 0xbb67ae85;
    c->h[2] = 0x3c6ef372;
    c->h[3] = 0xa54ff53a;
    c->h[4] = 0x510e527f;
    c->h[5] = 0x9b05688c;
    c->h[6] = 0x1f83d9ab;
    c->h[7] = 0x5be0cd19;
    c->total = 0;
    c->buflen = 0;
}

void sha256Block(Sha256* c, const uint8_t* p) {
    static const uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = (static_cast<uint32_t>(p[4 * i]) << 24) | (static_cast<uint32_t>(p[4 * i + 1]) << 16) |
               (static_cast<uint32_t>(p[4 * i + 2]) << 8) | static_cast<uint32_t>(p[4 * i + 3]);
    }
    for (int i = 16; i < 64; i++) {
        const uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3];
    uint32_t e = c->h[4], f = c->h[5], g = c->h[6], h = c->h[7];
    for (int i = 0; i < 64; i++) {
        const uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const uint32_t ch = (e & f) ^ (~e & g);
        const uint32_t t1 = h + s1 + ch + k[i] + w[i];
        const uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        const uint32_t t2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = cc;
        cc = b;
        b = a;
        a = t1 + t2;
    }
    c->h[0] += a;
    c->h[1] += b;
    c->h[2] += cc;
    c->h[3] += d;
    c->h[4] += e;
    c->h[5] += f;
    c->h[6] += g;
    c->h[7] += h;
}

void sha256Update(Sha256* c, const uint8_t* data, size_t len) {
    c->total += len;
    while (len > 0) {
        const size_t take = (sizeof(c->buf) - c->buflen) < len ? (sizeof(c->buf) - c->buflen) : len;
        memcpy(c->buf + c->buflen, data, take);
        c->buflen += take;
        data += take;
        len -= take;
        if (c->buflen == sizeof(c->buf)) {
            sha256Block(c, c->buf);
            c->buflen = 0;
        }
    }
}

void sha256Final(Sha256* c, uint8_t out[32]) {
    const uint64_t bitlen = c->total * 8;
    uint8_t pad = 0x80;
    sha256Update(c, &pad, 1);
    uint8_t zero = 0x00;
    while (c->buflen != 56) {
        sha256Update(c, &zero, 1);
    }
    uint8_t lenBytes[8];
    for (int i = 0; i < 8; i++) {
        lenBytes[i] = static_cast<uint8_t>(bitlen >> (56 - 8 * i));
    }
    // Append without re-entering the padding path: exactly 8 bytes fill 56->64.
    memcpy(c->buf + 56, lenBytes, 8);
    sha256Block(c, c->buf);
    for (int i = 0; i < 8; i++) {
        out[4 * i] = static_cast<uint8_t>(c->h[i] >> 24);
        out[4 * i + 1] = static_cast<uint8_t>(c->h[i] >> 16);
        out[4 * i + 2] = static_cast<uint8_t>(c->h[i] >> 8);
        out[4 * i + 3] = static_cast<uint8_t>(c->h[i]);
    }
}

void sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    Sha256 c;
    sha256Init(&c);
    if (len > 0) {
        sha256Update(&c, data, len);
    }
    sha256Final(&c, out);
}

}  // namespace

void sha256Bytes(const uint8_t* data, size_t len, uint8_t out[HMAC_LEN]) {
    sha256(data != nullptr ? data : reinterpret_cast<const uint8_t*>(""), len, out);
}

void hmacSha256(const uint8_t* key, size_t keyLen,
                const uint8_t* msg, size_t msgLen,
                uint8_t out[HMAC_LEN]) {
    uint8_t kbuf[64];
    memset(kbuf, 0, sizeof(kbuf));
    if (keyLen > sizeof(kbuf)) {
        sha256(key, keyLen, kbuf);  // long keys hash down first (RFC 2104)
    } else if (key != nullptr && keyLen > 0) {
        memcpy(kbuf, key, keyLen);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = kbuf[i] ^ 0x36;
        opad[i] = kbuf[i] ^ 0x5c;
    }
    Sha256 inner;
    sha256Init(&inner);
    sha256Update(&inner, ipad, sizeof(ipad));
    if (msgLen > 0 && msg != nullptr) {
        sha256Update(&inner, msg, msgLen);
    }
    uint8_t innerDigest[32];
    sha256Final(&inner, innerDigest);
    Sha256 outer;
    sha256Init(&outer);
    sha256Update(&outer, opad, sizeof(opad));
    sha256Update(&outer, innerDigest, sizeof(innerDigest));
    sha256Final(&outer, out);
}

std::string toHex(const uint8_t* data, size_t len) {
    static const char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    if (data == nullptr) {
        return out;
    }
    for (size_t i = 0; i < len; i++) {
        out.push_back(kDigits[(data[i] >> 4) & 0x0F]);
        out.push_back(kDigits[data[i] & 0x0F]);
    }
    return out;
}

std::string sha256Hex(const std::string& data) {
    uint8_t digest[HMAC_LEN];
    sha256Bytes(reinterpret_cast<const uint8_t*>(data.data()), data.size(), digest);
    return toHex(digest, sizeof(digest));
}

void fillRandomBytes(uint8_t* out, size_t len, uint32_t (*randomWord)()) {
    if (out == nullptr || randomWord == nullptr) {
        return;
    }
    size_t i = 0;
    while (i < len) {
        const uint32_t w = randomWord();
        for (int b = 0; b < 4 && i < len; b++, i++) {
            out[i] = static_cast<uint8_t>((w >> (8 * b)) & 0xFF);
        }
    }
}

std::string wrapKeyHex(const std::string& readerSecret,
                       const std::string& credId,
                       const std::string& keyNonceHex,
                       const uint8_t key[KEY_LEN]) {
    if (key == nullptr) {
        return std::string();
    }
    const std::string label = std::string("pulse-hce-key-wrap/v1\n") + credId + "\n" + keyNonceHex;
    uint8_t pad[HMAC_LEN];
    hmacSha256(reinterpret_cast<const uint8_t*>(readerSecret.data()), readerSecret.size(),
               reinterpret_cast<const uint8_t*>(label.data()), label.size(), pad);
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(KEY_LEN * 2);
    for (size_t i = 0; i < KEY_LEN; i++) {
        const uint8_t b = static_cast<uint8_t>(key[i] ^ pad[i]);
        out += hex[b >> 4];
        out += hex[b & 0x0F];
    }
    memset(pad, 0, sizeof(pad));
    return out;
}

// --- ISO-DEP helpers --------------------------------------------------------

bool sakPromisesIsoDep(uint8_t sak) {
    return (sak & 0x24) == 0x20;
}

bool isIBlock(uint8_t pcb) { return (pcb & 0xC0) == 0x00; }

bool isRBlock(uint8_t pcb) { return (pcb & 0xC0) == 0x80; }

bool isWtxRequest(uint8_t pcb) { return (pcb & 0xC0) == 0xC0 && (pcb & 0x30) == 0x30; }

bool isWtxFrame(const uint8_t* frame, size_t len) {
    return frame != nullptr && len >= MIN_ISO_DEP_FRAME && isWtxRequest(frame[0]);
}

bool stripIBlock(const uint8_t* frame, size_t frameLen, size_t respCap,
                 size_t& infOffsetOut, size_t& infLenOut) {
    infOffsetOut = 0;
    infLenOut = 0;
    if (frame == nullptr || frameLen < MIN_ISO_DEP_FRAME) {
        return false;
    }
    if (!isIBlock(frame[0])) {
        return false;  // R-block / S(DESELECT): no app data
    }
    size_t off = 1;
    if (frame[0] & 0x08) {
        ++off;  // CID follows
    }
    if (frame[0] & 0x04) {
        ++off;  // NAD follows
    }
    if (frameLen < off + 2u + 1u) {
        return false;  // prologue + CRC only, no INF
    }
    const size_t infLen = frameLen - off - 2;
    if (infLen > respCap) {
        return false;  // mirrors STATUS_NO_ROOM
    }
    infOffsetOut = off;
    infLenOut = infLen;
    return true;
}

bool nextBlockNumber(uint8_t receivedPcb) {
    // The phone echoes the block number it received; ours is the opposite.
    return ((receivedPcb & 0x01) == 0);
}

}  // namespace rc522hce
