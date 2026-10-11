#include "HceProtocol.h"

#include <cstring>

namespace rc522hce {

namespace {
// Shared frame writer: 00 A4 04 00 Lc AID.
size_t buildSelectAidInto(const uint8_t* aid, size_t aidLen, uint8_t* out, size_t cap) {
    if (out == nullptr || cap < 5 + aidLen) {
        return 0;
    }
    out[0] = CLA_PROTO;
    out[1] = INS_SELECT;
    out[2] = 0x04;
    out[3] = 0x00;
    out[4] = static_cast<uint8_t>(aidLen);
    memcpy(out + 5, aid, aidLen);
    return 5 + aidLen;
}
}  // namespace

size_t buildSelectAidWith(const uint8_t* aid, size_t aidLen, uint8_t* out, size_t cap) {
    if (aid == nullptr || aidLen == 0 || aidLen > MAX_AID_LEN) {
        return 0;
    }
    return buildSelectAidInto(aid, aidLen, out, cap);
}

size_t buildSelectAid(uint8_t* out, size_t cap) {
    return buildSelectAidWith(AID, AID_LEN, out, cap);
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
    if (key == nullptr || keyNonceHex.size() != KEY_NONCE_LEN * 2) {
        return std::string();
    }
    uint8_t keyNonce[KEY_NONCE_LEN];
    if (unhex(keyNonceHex, keyNonce, sizeof(keyNonce)) != KEY_NONCE_LEN) {
        return std::string();
    }
    const std::string encLabel = std::string(KEY_WRAP_ENC_LABEL_V2) + credId;
    uint8_t ke[AEAD_KEY_LEN];
    hmacSha256(reinterpret_cast<const uint8_t*>(readerSecret.data()), readerSecret.size(),
               reinterpret_cast<const uint8_t*>(encLabel.data()), encLabel.size(), ke);
    const std::string aad = std::string(KEY_WRAP_LABEL_V2) + credId + "\n" + keyNonceHex;
    uint8_t ct[KEY_LEN];
    uint8_t tag[AEAD_TAG_LEN];
    chacha20Poly1305Encrypt(ke, keyNonce,
                            reinterpret_cast<const uint8_t*>(aad.data()), aad.size(),
                            key, KEY_LEN, ct, tag);
    memset(ke, 0, sizeof(ke));
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(KEY_NONCE_LEN * 2 + KEY_LEN * 2 + AEAD_TAG_LEN * 2);
    out += keyNonceHex;
    for (size_t i = 0; i < KEY_LEN; i++) {
        out += hex[ct[i] >> 4];
        out += hex[ct[i] & 0x0F];
    }
    for (size_t i = 0; i < AEAD_TAG_LEN; i++) {
        out += hex[tag[i] >> 4];
        out += hex[tag[i] & 0x0F];
    }
    memset(ct, 0, sizeof(ct));
    memset(tag, 0, sizeof(tag));
    memset(keyNonce, 0, sizeof(keyNonce));
    return out;
}

size_t unwrapKeyHex(const std::string& readerSecret,
                    const std::string& credId,
                    const std::string& keyNonceHex,
                    const std::string& wrappedHex,
                    uint8_t keyOut[KEY_LEN]) {
    static const size_t kWrappedLen = KEY_NONCE_LEN * 2 + KEY_LEN * 2 + AEAD_TAG_LEN * 2;  // 120
    if (keyOut == nullptr || wrappedHex.size() != kWrappedLen) {
        return 0;
    }
    // The leading nonce must match the out-of-band keyNonceHex (defense in
    // depth: the AAD already binds it, this rejects spliced wraps early).
    if (wrappedHex.compare(0, keyNonceHex.size(), keyNonceHex) != 0) {
        return 0;
    }
    uint8_t keyNonce[KEY_NONCE_LEN];
    uint8_t ct[KEY_LEN];
    uint8_t tag[AEAD_TAG_LEN];
    uint8_t tmp[KEY_NONCE_LEN + KEY_LEN + AEAD_TAG_LEN];
    if (unhex(wrappedHex, tmp, sizeof(tmp)) != sizeof(tmp) ||
        unhex(keyNonceHex, keyNonce, sizeof(keyNonce)) != KEY_NONCE_LEN) {
        memset(tmp, 0, sizeof(tmp));
        return 0;
    }
    memcpy(ct, tmp + KEY_NONCE_LEN, KEY_LEN);
    memcpy(tag, tmp + KEY_NONCE_LEN + KEY_LEN, AEAD_TAG_LEN);
    memset(tmp, 0, sizeof(tmp));
    const std::string encLabel = std::string(KEY_WRAP_ENC_LABEL_V2) + credId;
    uint8_t ke[AEAD_KEY_LEN];
    hmacSha256(reinterpret_cast<const uint8_t*>(readerSecret.data()), readerSecret.size(),
               reinterpret_cast<const uint8_t*>(encLabel.data()), encLabel.size(), ke);
    const std::string aad = std::string(KEY_WRAP_LABEL_V2) + credId + "\n" + keyNonceHex;
    const bool ok = chacha20Poly1305Decrypt(ke, keyNonce,
                                            reinterpret_cast<const uint8_t*>(aad.data()),
                                            aad.size(), ct, KEY_LEN, tag, keyOut);
    memset(ke, 0, sizeof(ke));
    memset(ct, 0, sizeof(ct));
    memset(tag, 0, sizeof(tag));
    memset(keyNonce, 0, sizeof(keyNonce));
    return ok ? KEY_LEN : 0;
}

// --- ChaCha20-Poly1305 AEAD (RFC 8439, compact, no dependencies) ---------------

namespace {

inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

inline uint32_t load32le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

inline void store32le(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

#define RC522HCE_QR(x, a, b, c, d)       \
    x[a] += x[b];                        \
    x[d] ^= x[a];                        \
    x[d] = rotl32(x[d], 16);             \
    x[c] += x[d];                        \
    x[b] ^= x[c];                        \
    x[b] = rotl32(x[b], 12);             \
    x[a] += x[b];                        \
    x[d] ^= x[a];                        \
    x[d] = rotl32(x[d], 8);              \
    x[c] += x[d];                        \
    x[b] ^= x[c];                        \
    x[b] = rotl32(x[b], 7)

void chachaBlock(const uint32_t in[16], uint8_t out[64]) {
    uint32_t x[16];
    memcpy(x, in, sizeof(x));
    for (int i = 0; i < 10; i++) {
        RC522HCE_QR(x, 0, 4, 8, 12);
        RC522HCE_QR(x, 1, 5, 9, 13);
        RC522HCE_QR(x, 2, 6, 10, 14);
        RC522HCE_QR(x, 3, 7, 11, 15);
        RC522HCE_QR(x, 0, 5, 10, 15);
        RC522HCE_QR(x, 1, 6, 11, 12);
        RC522HCE_QR(x, 2, 7, 8, 13);
        RC522HCE_QR(x, 3, 4, 9, 14);
    }
    for (int i = 0; i < 16; i++) {
        store32le(out + 4 * i, x[i] + in[i]);
    }
}

// XOR (en/de)crypt: keystream from counter onwards. in/out may alias.
void chachaXor(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
               const uint8_t* in, uint8_t* out, size_t len) {
    uint32_t state[16];
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) {
        state[4 + i] = load32le(key + 4 * i);
    }
    state[12] = counter;
    for (int i = 0; i < 3; i++) {
        state[13 + i] = load32le(nonce + 4 * i);
    }
    uint8_t block[64];
    size_t off = 0;
    while (len > 0) {
        state[12] = counter++;
        chachaBlock(state, block);
        size_t take = len < sizeof(block) ? len : sizeof(block);
        for (size_t i = 0; i < take; i++) {
            out[off + i] = static_cast<uint8_t>(in[off + i] ^ block[i]);
        }
        off += take;
        len -= take;
    }
    memset(block, 0, sizeof(block));
    memset(state, 0, sizeof(state));
}

// --- Poly1305 (radix 2^26, 32-bit limbs; uint64_t accumulators only) ---------
static const uint32_t kP26Mask = 0x3ffffff;

struct Poly1305 {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    uint8_t buf[16];
    size_t buflen;
};

void polyInit(Poly1305* st, const uint8_t key[32]) {
    const uint32_t t0 = load32le(key + 0);
    const uint32_t t1 = load32le(key + 4);
    const uint32_t t2 = load32le(key + 8);
    const uint32_t t3 = load32le(key + 12);
    // r &= 0x0ffffffc0ffffffc0ffffffc0fffffff (clamp)
    st->r[0] = t0 & 0x3ffffff;
    st->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
    st->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
    st->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
    st->r[4] = (t3 >> 8) & 0x00fffff;
    for (int i = 0; i < 5; i++) {
        st->h[i] = 0;
    }
    for (int i = 0; i < 4; i++) {
        st->pad[i] = load32le(key + 16 + 4 * i);
    }
    st->buflen = 0;
}

void polyMul(Poly1305* st) {
    const uint64_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
    const uint64_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3], r4 = st->r[4];
    const uint64_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint64_t t0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
    uint64_t t1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
    uint64_t t2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
    uint64_t t3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
    uint64_t t4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
    uint64_t c;
    c = t0 >> 26;
    t1 += c;
    t0 &= kP26Mask;
    c = t1 >> 26;
    t2 += c;
    t1 &= kP26Mask;
    c = t2 >> 26;
    t3 += c;
    t2 &= kP26Mask;
    c = t3 >> 26;
    t4 += c;
    t3 &= kP26Mask;
    c = t4 >> 26;
    t0 += c * 5;
    t4 &= kP26Mask;
    c = t0 >> 26;
    t1 += c;
    t0 &= kP26Mask;
    st->h[0] = static_cast<uint32_t>(t0);
    st->h[1] = static_cast<uint32_t>(t1);
    st->h[2] = static_cast<uint32_t>(t2);
    st->h[3] = static_cast<uint32_t>(t3);
    st->h[4] = static_cast<uint32_t>(t4);
}

// Fold one 16-byte block (with the 2^128 bit at hibit) into h, then multiply.
void polyBlock(Poly1305* st, const uint8_t m[16], uint32_t hibit) {
    // Normalize h first so limbs stay bounded over arbitrary-length input.
    uint32_t c = st->h[0] >> 26;
    st->h[1] += c;
    st->h[0] &= kP26Mask;
    c = st->h[1] >> 26;
    st->h[2] += c;
    st->h[1] &= kP26Mask;
    c = st->h[2] >> 26;
    st->h[3] += c;
    st->h[2] &= kP26Mask;
    c = st->h[3] >> 26;
    st->h[4] += c;
    st->h[3] &= kP26Mask;
    c = st->h[4] >> 26;
    st->h[0] += c * 5;
    st->h[4] &= kP26Mask;
    const uint32_t t0 = load32le(m + 0);
    const uint32_t t1 = load32le(m + 4);
    const uint32_t t2 = load32le(m + 8);
    const uint32_t t3 = load32le(m + 12);
    st->h[0] += t0 & kP26Mask;
    st->h[1] += (static_cast<uint32_t>(((static_cast<uint64_t>(t1) << 32) | t0) >> 26)) & kP26Mask;
    st->h[2] += (static_cast<uint32_t>(((static_cast<uint64_t>(t2) << 32) | t1) >> 20)) & kP26Mask;
    st->h[3] += (static_cast<uint32_t>(((static_cast<uint64_t>(t3) << 32) | t2) >> 14)) & kP26Mask;
    st->h[4] += (t3 >> 8) | hibit;
    polyMul(st);
}

void polyUpdate(Poly1305* st, const uint8_t* m, size_t len) {
    if (m == nullptr || len == 0) {
        return;
    }
    if (st->buflen > 0) {
        size_t want = 16 - st->buflen;
        if (want > len) {
            want = len;
        }
        memcpy(st->buf + st->buflen, m, want);
        st->buflen += want;
        m += want;
        len -= want;
        if (st->buflen == 16) {
            polyBlock(st, st->buf, static_cast<uint32_t>(1) << 24);
            st->buflen = 0;
        }
    }
    while (len >= 16) {
        polyBlock(st, m, static_cast<uint32_t>(1) << 24);
        m += 16;
        len -= 16;
    }
    if (len > 0) {
        memcpy(st->buf, m, len);
        st->buflen = len;
    }
}

void polyFinish(Poly1305* st, uint8_t mac[16]) {
    if (st->buflen > 0) {
        uint8_t tmp[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        memcpy(tmp, st->buf, st->buflen);
        tmp[st->buflen] = 0x01;  // the 2^(8*len) bit; hibit already 0
        polyBlock(st, tmp, 0);
    }
    // Full carry.
    uint32_t c = st->h[1] >> 26;
    st->h[2] += c;
    st->h[1] &= kP26Mask;
    c = st->h[2] >> 26;
    st->h[3] += c;
    st->h[2] &= kP26Mask;
    c = st->h[3] >> 26;
    st->h[4] += c;
    st->h[3] &= kP26Mask;
    c = st->h[4] >> 26;
    st->h[0] += c * 5;
    st->h[4] &= kP26Mask;
    c = st->h[0] >> 26;
    st->h[1] += c;
    st->h[0] &= kP26Mask;
    // Freeze: h = h < p ? h : h - p.
    uint32_t g0 = st->h[0] + 5;
    c = g0 >> 26;
    g0 &= kP26Mask;
    uint32_t g1 = st->h[1] + c;
    c = g1 >> 26;
    g1 &= kP26Mask;
    uint32_t g2 = st->h[2] + c;
    c = g2 >> 26;
    g2 &= kP26Mask;
    uint32_t g3 = st->h[3] + c;
    c = g3 >> 26;
    g3 &= kP26Mask;
    uint32_t g4 = st->h[4] + c - (static_cast<uint32_t>(1) << 26);
    uint32_t mask = (g4 >> 31) - 1;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;
    st->h[0] = (st->h[0] & mask) | g0;
    st->h[1] = (st->h[1] & mask) | g1;
    st->h[2] = (st->h[2] & mask) | g2;
    st->h[3] = (st->h[3] & mask) | g3;
    st->h[4] = (st->h[4] & mask) | g4;
    // h += s, serialize little-endian.
    uint32_t h0 = st->h[0] | (st->h[1] << 26);
    uint32_t h1 = (st->h[1] >> 6) | (st->h[2] << 20);
    uint32_t h2 = (st->h[2] >> 12) | (st->h[3] << 14);
    uint32_t h3 = (st->h[3] >> 18) | (st->h[4] << 8);
    uint64_t f = static_cast<uint64_t>(h0) + st->pad[0];
    h0 = static_cast<uint32_t>(f);
    f = static_cast<uint64_t>(h1) + st->pad[1] + (f >> 32);
    h1 = static_cast<uint32_t>(f);
    f = static_cast<uint64_t>(h2) + st->pad[2] + (f >> 32);
    h2 = static_cast<uint32_t>(f);
    f = static_cast<uint64_t>(h3) + st->pad[3] + (f >> 32);
    h3 = static_cast<uint32_t>(f);
    store32le(mac + 0, h0);
    store32le(mac + 4, h1);
    store32le(mac + 8, h2);
    store32le(mac + 12, h3);
    memset(st, 0, sizeof(*st));
}

void polyMac(const uint8_t key[32], const uint8_t* msg, size_t len, uint8_t mac[16]) {
    Poly1305 st;
    polyInit(&st, key);
    polyUpdate(&st, msg, len);
    polyFinish(&st, mac);
}

// One-time Poly1305 key: first 32 bytes of ChaCha20(key, counter 0, nonce).
void polyKeyGen(const uint8_t key[32], const uint8_t nonce[12], uint8_t otk[32]) {
    uint8_t block[64];
    uint32_t state[16];
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) {
        state[4 + i] = load32le(key + 4 * i);
    }
    state[12] = 0;
    for (int i = 0; i < 3; i++) {
        state[13 + i] = load32le(nonce + 4 * i);
    }
    uint32_t in[16];
    memcpy(in, state, sizeof(in));
    chachaBlock(in, block);
    memcpy(otk, block, 32);
    memset(block, 0, sizeof(block));
    memset(state, 0, sizeof(state));
    memset(in, 0, sizeof(in));
}

void writeLe64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; i++) {
        p[i] = static_cast<uint8_t>(v >> (8 * i));
    }
}

// Forward-declared; defined with the server-side verification helpers below.
bool constantTimeEqual(const uint8_t* a, const uint8_t* b, size_t n);

}  // namespace

void chacha20Block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                   uint8_t out[64]) {
    if (key == nullptr || nonce == nullptr || out == nullptr) {
        return;
    }
    uint32_t in[16];
    in[0] = 0x61707865;
    in[1] = 0x3320646e;
    in[2] = 0x79622d32;
    in[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) {
        in[4 + i] = load32le(key + 4 * i);
    }
    in[12] = counter;
    for (int i = 0; i < 3; i++) {
        in[13 + i] = load32le(nonce + 4 * i);
    }
    chachaBlock(in, out);
    memset(in, 0, sizeof(in));
}

void chacha20Poly1305Encrypt(const uint8_t key[AEAD_KEY_LEN],
                             const uint8_t nonce[AEAD_NONCE_LEN],
                             const uint8_t* aad, size_t aadLen,
                             const uint8_t* pt, size_t ptLen,
                             uint8_t* ct, uint8_t tag[AEAD_TAG_LEN]) {
    if (key == nullptr || nonce == nullptr || ct == nullptr || tag == nullptr) {
        return;
    }
    if ((aadLen > 0 && aad == nullptr) || (ptLen > 0 && pt == nullptr)) {
        return;
    }
    uint8_t otk[32];
    polyKeyGen(key, nonce, otk);
    chachaXor(key, 1, nonce, pt, ct, ptLen);
    Poly1305 st;
    polyInit(&st, otk);
    memset(otk, 0, sizeof(otk));
    polyUpdate(&st, aad, aadLen);
    if (aadLen % 16 != 0) {
        static const uint8_t kZero[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        polyUpdate(&st, kZero, 16 - (aadLen % 16));
    }
    polyUpdate(&st, ct, ptLen);
    if (ptLen % 16 != 0) {
        static const uint8_t kZero[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        polyUpdate(&st, kZero, 16 - (ptLen % 16));
    }
    uint8_t lens[16];
    writeLe64(lens, static_cast<uint64_t>(aadLen));
    writeLe64(lens + 8, static_cast<uint64_t>(ptLen));
    polyUpdate(&st, lens, sizeof(lens));
    polyFinish(&st, tag);
}

bool chacha20Poly1305Decrypt(const uint8_t key[AEAD_KEY_LEN],
                             const uint8_t nonce[AEAD_NONCE_LEN],
                             const uint8_t* aad, size_t aadLen,
                             const uint8_t* ct, size_t ctLen,
                             const uint8_t tag[AEAD_TAG_LEN], uint8_t* pt) {
    if (key == nullptr || nonce == nullptr || tag == nullptr || pt == nullptr) {
        return false;
    }
    if ((aadLen > 0 && aad == nullptr) || (ctLen > 0 && ct == nullptr)) {
        memset(pt, 0, ctLen);
        return false;
    }
    uint8_t otk[32];
    polyKeyGen(key, nonce, otk);
    Poly1305 st;
    polyInit(&st, otk);
    memset(otk, 0, sizeof(otk));
    polyUpdate(&st, aad, aadLen);
    if (aadLen % 16 != 0) {
        static const uint8_t kZero[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        polyUpdate(&st, kZero, 16 - (aadLen % 16));
    }
    polyUpdate(&st, ct, ctLen);
    if (ctLen % 16 != 0) {
        static const uint8_t kZero[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        polyUpdate(&st, kZero, 16 - (ctLen % 16));
    }
    uint8_t lens[16];
    writeLe64(lens, static_cast<uint64_t>(aadLen));
    writeLe64(lens + 8, static_cast<uint64_t>(ctLen));
    polyUpdate(&st, lens, sizeof(lens));
    uint8_t expected[AEAD_TAG_LEN];
    polyFinish(&st, expected);
    if (!constantTimeEqual(tag, expected, AEAD_TAG_LEN)) {
        memset(pt, 0, ctLen);
        return false;
    }
    chachaXor(key, 1, nonce, ct, pt, ctLen);
    return true;
}

// --- Server-side verification ---------------------------------------------------

namespace {

/** Constant-time compare: a MAC comparison must not leak via timing. */
bool constantTimeEqual(const uint8_t* a, const uint8_t* b, size_t n) {
    volatile unsigned diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= static_cast<unsigned>(a[i] ^ b[i]);
    }
    return diff == 0;
}

}  // namespace

size_t unhex(const std::string& hex, uint8_t* out, size_t cap) {
    if (out == nullptr || hex.empty() || (hex.size() % 2) != 0) {
        return 0;
    }
    const size_t n = hex.size() / 2;
    if (n > cap) {
        return 0;
    }
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < n; i++) {
        const int hi = nibble(hex[2 * i]);
        const int lo = nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return 0;
        }
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return n;
}

bool verifyProof(const std::string& credId, const std::string& nonceHex,
                 const std::string& macHex, const uint8_t key[KEY_LEN]) {
    if (key == nullptr || macHex.size() != HMAC_LEN * 2 || nonceHex.empty()) {
        return false;
    }
    uint8_t nonce[NONCE_LEN];
    uint8_t mac[HMAC_LEN];
    if (unhex(nonceHex, nonce, sizeof(nonce)) != NONCE_LEN) {
        return false;  // the reader always sends exactly NONCE_LEN
    }
    if (unhex(macHex, mac, sizeof(mac)) != HMAC_LEN) {
        return false;
    }
    if (credId.empty() || credId.size() > MAX_CRED_LEN) {
        return false;  // an id the protocol could not carry cannot verify
    }
    uint8_t msg[MAX_CRED_LEN + NONCE_LEN];
    memcpy(msg, credId.data(), credId.size());
    memcpy(msg + credId.size(), nonce, NONCE_LEN);
    uint8_t expected[HMAC_LEN];
    hmacSha256(key, KEY_LEN, msg, credId.size() + NONCE_LEN, expected);
    memset(msg, 0, sizeof(msg));
    return constantTimeEqual(mac, expected, HMAC_LEN);
}

const char* statusWordName(uint8_t sw1, uint8_t sw2) {
    if (sw1 == 0x90 && sw2 == 0x00) {
        return "9000 (success)";
    }
    if (sw1 == 0x6A && sw2 == 0x82) {
        return "6A82 (app/AID not found — no app routed to our AID)";
    }
    if (sw1 == 0x6A && sw2 == 0x88) {
        return "6A88 (no key provisioned on the phone — enroll it)";
    }
    if (sw1 == 0x69 && sw2 == 0x85) {
        return "6985 (conditions not satisfied — enrollment window closed)";
    }
    if (sw1 == 0x67 && sw2 == 0x00) {
        return "6700 (wrong length)";
    }
    if (sw1 == 0x6D && sw2 == 0x00) {
        return "6D00 (INS unknown)";
    }
    if (sw1 == 0x6E && sw2 == 0x00) {
        return "6E00 (CLA unknown)";
    }
    return nullptr;
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
