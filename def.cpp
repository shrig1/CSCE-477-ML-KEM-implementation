#include "def.h"
#include "sha3.h"
#include "shake.h"
#include "misc.h"

int16_t mod_reduce(int32_t x) {
    int r = x % Q;
    if( r < 0 ) {
        r += Q;
    }
    return r;
}

int16_t montgomery_reduce(int32_t a) {
    int16_t t = (int16_t)(a * 62209);  // 62209 = -Q^{-1} mod 2^16
    return (a - t * Q) >> 16;
}


// H(s) := SHA3-256(s)
static std::array<uint8_t, 32> H(const std::vector<uint8_t>& s) {
    std::array<uint8_t, 32> output;
    CryptoPP::SHA3_256 hash;

    hash.Update(s.data(), s.size());
    hash.Final(output.data());

    return output;
}

// J(s) := SHAKE256(s, 8 * 32)
static std::array<uint8_t, 32> J(const std::vector<uint8_t>& s) {
    std::array<uint8_t, 32> output;
    CryptoPP::SHAKE256 xof;
    xof.Update(s.data(), s.size());
    xof.Final(output.data());
    return output;
}