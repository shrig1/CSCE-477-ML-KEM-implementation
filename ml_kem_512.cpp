// BROKEN IMPLEMENTATION - Couldn't get it to work, I think we have to just settle for an already made implementation shown in main.cpp :(



#include <cryptopp/sha3.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <array>
#include <vector>
#include <cstring>
#include <iostream>
#include <iomanip>

// ============================================================================
// ML-KEM-512 Parameters
// ============================================================================
constexpr int N = 256;           // Polynomial degree
constexpr int Q = 3329;          // Prime modulus
constexpr int K = 2;             // Dimension (512 = k×256)
constexpr int ETA1 = 3;          // CBD parameter for secrets/errors
constexpr int ETA2 = 2;          // CBD parameter for encryption noise
constexpr int DU = 10;           // Compression parameter for u
constexpr int DV = 4;            // Compression parameter for v

// Key/ciphertext sizes
constexpr size_t EK_PKE_SIZE = 384 * K + 32;        // 800 bytes
constexpr size_t DK_PKE_SIZE = 384 * K;             // 768 bytes
constexpr size_t DK_SIZE = DK_PKE_SIZE + EK_PKE_SIZE + 64;  // 1632 bytes
constexpr size_t CT_SIZE = 32 * DU * K + 32 * DV;   // 768 bytes

// ============================================================================
// Type Definitions
// ============================================================================
using Polynomial = std::array<int16_t, N>;
template<size_t k>
using PolyVector = std::array<Polynomial, k>;
template<size_t k>
using PolyMatrix = std::array<std::array<Polynomial, k>, k>;

// ============================================================================
// Precomputed NTT Constants
// ============================================================================
// These are ζ^BitRev7(i) mod 3329 where ζ = 17
constexpr std::array<int16_t, 128> ZETAS = {
    1, 1729, 2580, 3289, 2642, 630, 1897, 848,
    1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
    1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
    650, 1977, 2513, 632, 2865, 33, 1320, 1915,
    2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
    2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
    17, 2761, 583, 2649, 1637, 723, 2288, 1100,
    1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
    939, 2308, 2437, 2388, 733, 2337, 268, 641,
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
    1063, 319, 2773, 757, 2099, 561, 2466, 2594,
    2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
    1722, 1212, 1874, 1029, 2110, 2935, 885, 2154
};

constexpr std::array<int16_t, 128> ZETAS_INV = {
    1701, 1807, 1460, 2371, 2338, 2333, 308, 108,
    2851, 870, 854, 1510, 2535, 1278, 1530, 1185,
    1659, 1187, 3109, 874, 1335, 2111, 136, 1215,
    2945, 1465, 1285, 2007, 2719, 2726, 2232, 2512,
    75, 156, 3000, 2911, 2980, 872, 2685, 1590,
    2210, 602, 1846, 777, 147, 2170, 2551, 246,
    1676, 1755, 460, 291, 235, 3152, 2742, 2907,
    3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103,
    1275, 2652, 1065, 2881, 725, 1508, 2368, 398,
    951, 247, 1421, 3222, 2499, 271, 90, 853,
    1860, 3203, 1162, 1618, 666, 320, 8, 2813,
    1544, 282, 1838, 1293, 2314, 552, 2677, 2106,
    1571, 205, 2918, 1542, 2721, 2597, 2312, 681,
    130, 1602, 1871, 829, 2946, 3065, 1325, 2756,
    1861, 1474, 1202, 2367, 3147, 1752, 2707, 171,
    3127, 3042, 1907, 1836, 1517, 359, 758, 1441
};

// ============================================================================
// Modular Arithmetic
// ============================================================================

// Barrett reduction: reduces x mod Q
inline int16_t barrett_reduce(int16_t x) {
    // For Q = 3329, multiplier v = ⌊2^26 / Q⌋ = 20159
    int32_t t = ((int32_t)x * 20159) >> 26;
    t = x - t * Q;
    return t;
}

// Montgomery reduction: computes a*R^-1 mod Q where R = 2^16
inline int16_t montgomery_reduce(int32_t a) {
    // QINV = -Q^-1 mod 2^16 = 62209
    int16_t t = (int16_t)(a * 62209);
    t = (a - (int32_t)t * Q) >> 16;
    return t;
}

// ============================================================================
// Bit Manipulation
// ============================================================================

std::vector<uint8_t> BitsToBytes(const std::vector<bool>& bits) {
    size_t n = bits.size() / 8;
    std::vector<uint8_t> bytes(n);
    for (size_t i = 0; i < n; i++) {
        bytes[i] = 0;
        for (int j = 0; j < 8; j++) {
            bytes[i] |= (bits[8*i + j] ? 1 : 0) << j;
        }
    }
    return bytes;
}

std::vector<bool> BytesToBits(const std::vector<uint8_t>& bytes) {
    std::vector<bool> bits(bytes.size() * 8);
    for (size_t i = 0; i < bytes.size(); i++) {
        uint8_t b = bytes[i];
        for (int j = 0; j < 8; j++) {
            bits[8*i + j] = (b & 1);
            b >>= 1;
        }
    }
    return bits;
}

// ============================================================================
// Encoding/Decoding
// ============================================================================

std::vector<uint8_t> ByteEncode(const Polynomial& poly, int d) {
    std::vector<bool> bits(256 * d);
    for (int i = 0; i < 256; i++) {
        int16_t val = poly[i];
        for (int j = 0; j < d; j++) {
            bits[i*d + j] = (val >> j) & 1;
        }
    }
    return BitsToBytes(bits);
}

Polynomial ByteDecode(const std::vector<uint8_t>& bytes, int d) {
    auto bits = BytesToBits(bytes);
    Polynomial poly;
    for (int i = 0; i < 256; i++) {
        int16_t val = 0;
        for (int j = 0; j < d; j++) {
            if (bits[i*d + j]) val |= (1 << j);
        }
        poly[i] = val;
    }
    return poly;
}

// ============================================================================
// Compression/Decompression
// ============================================================================

Polynomial Compress(const Polynomial& poly, int d) {
    Polynomial result;
    for (int i = 0; i < 256; i++) {
        // Compress: round((2^d / q) * x) mod 2^d
        int32_t x = poly[i];
        x = ((x << d) + Q/2) / Q;
        result[i] = x & ((1 << d) - 1);
    }
    return result;
}

Polynomial Decompress(const Polynomial& poly, int d) {
    Polynomial result;
    for (int i = 0; i < 256; i++) {
        // Decompress: round((q / 2^d) * x)
        int32_t x = poly[i];
        result[i] = (x * Q + (1 << (d-1))) >> d;
    }
    return result;
}

// ============================================================================
// NTT Operations
// ============================================================================

// Algorithm 9: Forward NTT
void NTT(Polynomial& poly) {
    int k = 1;
    for (int len = 128; len >= 2; len >>= 1) {
        for (int start = 0; start < 256; start += 2 * len) {
            int16_t zeta = ZETAS[k++];
            for (int j = start; j < start + len; j++) {
                int16_t t = montgomery_reduce((int32_t)zeta * poly[j + len]);
                poly[j + len] = poly[j] - t;
                poly[j] = poly[j] + t;
            }
        }
    }
}

// Algorithm 10: Inverse NTT
void InvNTT(Polynomial& poly) {
    int k = 127;
    for (int len = 2; len <= 128; len <<= 1) {
        for (int start = 0; start < 256; start += 2 * len) {
            int16_t zeta = ZETAS_INV[k--];
            for (int j = start; j < start + len; j++) {
                int16_t t = poly[j];
                poly[j] = barrett_reduce(t + poly[j + len]);
                poly[j + len] = t - poly[j + len];
                poly[j + len] = montgomery_reduce((int32_t)zeta * poly[j + len]);
            }
        }
    }
    // Multiply by n^-1 = 3303 mod Q
    for (int j = 0; j < 256; j++) {
        poly[j] = montgomery_reduce((int32_t)poly[j] * 3303);
    }
}

// Algorithm 12: Base case multiplication
void BaseCaseMultiply(int16_t& c0, int16_t& c1,
                      int16_t a0, int16_t a1,
                      int16_t b0, int16_t b1,
                      int16_t gamma) {
    c0 = montgomery_reduce((int32_t)a0 * b0 + (int32_t)montgomery_reduce((int32_t)a1 * b1) * gamma);
    c1 = montgomery_reduce((int32_t)a0 * b1 + (int32_t)a1 * b0);
}

// Algorithm 11: Multiply two NTT polynomials
Polynomial MultiplyNTTs(const Polynomial& a, const Polynomial& b) {
    Polynomial result;
    for (int i = 0; i < 128; i++) {
        int16_t gamma = ZETAS[64 + i];  // ζ^(2*BitRev7(i)+1)
        BaseCaseMultiply(
            result[2*i], result[2*i+1],
            a[2*i], a[2*i+1],
            b[2*i], b[2*i+1],
            gamma
        );
    }
    return result;
}

// ============================================================================
// Sampling 
// ============================================================================

// Algorithm 7: Sample NTT polynomial uniformly from XOF
Polynomial SampleNTT(const std::vector<uint8_t>& rho, uint8_t i, uint8_t j) {
    Polynomial result;
    CryptoPP::SHA3_512 xof;
    xof.Update(rho.data(), 32);
    xof.Update(&j, 1);
    xof.Update(&i, 1);
    
    std::vector<uint8_t> buf(3 * 256);  // Enough bytes for rejection sampling
    xof.Final(buf.data());
    
    int pos = 0, coeff = 0;
    while (coeff < 256) {
        uint16_t d1 = buf[pos] | ((buf[pos+1] & 0x0F) << 8);
        uint16_t d2 = (buf[pos+1] >> 4) | (buf[pos+2] << 4);
        pos += 3;
        
        if (d1 < Q) result[coeff++] = d1;
        if (coeff < 256 && d2 < Q) result[coeff++] = d2;
    }
    return result;
}


Polynomial SamplePolyCBD(const std::vector<uint8_t>& bytes, int eta) {
    auto bits = BytesToBits(bytes);
    Polynomial result;
    
    for (int i = 0; i < 256; i++) {
        int x = 0, y = 0;
        for (int j = 0; j < eta; j++) {
            x += bits[2*i*eta + j];
            y += bits[2*i*eta + eta + j];
        }
        result[i] = x - y;
    }
    return result;
}

// ============================================================================
// Hash Functions
// ============================================================================

std::array<uint8_t, 32> H(const uint8_t* data, size_t len) {
    std::array<uint8_t, 32> output;
    CryptoPP::SHA3_256 hash;
    hash.Update(data, len);
    hash.Final(output.data());
    return output;
}

std::array<uint8_t, 32> J(const uint8_t* data, size_t len) {
    std::array<uint8_t, 32> output;
    CryptoPP::SHA3_256 xof;
    xof.Update(data, len);
    xof.Final(output.data());
    return output;
}

std::array<uint8_t, 64> G(const uint8_t* data, size_t len) {
    std::array<uint8_t, 64> output;
    CryptoPP::SHA3_512 hash;
    hash.Update(data, len);
    hash.Final(output.data());
    return output;
}

std::vector<uint8_t> PRF(const std::array<uint8_t, 32>& sigma, uint8_t nonce, size_t len) {
    std::vector<uint8_t> output(len);
    CryptoPP::SHA3_256 xof;
    xof.Update(sigma.data(), 32);
    xof.Update(&nonce, 1);
    xof.Final(output.data());
    return output;
}

// ============================================================================
// Vector/Matrix Operations
// ============================================================================

PolyVector<K> AddPolyVectors(const PolyVector<K>& a, const PolyVector<K>& b) {
    PolyVector<K> result;
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < 256; j++) {
            result[i][j] = a[i][j] + b[i][j];
        }
    }
    return result;
}

PolyVector<K> MatrixVectorMul(const PolyMatrix<K>& A, const PolyVector<K>& v) {
    PolyVector<K> result;
    for (int i = 0; i < K; i++) {
        result[i].fill(0);
        for (int j = 0; j < K; j++) {
            auto prod = MultiplyNTTs(A[i][j], v[j]);
            for (int k = 0; k < 256; k++) {
                result[i][k] += prod[k];
            }
        }
    }
    return result;
}

int16_t DotProduct(const PolyVector<K>& a, const PolyVector<K>& b) {
    Polynomial sum;
    sum.fill(0);
    for (int i = 0; i < K; i++) {
        auto prod = MultiplyNTTs(a[i], b[i]);
        for (int j = 0; j < 256; j++) {
            sum[j] += prod[j];
        }
    }
    return sum[0];
}

// ============================================================================
// K-PKE Algorithms
// ============================================================================

struct KeyPairPKE {
    std::vector<uint8_t> ek;
    std::vector<uint8_t> dk;
};

// Algorithm 13: K-PKE.KeyGen
KeyPairPKE KPKE_KeyGen(const std::array<uint8_t, 32>& d) {
    // Expand seed
    auto g_output = G(d.data(), 32);
    std::array<uint8_t, 32> rho, sigma;
    std::memcpy(rho.data(), g_output.data(), 32);
    std::memcpy(sigma.data(), g_output.data() + 32, 32);
    
    uint8_t N = 0;
    
    // Generate matrix A in NTT domain
    PolyMatrix<K> A_hat;
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < K; j++) {
            A_hat[i][j] = SampleNTT(std::vector<uint8_t>(rho.begin(), rho.end()), i, j);
        }
    }
    
    // Sample secret vector s
    PolyVector<K> s;
    for (int i = 0; i < K; i++) {
        auto bytes = PRF(sigma, N++, 64 * ETA1);
        s[i] = SamplePolyCBD(bytes, ETA1);
        NTT(s[i]);
    }
    
    // Sample error vector e
    PolyVector<K> e;
    for (int i = 0; i < K; i++) {
        auto bytes = PRF(sigma, N++, 64 * ETA1);
        e[i] = SamplePolyCBD(bytes, ETA1);
        NTT(e[i]);
    }
    
    // Compute t = A*s + e
    auto t_hat = MatrixVectorMul(A_hat, s);
    t_hat = AddPolyVectors(t_hat, e);
    
    // Encode keys
    KeyPairPKE keys;
    keys.ek.reserve(EK_PKE_SIZE);
    keys.dk.reserve(DK_PKE_SIZE);
    
    for (int i = 0; i < K; i++) {
        auto encoded = ByteEncode(t_hat[i], 12);
        keys.ek.insert(keys.ek.end(), encoded.begin(), encoded.end());
    }
    keys.ek.insert(keys.ek.end(), rho.begin(), rho.end());
    
    for (int i = 0; i < K; i++) {
        auto encoded = ByteEncode(s[i], 12);
        keys.dk.insert(keys.dk.end(), encoded.begin(), encoded.end());
    }
    
    return keys;
}

// Algorithm 14: K-PKE.Encrypt
std::vector<uint8_t> KPKE_Encrypt(const std::vector<uint8_t>& ek,
                                  const std::array<uint8_t, 32>& m,
                                  const std::array<uint8_t, 32>& r) {
    // Parse public key
    PolyVector<K> t_hat;
    for (int i = 0; i < K; i++) {
        std::vector<uint8_t> poly_bytes(ek.begin() + i*384, ek.begin() + (i+1)*384);
        t_hat[i] = ByteDecode(poly_bytes, 12);
    }
    
    std::array<uint8_t, 32> rho;
    std::memcpy(rho.data(), ek.data() + 384*K, 32);
    
    // Regenerate matrix A
    PolyMatrix<K> A_hat;
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < K; j++) {
            A_hat[i][j] = SampleNTT(std::vector<uint8_t>(rho.begin(), rho.end()), i, j);
        }
    }
    
    uint8_t N = 0;
    
    // Sample randomness vector r
    PolyVector<K> r_vec;
    for (int i = 0; i < K; i++) {
        auto bytes = PRF(r, N++, 64 * ETA1);
        r_vec[i] = SamplePolyCBD(bytes, ETA1);
        NTT(r_vec[i]);
    }
    
    // Sample error vectors
    PolyVector<K> e1;
    for (int i = 0; i < K; i++) {
        auto bytes = PRF(r, N++, 64 * ETA2);
        e1[i] = SamplePolyCBD(bytes, ETA2);
    }
    
    auto bytes_e2 = PRF(r, N++, 64 * ETA2);
    Polynomial e2 = SamplePolyCBD(bytes_e2, ETA2);
    
    // Compute u = A^T * r + e1
    PolyMatrix<K> A_T;
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < K; j++) {
            A_T[i][j] = A_hat[j][i];
        }
    }
    auto u = MatrixVectorMul(A_T, r_vec);
    for (int i = 0; i < K; i++) {
        InvNTT(u[i]);
    }
    u = AddPolyVectors(u, e1);
    
    // Decompress message
    auto m_bits = BytesToBits(std::vector<uint8_t>(m.begin(), m.end()));
    Polynomial mu;
    for (int i = 0; i < 256; i++) {
        mu[i] = m_bits[i] ? (Q+1)/2 : 0;  // Decompress_1
    }
    
    // Compute v = t^T * r + e2 + mu
    Polynomial v;
    v.fill(0);
    for (int i = 0; i < K; i++) {
        auto prod = MultiplyNTTs(t_hat[i], r_vec[i]);
        InvNTT(prod);
        for (int j = 0; j < 256; j++) {
            v[j] += prod[j];
        }
    }
    for (int j = 0; j < 256; j++) {
        v[j] = v[j] + e2[j] + mu[j];
    }
    
    // Compress and encode
    std::vector<uint8_t> c;
    for (int i = 0; i < K; i++) {
        auto compressed = Compress(u[i], DU);
        auto encoded = ByteEncode(compressed, DU);
        c.insert(c.end(), encoded.begin(), encoded.end());
    }
    
    auto v_compressed = Compress(v, DV);
    auto v_encoded = ByteEncode(v_compressed, DV);
    c.insert(c.end(), v_encoded.begin(), v_encoded.end());
    
    return c;
}

// Algorithm 15: K-PKE.Decrypt
std::array<uint8_t, 32> KPKE_Decrypt(const std::vector<uint8_t>& dk,
                                     const std::vector<uint8_t>& c) {
    // Parse secret key
    PolyVector<K> s_hat;
    for (int i = 0; i < K; i++) {
        std::vector<uint8_t> poly_bytes(dk.begin() + i*384, dk.begin() + (i+1)*384);
        s_hat[i] = ByteDecode(poly_bytes, 12);
    }
    
    // Parse ciphertext
    PolyVector<K> u;
    for (int i = 0; i < K; i++) {
        std::vector<uint8_t> u_bytes(c.begin() + i*320, c.begin() + (i+1)*320);
        u[i] = Decompress(ByteDecode(u_bytes, DU), DU);
        NTT(u[i]);
    }
    
    std::vector<uint8_t> v_bytes(c.begin() + 320*K, c.begin() + 320*K + 128);
    Polynomial v = Decompress(ByteDecode(v_bytes, DV), DV);
    
    // Compute w = v - s^T * u
    Polynomial w = v;
    for (int i = 0; i < K; i++) {
        auto prod = MultiplyNTTs(s_hat[i], u[i]);
        InvNTT(prod);
        for (int j = 0; j < 256; j++) {
            w[j] -= prod[j];
        }
    }
    
    // Compress and decode message
    auto w_compressed = Compress(w, 1);
    std::array<uint8_t, 32> m;
    auto m_encoded = ByteEncode(w_compressed, 1);
    std::memcpy(m.data(), m_encoded.data(), 32);
    
    return m;
}

// ============================================================================
// ML-KEM Main Algorithms
// ============================================================================

struct KeyPair {
    std::vector<uint8_t> ek;  // Encapsulation key
    std::vector<uint8_t> dk;  // Decapsulation key
};

// Algorithm 19: ML-KEM.KeyGen()
KeyPair MLKEM_KeyGen() {
    // Generate random seeds
    CryptoPP::AutoSeededRandomPool rng;
    std::array<uint8_t, 32> d, z;
    rng.GenerateBlock(d.data(), 32);
    rng.GenerateBlock(z.data(), 32);
    
    // Generate K-PKE keys
    auto [ek_pke, dk_pke] = KPKE_KeyGen(d);
    
    // Hash encapsulation key
    auto h = H(ek_pke.data(), ek_pke.size());
    
    // Construct ML-KEM keys
    KeyPair keys;
    keys.ek = ek_pke;
    keys.dk.reserve(DK_SIZE);
    keys.dk.insert(keys.dk.end(), dk_pke.begin(), dk_pke.end());
    keys.dk.insert(keys.dk.end(), ek_pke.begin(), ek_pke.end());
    keys.dk.insert(keys.dk.end(), h.begin(), h.end());
    keys.dk.insert(keys.dk.end(), z.begin(), z.end());
    
    return keys;
}

// Algorithm 20: ML-KEM.Encaps(ek)
struct EncapsResult {
    std::array<uint8_t, 32> K;  // Shared secret
    std::vector<uint8_t> c;     // Ciphertext
};

EncapsResult MLKEM_Encaps(const std::vector<uint8_t>& ek) {
    // Generate random message
    CryptoPP::AutoSeededRandomPool rng;
    std::array<uint8_t, 32> m;
    rng.GenerateBlock(m.data(), 32);
    
    // Hash encapsulation key
    auto h = H(ek.data(), ek.size());
    
    // Derive (K̄, r) from G(m ‖ h)
    std::vector<uint8_t> input(64);
    std::memcpy(input.data(), m.data(), 32);
    std::memcpy(input.data() + 32, h.data(), 32);
    auto g_out = G(input.data(), 64);
    
    std::array<uint8_t, 32> K_bar, r;
    std::memcpy(K_bar.data(), g_out.data(), 32);
    std::memcpy(r.data(), g_out.data() + 32, 32);
    
    // Encrypt
    auto c = KPKE_Encrypt(ek, m, r);
    
    // Final KDF
    auto h_c = H(c.data(), c.size());
    std::vector<uint8_t> kdf_input(64);
    std::memcpy(kdf_input.data(), K_bar.data(), 32);
    std::memcpy(kdf_input.data() + 32, h_c.data(), 32);
    auto K = J(kdf_input.data(), 64);
    
    return {K, c};
}

// Algorithm 21: ML-KEM.Decaps(dk, c)
std::array<uint8_t, 32> MLKEM_Decaps(const std::vector<uint8_t>& dk,
                                     const std::vector<uint8_t>& c) {
    // Parse decapsulation key
    std::vector<uint8_t> dk_pke(dk.begin(), dk.begin() + DK_PKE_SIZE);
    std::vector<uint8_t> ek_pke(dk.begin() + DK_PKE_SIZE, dk.begin() + DK_PKE_SIZE + EK_PKE_SIZE);
    
    std::array<uint8_t, 32> h, z;
    std::memcpy(h.data(), dk.data() + DK_PKE_SIZE + EK_PKE_SIZE, 32);
    std::memcpy(z.data(), dk.data() + DK_PKE_SIZE + EK_PKE_SIZE + 32, 32);
    
    // Decrypt
    auto m_prime = KPKE_Decrypt(dk_pke, c);
    
    // Derive (K̄', r')
    std::vector<uint8_t> input(64);
    std::memcpy(input.data(), m_prime.data(), 32);
    std::memcpy(input.data() + 32, h.data(), 32);
    auto g_out = G(input.data(), 64);
    
    std::array<uint8_t, 32> K_bar_prime, r_prime;
    std::memcpy(K_bar_prime.data(), g_out.data(), 32);
    std::memcpy(r_prime.data(), g_out.data() + 32, 32);
    
    // Re-encrypt
    auto c_prime = KPKE_Encrypt(ek_pke, m_prime, r_prime);
    
    // Constant-time comparison
    bool valid = (c.size() == c_prime.size());
    for (size_t i = 0; i < c.size() && i < c_prime.size(); i++) {
        valid &= (c[i] == c_prime[i]);
    }
    
    // Select key material (implicit rejection)
    auto key_material = valid ? K_bar_prime : z;
    
    // Final KDF
    auto h_c = H(c.data(), c.size());
    std::vector<uint8_t> kdf_input(64);
    std::memcpy(kdf_input.data(), key_material.data(), 32);
    std::memcpy(kdf_input.data() + 32, h_c.data(), 32);
    
    return J(kdf_input.data(), 64);
}

// ============================================================================
// Demo and Testing
// ============================================================================

void print_hex(const char* label, const uint8_t* data, size_t len, size_t max_display = 16) {
    std::cout << label << " (" << len << " bytes):\n  ";
    for (size_t i = 0; i < std::min(len, max_display); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    if (len > max_display) std::cout << "...";
    std::cout << std::dec << "\n";
}

int main() {
    
    // Step 1: Key Generation
    std::cout << "Step 1: Generating keypair...\n";
    auto keys = MLKEM_KeyGen();
    
    print_hex("Public Key (ek)", keys.ek.data(), keys.ek.size());
    print_hex("Secret Key (dk)", keys.dk.data(), keys.dk.size());
    std::cout << "\n";
    
    // Step 2: Encapsulation
    std::cout << "Step 2: Encapsulating (generating shared secret)...\n";
    auto [K_sender, ciphertext] = MLKEM_Encaps(keys.ek);
    
    print_hex("Ciphertext", ciphertext.data(), ciphertext.size());
    print_hex("Sender's Shared Secret (K)", K_sender.data(), 32, 32);
    std::cout << "\n";
    
    // Step 3: Decapsulation
    std::cout << "Step 3: Decapsulating (recovering shared secret)...\n";
    auto K_receiver = MLKEM_Decaps(keys.dk, ciphertext);
    
    print_hex("Receiver's Shared Secret (K)", K_receiver.data(), 32, 32);
    std::cout << "\n";
    
    // Step 4: Verify
    std::cout << "Step 4: Verification...\n";
    bool success = (K_sender == K_receiver);
    
    if (success) {
        std::cout << "SUCCESS: Both parties derived the same shared secret!\n";
        std::cout << "The 32-byte shared secret K can now be used with AES, ChaCha20, etc.\n";
    } else {
        std::cout << "FAILURE: Shared secrets do not match!\n";
    }
    
    std::cout << "\n=================================================================\n";
    std::cout << "ML-KEM-512 Parameters:\n";
    std::cout << "  Security Level: ~AES-128 (NIST Level 1)\n";
    std::cout << "  Public Key Size: " << EK_PKE_SIZE << " bytes\n";
    std::cout << "  Secret Key Size: " << DK_SIZE << " bytes\n";
    std::cout << "  Ciphertext Size: " << CT_SIZE << " bytes\n";
    std::cout << "  Shared Secret: 32 bytes (256 bits)\n";
    std::cout << "=================================================================\n";
    
    return 0;
}
