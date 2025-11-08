#ifndef DEF_H
#define DEF_H

#include <stdint.h>
#include <array>

constexpr uint16_t N = 256;
constexpr uint16_t Q = 3329;
constexpr uint16_t ZETA = 17;

using Polynomial = std::array<uint16_t, N>;              // Coefficient Domain
using NTTPolynomial = std::array<uint16_t, N>;            // Frequency Domain

template<std::size_t K>
using PolyVector = std::array<Polynomial, K>;

template<std::size_t K>
using PolyMatrix = std::array<std::array<Polynomial, K>, K>;


int16_t mod_reduce(int32_t x);
int16_t montgomery_reduce(int32_t a);

void ntt_forward(NTTPolynomial& poly);
void ntt_inverse(Polynomial& poly);

Polynomial polynomial_multiplication(const Polynomial& a, const Polynomial& b);
#endif