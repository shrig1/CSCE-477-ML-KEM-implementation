#include "ml_kem/ml_kem_768.hpp"
#include "randomshake/randomshake.hpp"
#include <iostream>
#include <iomanip>
#include <string>
#include <array>

// ============================================================================
// Utility Functions
// ============================================================================

void print_hex(const char *label, const uint8_t *data, size_t len, size_t max = 32)
{
    std::cout << label << " (" << len << " bytes):\n  ";
    for (size_t i = 0; i < std::min(len, max); i++)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    if (len > max)
        std::cout << "...";
    std::cout << std::dec << "\n";
}

void print_separator(const std::string &title = "")
{
    std::cout << "\n=================================================================\n";
    if (!title.empty())
    {
        std::cout << title << "\n";
        std::cout << "=================================================================\n";
    }
}

// ============================================================================
// Main Demo
// ============================================================================

int main()
{

    try
    {
        // ====================================================================
        // ML-KEM-768 Key Establishment
        // ====================================================================
        std::cout << "\nML-KEM-768 Parameters:\n";
        std::cout << "  • Security Level: ≈AES-192 (NIST Level 3)\n";
        std::cout << "  • Public Key: " << ml_kem_768::PKEY_BYTE_LEN << " bytes\n";
        std::cout << "  • Secret Key: " << ml_kem_768::SKEY_BYTE_LEN << " bytes\n";
        std::cout << "  • Ciphertext: " << ml_kem_768::CIPHER_TEXT_BYTE_LEN << " bytes\n";
        std::cout << "  • Shared Secret: " << ml_kem_768::SHARED_SECRET_BYTE_LEN << " bytes\n";
        print_separator();

        // Initialize CSPRNG
        randomshake::randomshake_t<> csprng;

        // Step 1: Alice generates her keypair
        std::cout << "\nStep 1: Alice generates ML-KEM-768 keypair...\n";

        std::array<uint8_t, ml_kem_768::SEED_D_BYTE_LEN> seed_d;
        std::array<uint8_t, ml_kem_768::SEED_Z_BYTE_LEN> seed_z;
        std::array<uint8_t, ml_kem_768::PKEY_BYTE_LEN> alice_public_key;
        std::array<uint8_t, ml_kem_768::SKEY_BYTE_LEN> alice_secret_key;

        csprng.generate(seed_d);
        csprng.generate(seed_z);

        ml_kem_768::keygen(seed_d, seed_z, alice_public_key, alice_secret_key);

        print_hex("Alice's Public Key", alice_public_key.data(),
                  alice_public_key.size(), 16);
        print_hex("Alice's Secret Key", alice_secret_key.data(),
                  alice_secret_key.size(), 16);

        // Step 2: Bob encapsulates (creates shared secret)
        std::cout << "\nStep 2: Bob encapsulates using Alice's public key...\n";

        std::array<uint8_t, ml_kem_768::SEED_M_BYTE_LEN> seed_m;
        std::array<uint8_t, ml_kem_768::CIPHER_TEXT_BYTE_LEN> ciphertext;
        std::array<uint8_t, ml_kem_768::SHARED_SECRET_BYTE_LEN> shared_secret_bob;

        csprng.generate(seed_m);

        bool encaps_success = ml_kem_768::encapsulate(
            seed_m, alice_public_key, ciphertext, shared_secret_bob);

        if (!encaps_success)
        {
            std::cerr << "ERROR: Encapsulation failed (malformed public key)\n";
            return 1;
        }

        print_hex("Ciphertext (sent to Alice)", ciphertext.data(),
                  ciphertext.size(), 16);
        print_hex("Bob's Shared Secret", shared_secret_bob.data(), 32);

        // Step 3: Alice decapsulates (recovers shared secret)
        std::cout << "\nStep 3: Alice decapsulates using her secret key...\n";

        std::array<uint8_t, ml_kem_768::SHARED_SECRET_BYTE_LEN> shared_secret_alice;

        ml_kem_768::decapsulate(alice_secret_key, ciphertext, shared_secret_alice);

        print_hex("Alice's Shared Secret", shared_secret_alice.data(), 32);

        // Step 4: Verify both parties have the same shared secret
        std::cout << "\nStep 4: Verification...\n";
        bool keys_match = (shared_secret_alice == shared_secret_bob);
        std::cout << "Shared secrets match: " << (keys_match ? "YES" : "NO") << "\n";

        if (!keys_match)
        {
            std::cerr << "ERROR: Shared secrets don't match!\n";
            return 1;
        }


        std::cout << "\nKey Sizes:\n";
        std::cout << "  • Public Key: " << alice_public_key.size() << " bytes\n";
        std::cout << "  • Secret Key: " << alice_secret_key.size() << " bytes\n";
        std::cout << "  • Ciphertext: " << ciphertext.size() << " bytes\n";
        std::cout << "  • Shared Secret: " << shared_secret_alice.size() << " bytes\n";
    }
    catch (const std::exception &e)
    {
        std::cerr << "\nError: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
