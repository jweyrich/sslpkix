#include "sslpkix/x509/key.h"

namespace sslpkix {

int Key::static_key_counter = 0;

namespace factory {
    // Move to a KeyGenerator class?
    EVP_PKEY* generate_key_ex(const char* key_type, const OSSL_PARAM* params) {
        if (!key_type) {
            return nullptr;
        }

        EVP_PKEY* pkey = nullptr;

        // Create a context for key generation based on algorithm name
        auto ctx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(EVP_PKEY_CTX_new_from_name(nullptr, key_type, nullptr), EVP_PKEY_CTX_free);
        if (!ctx) {
            throw std::runtime_error("Failed on EVP_PKEY_CTX_new_from_name. Reason: " + get_error_string());
        }

        if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
            throw std::runtime_error("Failed on EVP_PKEY_keygen_init. Reason: " + get_error_string());
        }

        // Optionally set parameters
        if (params && EVP_PKEY_CTX_set_params(ctx.get(), params) != 1) {
            throw std::runtime_error("Failed on EVP_PKEY_CTX_set_params. Reason: " + get_error_string());
        }

        // Generate the key
        if (EVP_PKEY_generate(ctx.get(), &pkey) != 1) {
            throw std::runtime_error("Failed on EVP_PKEY_generate. Reason: " + get_error_string());
        }

        return pkey;
    }
}

} // namespace sslpkix