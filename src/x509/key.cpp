#include "sslpkix/x509/key.h"
#include <openssl/param_build.h>

namespace sslpkix {

int Key::static_key_counter = 0;

std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)> build_params(OSSL_PARAM_BLD* builder) {
    auto params = OSSL_PARAM_BLD_to_param(builder);
    if (!params) {
        throw error::key::RuntimeError("Failed on OSSL_PARAM_BLD_to_param");
    }
    return std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)>(params, OSSL_PARAM_free);
}

// TODO(jweyrich): Move to a KeyExtractor class that supports specialized extraction of public keys
std::unique_ptr<Key> Key::pubkey() const {
    if (!_handle) {
        return nullptr;
    }

    const char* key_type_name = EVP_PKEY_get0_type_name(_handle.get());
    if (!key_type_name) {
        throw error::key::RuntimeError("Failed on EVP_PKEY_get0_type_name");
    }

    // Build provider-native BN parameters directly:
    auto params_builder_ptr = OSSL_PARAM_BLD_new();
    if (!params_builder_ptr) {
        throw error::key::RuntimeError("Failed on OSSL_PARAM_BLD_new");
    }
    auto params_builder = std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)>(params_builder_ptr, OSSL_PARAM_BLD_free);

    auto params = std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)>(nullptr, OSSL_PARAM_free);

    if (strcmp(key_type_name, "RSA") == 0) {
        BIGNUM* n = nullptr;
        BIGNUM* e = nullptr;
        if (!EVP_PKEY_get_bn_param(_handle.get(), OSSL_PKEY_PARAM_RSA_N, &n) ||
            !EVP_PKEY_get_bn_param(_handle.get(), OSSL_PKEY_PARAM_RSA_E, &e))
        {
            throw error::key::RuntimeError("Failed on EVP_PKEY_get_bn_param");
        }

        if (!OSSL_PARAM_BLD_push_BN(params_builder_ptr, OSSL_PKEY_PARAM_RSA_N, n) ||
            !OSSL_PARAM_BLD_push_BN(params_builder_ptr, OSSL_PKEY_PARAM_RSA_E, e))
        {
            throw error::key::RuntimeError("Failed on OSSL_PARAM_BLD_push_*");
        }

        params = build_params(params_builder_ptr);

        BN_free(n);
        BN_free(e);
    } else if (strcmp(key_type_name, "EC") == 0) {
        // Extract curve name
        char curve_name[80];
        size_t curve_len = 0;
        if (EVP_PKEY_get_utf8_string_param(_handle.get(), OSSL_PKEY_PARAM_GROUP_NAME, curve_name, sizeof(curve_name), &curve_len) != 1) {
            throw error::key::RuntimeError("Failed on EVP_PKEY_get_utf8_string_param");
        }

        // Get public key
        size_t pubkey_len = 0;
        if (EVP_PKEY_get_octet_string_param(_handle.get(), OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &pubkey_len) != 1) {
            throw error::key::RuntimeError("Failed on EVP_PKEY_get_octet_string_param (size)");
        }

        std::vector<unsigned char> pubkey(pubkey_len);
        if (EVP_PKEY_get_octet_string_param(_handle.get(), OSSL_PKEY_PARAM_PUB_KEY, pubkey.data(), pubkey_len, nullptr) != 1) {
            throw error::key::RuntimeError("Failed on EVP_PKEY_get_octet_string_param (data)");
        }

        if (!OSSL_PARAM_BLD_push_utf8_string(params_builder_ptr, OSSL_PKEY_PARAM_GROUP_NAME, curve_name, curve_len) ||
            !OSSL_PARAM_BLD_push_octet_string(params_builder_ptr, OSSL_PKEY_PARAM_PUB_KEY, pubkey.data(), pubkey_len))
        {
            throw error::key::RuntimeError("Failed on OSSL_PARAM_BLD_push_*");
        }

        params = build_params(params_builder_ptr);
    } else if (strcmp(key_type_name, "ED25519") == 0 || strcmp(key_type_name, "ED448") == 0) {
        size_t pubkey_len = 0;
        if (EVP_PKEY_get_octet_string_param(_handle.get(), OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &pubkey_len) != 1) {
            throw error::key::RuntimeError("Failed on EVP_PKEY_get_octet_string_param (size)");
        }

        std::vector<unsigned char> pubkey(pubkey_len);
        if (EVP_PKEY_get_octet_string_param(_handle.get(), OSSL_PKEY_PARAM_PUB_KEY, pubkey.data(), pubkey_len, nullptr) != 1) {
            throw error::key::RuntimeError("Failed on EVP_PKEY_get_octet_string_param (data)");
        }

        if (!OSSL_PARAM_BLD_push_octet_string(params_builder_ptr, OSSL_PKEY_PARAM_PUB_KEY, pubkey.data(), pubkey_len)) {
            throw error::key::RuntimeError("Failed on OSSL_PARAM_BLD_push_*");
        }

        params = build_params(params_builder_ptr);
    } else {
        // Unsupported or custom key type
        return nullptr;
    }

    auto ctx_ptr = EVP_PKEY_CTX_new_from_name(nullptr, key_type_name, nullptr);
    if (!ctx_ptr) {
        throw error::key::RuntimeError("Failed on EVP_PKEY_CTX_new_from_name");
        return nullptr;
    }
    auto ctx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(ctx_ptr, EVP_PKEY_CTX_free);

    if (EVP_PKEY_fromdata_init(ctx_ptr) <= 0) {
        throw error::key::RuntimeError("Failed on EVP_PKEY_fromdata_init");
    }

    EVP_PKEY* new_pub_key = nullptr;

    if (EVP_PKEY_fromdata(ctx_ptr, &new_pub_key, EVP_PKEY_PUBLIC_KEY, params.get()) <= 0) {
        throw error::key::RuntimeError("Failed on EVP_PKEY_fromdata");
    }

    return std::make_unique<Key>(new_pub_key);
}

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
            throw error::key::RuntimeError("Failed on EVP_PKEY_CTX_new_from_name");
        }

        if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
            throw error::key::RuntimeError("Failed on EVP_PKEY_keygen_init");
        }

        // Optionally set parameters
        if (params && EVP_PKEY_CTX_set_params(ctx.get(), params) != 1) {
            throw error::key::RuntimeError("Failed on EVP_PKEY_CTX_set_params");
        }

        // Generate the key
        if (EVP_PKEY_generate(ctx.get(), &pkey) != 1) {
            throw error::key::RuntimeError("Failed on EVP_PKEY_generate");
        }

        return pkey;
    }
}

} // namespace sslpkix