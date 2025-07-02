#include "sslpkix/x509/key.h"
#include <openssl/param_build.h>

namespace sslpkix {

using param_builder_ptr = std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)>;
using ossl_param_ptr = std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)>;
using evp_pkey_ctx_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

int Key::static_key_counter = 0;

ossl_param_ptr traits::build_key_params(OSSL_PARAM_BLD* builder) {
    auto params = OSSL_PARAM_BLD_to_param(builder);
    if (!params) {
        throw error::key::RuntimeError("Failed on OSSL_PARAM_BLD_to_param");
    }
    return ossl_param_ptr(params, OSSL_PARAM_free);
}

traits::ossl_param_ptr traits::extract_pubkey_parameters(const char *key_type_name, EVP_PKEY* pkey, OSSL_PARAM_BLD* params_builder) {
    if (!key_type_name || !pkey || !params_builder) {
        throw error::key::InvalidArgumentError("Invalid arguments for extracting public key parameters");
    }

    auto name_func_pairs = {
        std::make_pair("RSA", &traits::RSA::extract_pubkey_params),
        std::make_pair("DSA", &traits::DSA::extract_pubkey_params),
        std::make_pair("DH", &traits::DH::extract_pubkey_params),
        std::make_pair("EC", &traits::EC::extract_pubkey_params),
        std::make_pair("ED25519", &traits::ED::extract_pubkey_params),
        std::make_pair("ED448", &traits::ED::extract_pubkey_params),
        std::make_pair("X25519", &traits::X25519::extract_pubkey_params),
        std::make_pair("X448", &traits::X25519::extract_pubkey_params)
    };

    traits::ossl_param_ptr params(nullptr, OSSL_PARAM_free);
    for (const auto& pair : name_func_pairs) {
        if (strcmp(key_type_name, pair.first) == 0) {
            params = pair.second(pkey, params_builder);
            break;
        }
    }

    return params; // It may return nullptr if no matching type was found
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
    param_builder_ptr params_builder(OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free);
    if (!params_builder) {
        throw error::key::RuntimeError("Failed on OSSL_PARAM_BLD_new");
    }

    auto params = traits::extract_pubkey_parameters(key_type_name, _handle.get(), params_builder.get());
    if (!params) {
        throw error::key::RuntimeError("Failed to extract public key parameters for key type: " + std::string(key_type_name));
    }

    evp_pkey_ctx_ptr ctx(EVP_PKEY_CTX_new_from_name(nullptr, key_type_name, nullptr), EVP_PKEY_CTX_free);
    if (!ctx) {
        throw error::key::RuntimeError("Failed on EVP_PKEY_CTX_new_from_name");
    }

    if (EVP_PKEY_fromdata_init(ctx.get()) != 1) {
        throw error::key::RuntimeError("Failed on EVP_PKEY_fromdata_init");
    }

    EVP_PKEY* new_pub_key = nullptr;

    if (EVP_PKEY_fromdata(ctx.get(), &new_pub_key, EVP_PKEY_PUBLIC_KEY, params.get()) != 1) {
        throw error::key::RuntimeError("Failed on EVP_PKEY_fromdata");
    }

    return std::make_unique<Key>(new_pub_key, ResourceOwnership::Transfer);
}

namespace factory {
    // Move to a KeyGenerator class?
    EVP_PKEY* generate_key_ex(const char* key_type_name, const OSSL_PARAM* params) {
        if (!key_type_name) {
            return nullptr;
        }

        EVP_PKEY* pkey = nullptr;

        // Create a context for key generation based on algorithm name
        evp_pkey_ctx_ptr ctx(EVP_PKEY_CTX_new_from_name(nullptr, key_type_name, nullptr), EVP_PKEY_CTX_free);
        if (!ctx) {
            throw error::key::RuntimeError("Failed on EVP_PKEY_CTX_new_from_name");
        }

        if (EVP_PKEY_keygen_init(ctx.get()) != 1) {
            throw error::key::RuntimeError("Failed on EVP_PKEY_keygen_init");
        }

        // Optionally set parameters
        // Note: EVP_PKEY_CTX_set_params only works after EVP_PKEY_keygen_init is called
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