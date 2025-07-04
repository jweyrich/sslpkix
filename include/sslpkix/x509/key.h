#pragma once

#include <iostream>
#include <memory>
#include <functional>
#include <type_traits>
#include <stdexcept>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/opensslv.h>
#include "sslpkix/bio_wrapper.h"
#include "sslpkix/iosink.h"
#include "sslpkix/exception.h"
#include "sslpkix/resource_ownership.h"
#include "sslpkix/x509/key_capabilities.h"

namespace sslpkix {

namespace error {
    namespace key {
        using BadAllocError = BadAllocError;
        using RuntimeError = RuntimeError;
        using InvalidArgumentError = InvalidArgumentError;
        using LogicError = LogicError;
    } // key
} // namespace error

namespace detail {
    // Custom deleter for EVP_PKEY
    struct EVP_PKEY_Deleter {
        void operator()(EVP_PKEY* ptr) const noexcept {
            if (ptr) {
                // std::cout << "Freeing EVP_PKEY " << ptr << std::endl;
                EVP_PKEY_free(ptr);
            }
        }
    };

    using handle_type = EVP_PKEY;
    using handle_ptr = std::unique_ptr<handle_type, EVP_PKEY_Deleter>;

    /**
     * @brief Get the algorithm type object
     * @return int The algorithm type (EVP_PKEY_RSA, EVP_PKEY_EC etc, or EVP_PKEY_NONE if the key is invalid)
     */
    inline int get_algorithm_type(EVP_PKEY* pkey) {
        if (!pkey) return EVP_PKEY_NONE; // Zero!
        return EVP_PKEY_get_base_id(pkey);
    }

    /**
     * @brief Returns true if the key has a public key.
     */
    inline bool has_public_key(const EVP_PKEY* key) noexcept {
        auto ctx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(
            EVP_PKEY_CTX_new_from_pkey(NULL, const_cast<EVP_PKEY*>(key), NULL),
            EVP_PKEY_CTX_free
        );
        return ctx && EVP_PKEY_public_check_quick(ctx.get()) == 1;
    }

    /**
     * @brief Returns true if the informed key has a private key.
     */
    inline bool has_private_key(const EVP_PKEY* key) noexcept {
        auto ctx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(
            EVP_PKEY_CTX_new_from_pkey(NULL, const_cast<EVP_PKEY*>(key), NULL),
            EVP_PKEY_CTX_free
        );
        return ctx && EVP_PKEY_private_check(ctx.get()) == 1;
    }

} // namespace detail

enum class KeyType {
    UNKNOWN = EVP_PKEY_NONE,
    #ifndef OPENSSL_NO_RSA
    RSA = EVP_PKEY_RSA,
    #endif
    #ifndef OPENSSL_NO_DSA
    DSA = EVP_PKEY_DSA,
    #endif
    #ifndef OPENSSL_NO_DH
    DH = EVP_PKEY_DH,
    #endif
    #ifndef OPENSSL_NO_EC
    EC = EVP_PKEY_EC,
    #endif
    // Edwards curve forms (signature)
    ED25519 = EVP_PKEY_ED25519,
    ED448 = EVP_PKEY_ED448,
    // Montgomery curve forms (key exchange)
    X25519 = EVP_PKEY_X25519,
    X448 = EVP_PKEY_X448,
};

namespace factory {
    // Move to a KeyGenerator class?
    EVP_PKEY* generate_key_ex(const char* key_type, const OSSL_PARAM* params = nullptr);
}

namespace traits {
    // Base template for key type traits (specializations will be provided)
    template<typename KeyType>
    struct key_type_traits {
        static_assert(std::is_same_v<KeyType, void>, "Key type not supported");
    };

    // SFINAE helper to check if a key type is supported
    template<typename T, typename = void>
    struct is_key_type_supported : std::false_type {};

    template<typename T>
    struct is_key_type_supported<T, std::void_t<decltype(key_type_traits<T>::evp_pkey_type)>>
        : std::true_type {};

    template<typename T>
    constexpr bool is_key_type_supported_v = is_key_type_supported<T>::value;

    using ossl_param_ptr = std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)>;

    ossl_param_ptr build_key_params(OSSL_PARAM_BLD* builder);

    #ifndef OPENSSL_NO_RSA
    struct RSA {
        static inline EVP_PKEY* generate_key(int bits) {
            const OSSL_PARAM params[] = {
                OSSL_PARAM_int(OSSL_PKEY_PARAM_RSA_BITS, &bits),
                OSSL_PARAM_END
            };

            return factory::generate_key_ex("RSA", params);
        }

        static ossl_param_ptr extract_pubkey_params(EVP_PKEY* pkey, OSSL_PARAM_BLD* params_builder) {
            // RSA parameters (n, e) and public key
            struct RSAParams {
                BIGNUM* n = nullptr;
                BIGNUM* e = nullptr;
                ~RSAParams() {
                    BN_free(n);
                    BN_free(e);
                }
            } rsa_params;

            // Get all RSA parameters including public key (n, e)
            if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &rsa_params.n) ||
                !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &rsa_params.e))
            {
                throw error::key::RuntimeError("Failed on EVP_PKEY_get_bn_param");
            }

            // Push parameters in correct order
            if (!OSSL_PARAM_BLD_push_BN(params_builder, OSSL_PKEY_PARAM_RSA_N, rsa_params.n) ||
                !OSSL_PARAM_BLD_push_BN(params_builder, OSSL_PKEY_PARAM_RSA_E, rsa_params.e))
            {
                throw error::key::RuntimeError("Failed on OSSL_PARAM_BLD_push_*");
            }

            return build_key_params(params_builder);
        }
    };

    // RSA key traits specialization
    template<>
    struct key_type_traits<traits::RSA> {
        static constexpr KeyType key_type = KeyType::RSA;
        static constexpr int evp_pkey_type = EVP_PKEY_RSA;
        static constexpr bool can_select_digest = true;
        // NOTE: RSA keys can be used for both signatures and encryption
        static constexpr key_capabilities capabilities = key_capabilities::Signature | key_capabilities::Encryption;
        static constexpr auto generate_func = traits::RSA::generate_key;
        static constexpr auto extract_pubkey_params_func = traits::RSA::extract_pubkey_params;
    };
    #endif

    #ifndef OPENSSL_NO_DSA
    struct DSA {
        static inline EVP_PKEY* generate_key(int pbits, int qbits) {
            OSSL_PARAM params[] = {
                OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_PBITS, &pbits),
                OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_QBITS, &qbits),
                OSSL_PARAM_END
            };
            return factory::generate_key_ex("DSA", params);
        }

        static ossl_param_ptr extract_pubkey_params(EVP_PKEY* pkey, OSSL_PARAM_BLD* params_builder) {
            // DSA parameters (p, q, g) and public key (y)
            struct DSAParams {
                BIGNUM* p = nullptr;
                BIGNUM* q = nullptr;
                BIGNUM* g = nullptr;
                BIGNUM* pub_key = nullptr;
                ~DSAParams() {
                    BN_free(p);
                    BN_free(q);
                    BN_free(g);
                    BN_free(pub_key);
                }
            } dsa_params;

            // Get all DSA parameters including public key (y)
            if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &dsa_params.p) ||
                !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_Q, &dsa_params.q) ||
                !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_G, &dsa_params.g) ||
                !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, &dsa_params.pub_key))
            {
                throw error::key::RuntimeError("Failed on EVP_PKEY_get_bn_param for DSA parameters");
            }

            // Push parameters in correct order
            if (!OSSL_PARAM_BLD_push_BN(params_builder, OSSL_PKEY_PARAM_FFC_P, dsa_params.p) ||
                !OSSL_PARAM_BLD_push_BN(params_builder, OSSL_PKEY_PARAM_FFC_Q, dsa_params.q) ||
                !OSSL_PARAM_BLD_push_BN(params_builder, OSSL_PKEY_PARAM_FFC_G, dsa_params.g) ||
                !OSSL_PARAM_BLD_push_BN(params_builder, OSSL_PKEY_PARAM_PUB_KEY, dsa_params.pub_key))
            {
                throw error::key::RuntimeError("Failed on OSSL_PARAM_BLD_push_* for DSA parameters");
            }

            return build_key_params(params_builder);
        }
    };

    // DSA key traits specialization
    template<>
    struct key_type_traits<traits::DSA> {
        static constexpr KeyType key_type = KeyType::DSA;
        static constexpr int evp_pkey_type = EVP_PKEY_DSA;
        static constexpr bool can_select_digest = true;
        // NOTE: DSA keys are primarily used for digital signatures
        static constexpr key_capabilities capabilities = key_capabilities::Signature;
        static constexpr auto generate_func = traits::DSA::generate_key;
        static constexpr auto extract_pubkey_params_func = traits::DSA::extract_pubkey_params;
    };
    #endif

    #ifndef OPENSSL_NO_DH
    struct DH {
        enum class KeyGroup {
            // FFDHE groups are defined in RFC 7919
            FFDHE_2048 = NID_ffdhe2048,
            FFDHE_3072 = NID_ffdhe3072,
            FFDHE_4096 = NID_ffdhe4096,
            FFDHE_6144 = NID_ffdhe6144,
            FFDHE_8192 = NID_ffdhe8192,
            // MODP groups are defined in RFC 3526
            MODP_1536 = NID_modp_1536,
            MODP_2048 = NID_modp_2048,
            MODP_3072 = NID_modp_3072,
            MODP_4096 = NID_modp_4096,
            MODP_6144 = NID_modp_6144,
            MODP_8192 = NID_modp_8192,
        };

        static inline EVP_PKEY* generate_key(KeyGroup group) {
            const char* group_name = OBJ_nid2sn(static_cast<int>(group));
            OSSL_PARAM params[] = {
                OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char*>(group_name), 0),
                OSSL_PARAM_END
            };
            return factory::generate_key_ex("DH", params);
        }

        static ossl_param_ptr extract_pubkey_params(EVP_PKEY* pkey, OSSL_PARAM_BLD* params_builder) {
            // DH parameters (p, g) and public key (pub_key)
            struct DHParams {
                BIGNUM* p = nullptr;
                BIGNUM* g = nullptr;
                BIGNUM* pub_key = nullptr;
                ~DHParams() {
                    BN_free(p);
                    BN_free(g);
                    BN_free(pub_key);
                }
            } dh_params;

            // Get all DH parameters including public key
            if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &dh_params.p) ||
                !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_G, &dh_params.g) ||
                !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, &dh_params.pub_key))
            {
                throw error::key::RuntimeError("Failed on EVP_PKEY_get_bn_param for DH parameters");
            }

            // Push parameters in correct order
            if (!OSSL_PARAM_BLD_push_BN(params_builder, OSSL_PKEY_PARAM_FFC_P, dh_params.p) ||
                !OSSL_PARAM_BLD_push_BN(params_builder, OSSL_PKEY_PARAM_FFC_G, dh_params.g) ||
                !OSSL_PARAM_BLD_push_BN(params_builder, OSSL_PKEY_PARAM_PUB_KEY, dh_params.pub_key))
            {
                throw error::key::RuntimeError("Failed on OSSL_PARAM_BLD_push_* for DH parameters");
            }

            return build_key_params(params_builder);
        }
    };

    // DH key traits specialization
    template<>
    struct key_type_traits<traits::DH> {
        static constexpr KeyType key_type = KeyType::DH;
        static constexpr int evp_pkey_type = EVP_PKEY_DH;
        // NOTE: DH keys do not support digest selection
        static constexpr bool can_select_digest = false;
        static constexpr key_capabilities capabilities = key_capabilities::KeyExchange;
        static constexpr auto generate_func = traits::DH::generate_key;
        static constexpr auto extract_pubkey_params_func = traits::DH::extract_pubkey_params;
    };
    #endif

    #ifndef OPENSSL_NO_EC
    struct EC {
        enum class KeyGroup {
            P256 = NID_X9_62_prime256v1,
            P384 = NID_secp384r1,
            P521 = NID_secp521r1,
            BRAINPOOL_P256_R1 = NID_brainpoolP256r1,
            BRAINPOOL_P384_R1 = NID_brainpoolP384r1,
            BRAINPOOL_P512_R1 = NID_brainpoolP512r1,
        };

        static inline EVP_PKEY* generate_key(KeyGroup group) {
            const char* group_name = OBJ_nid2sn(static_cast<int>(group));
            OSSL_PARAM params[] = {
                OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char*>(group_name), 0),
                OSSL_PARAM_END
            };
            return factory::generate_key_ex("EC", params);
        }

        static ossl_param_ptr extract_pubkey_params(EVP_PKEY* pkey, OSSL_PARAM_BLD* params_builder) {
            // Extract curve name
            char curve_name[80];
            size_t curve_len = 0;
            if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, curve_name, sizeof(curve_name), &curve_len) != 1) {
                throw error::key::RuntimeError("Failed on EVP_PKEY_get_utf8_string_param");
            }

            // Get public key
            size_t pubkey_len = 0;
            if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &pubkey_len) != 1) {
                throw error::key::RuntimeError("Failed on EVP_PKEY_get_octet_string_param (size)");
            }

            std::vector<unsigned char> pubkey(pubkey_len);
            if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pubkey.data(), pubkey_len, nullptr) != 1) {
                throw error::key::RuntimeError("Failed on EVP_PKEY_get_octet_string_param (data)");
            }

            if (!OSSL_PARAM_BLD_push_utf8_string(params_builder, OSSL_PKEY_PARAM_GROUP_NAME, curve_name, curve_len) ||
                !OSSL_PARAM_BLD_push_octet_string(params_builder, OSSL_PKEY_PARAM_PUB_KEY, pubkey.data(), pubkey_len))
            {
                throw error::key::RuntimeError("Failed on OSSL_PARAM_BLD_push_*");
            }

            return build_key_params(params_builder);
        }
    };

    // EC key traits specialization
    template<>
    struct key_type_traits<traits::EC> {
        static constexpr KeyType key_type = KeyType::EC;
        static constexpr int evp_pkey_type = EVP_PKEY_EC;
        static constexpr bool can_select_digest = false;
        // NOTE: EC keys can be used for both signatures and key exchange, but the specific
        // capabilities depend on the curve and the context in which they are used.
        // For example, P-256 can be used for ECDH key exchange, while P-384 and P-521 are often used for digital signatures.
        static constexpr key_capabilities capabilities = key_capabilities::KeyExchange | key_capabilities::Signature;
        static constexpr auto generate_func = traits::EC::generate_key;
        static constexpr auto extract_pubkey_params_func = traits::EC::extract_pubkey_params;
    };
    #endif

    struct ED {
        // Edwards curves
        enum class KeyGroup {
            ED25519 = NID_ED25519,
            ED448 = NID_ED448,
        };

        static inline EVP_PKEY* generate_key(KeyGroup type) {
            const char* key_type_name = OBJ_nid2sn(static_cast<int>(type));
            return factory::generate_key_ex(key_type_name);
        }

        static ossl_param_ptr extract_pubkey_params(EVP_PKEY* pkey, OSSL_PARAM_BLD* params_builder) {
            size_t pubkey_len = 0;
            if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &pubkey_len) != 1) {
                throw error::key::RuntimeError("Failed on EVP_PKEY_get_octet_string_param (size)");
            }

            std::vector<unsigned char> pubkey(pubkey_len);
            if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pubkey.data(), pubkey_len, nullptr) != 1) {
                throw error::key::RuntimeError("Failed on EVP_PKEY_get_octet_string_param (data)");
            }

            if (!OSSL_PARAM_BLD_push_octet_string(params_builder, OSSL_PKEY_PARAM_PUB_KEY, pubkey.data(), pubkey_len)) {
                throw error::key::RuntimeError("Failed on OSSL_PARAM_BLD_push_*");
            }

            return build_key_params(params_builder);
        }
    };

    // ED key traits specialization
    template<>
    struct key_type_traits<traits::ED> {
        static constexpr KeyType key_type = KeyType::ED25519;
        static constexpr int evp_pkey_type = EVP_PKEY_ED25519;
        // NOTE: ED keys do not support digest selection
        static constexpr bool can_select_digest = false;
        // NOTE: ED keys are primarily used for digital signatures (except X25519 and X448)
        static constexpr key_capabilities capabilities = key_capabilities::Signature;
        static constexpr auto generate_func = traits::ED::generate_key;
        static constexpr auto extract_pubkey_params_func = traits::ED::extract_pubkey_params;
    };

    struct X25519 {
        static inline EVP_PKEY* generate_key() {
            return factory::generate_key_ex("X25519");
        }

        static ossl_param_ptr extract_pubkey_params(EVP_PKEY* pkey, OSSL_PARAM_BLD* params_builder) {
            return traits::ED::extract_pubkey_params(pkey, params_builder);
        }
    };

    // X25519 key traits specialization
    template<>
    struct key_type_traits<traits::X25519> {
        static constexpr KeyType key_type = KeyType::X25519;
        static constexpr int evp_pkey_type = EVP_PKEY_X25519;
        // NOTE: X25519 keys do not support digest selection
        static constexpr bool can_select_digest = false;
        // NOTE: X25519 keys are primarily used for key exchange
        static constexpr key_capabilities capabilities = key_capabilities::KeyExchange;
        static constexpr auto generate_func = traits::X25519::generate_key;
        static constexpr auto extract_pubkey_params_func = traits::X25519::extract_pubkey_params;
    };

    struct X448 {
        static inline EVP_PKEY* generate_key() {
            return factory::generate_key_ex("X448");
        }

        static ossl_param_ptr extract_pubkey_params(EVP_PKEY* pkey, OSSL_PARAM_BLD* params_builder) {
            return traits::ED::extract_pubkey_params(pkey, params_builder);
        }
    };

    // X448 key traits specialization
    template<>
    struct key_type_traits<traits::X448> {
        static constexpr KeyType key_type = KeyType::X448;
        static constexpr int evp_pkey_type = EVP_PKEY_X448;
        // NOTE: X448 keys do not support digest selection
        static constexpr bool can_select_digest = false;
        // NOTE: X448 keys are primarily used for key exchange
        static constexpr key_capabilities capabilities = key_capabilities::KeyExchange;
        static constexpr auto generate_func = traits::X448::generate_key;
        static constexpr auto extract_pubkey_params_func = traits::X448::extract_pubkey_params;
    };

    // Function to extract public key parameters from a key based on a type
    template<typename KeyType, typename... Args,
        std::enable_if_t<
            std::is_invocable_v<decltype(traits::key_type_traits<KeyType>::extract_pubkey_params_func), Args...>, int> = 0>
    inline traits::ossl_param_ptr extract_pubkey_parameters(Args&&... args) {
        static_assert(traits::is_key_type_supported_v<KeyType>, "Key type not supported");
        return traits::key_type_traits<KeyType>::extract_pubkey_params_func(std::forward<Args>(args)...);
    }

    // Function to extract public key parameters from a key based on a type name
    traits::ossl_param_ptr extract_pubkey_parameters(const char *key_type_name, EVP_PKEY* pkey, OSSL_PARAM_BLD* params_builder);
} // namespace traits

//
// NOTE: With OpenSSL, the private key also contains the public key information
//
class Key {
public:
    inline KeyType algorithm_to_key_type(int algorithm) const noexcept {
        switch (algorithm) {
            case EVP_PKEY_NONE: return KeyType::UNKNOWN;
            #ifndef OPENSSL_NO_RSA
            case EVP_PKEY_RSA: return KeyType::RSA;
            #endif
            #ifndef OPENSSL_NO_DSA
            case EVP_PKEY_DSA: return KeyType::DSA;
            #endif
            #ifndef OPENSSL_NO_DH
            case EVP_PKEY_DH: return KeyType::DH;
            #endif
            #ifndef OPENSSL_NO_EC
            case EVP_PKEY_EC: return KeyType::EC;
            #endif
            case EVP_PKEY_ED25519: return KeyType::ED25519;
            case EVP_PKEY_ED448: return KeyType::ED448;
            case EVP_PKEY_X25519: return KeyType::X25519;
            case EVP_PKEY_X448: return KeyType::X448;
            // Add more cases as needed for other key types
            default: return KeyType::UNKNOWN;
        }
    }

protected:
    detail::handle_ptr _handle{nullptr, detail::EVP_PKEY_Deleter()};

    /**
     * @brief This constructor is a protected, explicit, and inline constructor used for creating an empty key, primarily
     * intended for use by derived classes. If the `create_handle` parameter is true, it initializes a new key by invoking
     * `create_new_key()` and assigns a unique `key_id` using a static counter.
     *
     * @param auto_create_handle If true, a new EVP_PKEY is created and stored in _handle; otherwise, the _handle is left uninitialized.
     *
     * @throws `error::key::BadAllocError` if the key creation fails.
     *
     * @note 1. This constructor is not intended for direct use outside of the class hierarchy.
     * @note 2. The `key_id` is assigned a unique value from a static counter to uniquely identify each key instance.
     * @note 3. This constructor is used to create a new key when the `Key` object is instantiated without any parameters or when a new key is explicitly requested.
     */
    explicit Key(bool auto_create_handle) {
        if (auto_create_handle) {
            create_new_key();
        }
        key_id = static_key_counter++;
        // std::cout << "Creating key (default) " << key_id << std::endl;
    }

    // Helper method to create a new EVP_PKEY
    void create_new_key() {
        auto new_key = EVP_PKEY_new();
        if (!new_key) {
            throw error::key::BadAllocError("Failed to create new key");
        }
        // std::cout << "Created new key " << new_key << std::endl;
        _handle.reset(new_key);
    }

    int key_id = 0;
    static int static_key_counter;

public:
    /**
     * @brief This inline default constructor initializes a new key by delegating to another constructor with a true argument.
     * It simplifies the creation of a key with default behavior.
     */
    Key() : Key(true) {}

    /**
     * @brief This constructor initializes a Key object using an external EVP_PKEY handle without creating a new key.
     * It assigns a unique key ID and sets the external handle.
     *
     * @param external_handle The existing EVP_PKEY handle to wrap.
     * @param ownership The ownership semantics for the handle. If set to `ResourceOwnership::Transfer`, the Key will take ownership of the handle and free it when destroyed.
     *
     * @throws `error::key::RuntimeError` if the reference count increment fails when ownership is not transferred.
     */
    explicit Key(EVP_PKEY* external_handle, const ResourceOwnership ownership) {
        key_id = static_key_counter++;
        // auto provider = EVP_PKEY_get0_provider(external_handle);
        // if (!provider) {
        //     throw error::key::InvalidArgumentError("Cannot assign a legacy key");
        // }
        // std::cout << "Creating key (external) " << key_id << std::endl;
        set_external_handle(external_handle, ownership);
    }

    // Move constructor
    Key(Key&& other) noexcept : _handle(std::move(other._handle)), key_id(other.key_id) {
        other._handle.reset(); // Ensure moved-from key is in a valid state
        // std::cout << "Creating key (move) " << other.key_id << std::endl;
    }

    // Move assignment
    Key& operator=(Key&& other) noexcept {
        // std::cout << "Moving Key " << other.key_id << " to " << key_id << std::endl;
        _handle = std::move(other._handle);
        key_id = std::move(other.key_id);
        other._handle.reset(); // Ensure moved-from key is in a valid state
        return *this;
    }

    // Virtual destructor
    // virtual ~Key() = default;
    virtual ~Key() {
        // std::cout << "Destroying key " << key_id << std::endl;
    }

    // Get raw handle (for C API compatibility)
    inline detail::handle_type* handle() const noexcept {
        return _handle.get();
    }

    inline bool has_handle() const noexcept {
        return _handle.get() != nullptr;
    }

    /**
     * @brief Returns true if the key has a public key.
     */
    bool has_public_key() const noexcept {
        if (!has_handle()) {
            return false;
        }
        return detail::has_public_key(_handle.get());
    }

    /**
     * @brief Returns true if the key has a private key.
     */
    bool has_private_key() const noexcept {
        if (!has_handle()) {
            return false;
        }
        return detail::has_private_key(_handle.get());
    }



    // Get algorithm type
    KeyType algorithm() const {
        int algorithm = detail::get_algorithm_type(_handle.get());
        return algorithm_to_key_type(algorithm);
    }

    /**
     * @brief Returns the bit length of the key, or 0 if the size is not available or the key is not valid.
     */
    int bit_length() const {
        return EVP_PKEY_get_bits(_handle.get());
    }

    /**
     * @brief Returns the type name of the key, or "unknown" if the key is not valid.
     */
    std::string type_name() const noexcept{
        const char* name = EVP_PKEY_get0_type_name(_handle.get());
        if (!name) {
            return "unknown";
        }
        return std::string(name);
    }

    /**
     * @brief Returns the base type of the key (EVP_PKEY_RSA, EVP_PKEY_EC, etc.),
     * or EVP_PKEY_NONE if the key is not valid.
     */
    int base_type() const noexcept {
        return EVP_PKEY_get_base_id(_handle.get());
    }

    /**
     * @brief Returns true if the key can be used to sign data.
     * @note It does not mean that the key is a private key.
     */
    bool can_sign() const noexcept {
        return EVP_PKEY_can_sign(_handle.get()) == 1;
    }

    /**
     * @brief Assign an existing key to this Key object.
     *
     * @param key The existing EVP_PKEY to assign.
     * @param ownership The ownership semantics for the handle. If set to `ResourceOwnership::Transfer`, the Key will take ownership of the handle and free it when destroyed.
     */
    void assign(EVP_PKEY* key, const ResourceOwnership ownership) {
        if (!key) {
            throw error::key::InvalidArgumentError("Cannot assign a null key");
        }
        auto provider = EVP_PKEY_get0_provider(key);
        if (!provider) {
            throw error::key::InvalidArgumentError("Cannot assign a legacy key");
        }

        if (!should_own_resource(ownership)) {
            // If we are not transferring ownership, we need to increment the reference count.
            // This is necessary to ensure that the key is not freed while this Key object is still using it.
            if (!EVP_PKEY_up_ref(key)) {
                throw error::key::RuntimeError("Failed to increment reference count of the key");
            }
        }

        _handle.reset(key);
    }

    /**
     * @brief Copies the contents of an existing key to this Key object.
     *
     * @param key The existing EVP_PKEY to copy.
     *
     * @note This method creates a new EVP_PKEY by duplicating the existing key.
     * It copies both the public and private key information if available.
     */
    void copy(const EVP_PKEY* key) {
        if (!key) {
            throw error::key::InvalidArgumentError("Cannot copy from a null key");
        }

        auto mem = BioWrapper(BIO_new(BIO_s_mem()));
        if (!mem) {
            throw error::key::BadAllocError("Failed to create BIO for key serialization");
        }

        if (detail::has_private_key(key)) {
            // If the key has a private key, write both private and public keys
            if (!PEM_write_bio_PrivateKey(mem.get(), key, nullptr, nullptr, 0, nullptr, nullptr)) {
                throw error::key::RuntimeError("Failed to write private key to BIO");
            }
            EVP_PKEY* copy = PEM_read_bio_PrivateKey_ex(mem.get(), nullptr, nullptr, nullptr, nullptr, nullptr);
            _handle.reset(copy);
        } else {
            // Always write the public key, even if the private key is not present
            if (!PEM_write_bio_PUBKEY(mem.get(), key)) {
                throw error::key::RuntimeError("Failed to write public key to BIO");
            }
            EVP_PKEY* copy = PEM_read_bio_PUBKEY_ex(mem.get(), nullptr, nullptr, nullptr, nullptr, nullptr);
            _handle.reset(copy);
        }
    }

    virtual int print_ex(BIO* bio) const noexcept {
        return EVP_PKEY_print_public(bio, _handle.get(), 0, NULL);
    }

    virtual int print(FILE* stream = stdout) const noexcept {
        auto bio_out = BioWrapper(BIO_new_fp(stream, BIO_NOCLOSE));
        int ret = print_ex(bio_out.get());
        return ret;
    }

    // Virtual methods for derived classes
    virtual void load(IoSink& sink [[maybe_unused]], const char* password [[maybe_unused]]) {
        // TODO(jweyrich): implement this using PEM_read_bio_PUBKEY
    }

    virtual void save(IoSink& sink [[maybe_unused]]) const {
        // TODO(jweyrich): implement this using PEM_write_bio_PUBKEY
    }

    // Comparison operators

    /**
     * @brief Compares two keys for equality.
     * @note This method compares the keys based solely on their public key information.
     * If keys are not valid, it will compare the handles directly.
     * It does not compare the private key information.
     * If you want to compare the private keys, you should use the has_private_key() method
     * to check if both keys have a private key, and then compare the public key information.
     * @return true if the keys are equal, false otherwise.
     */
    friend bool operator==(const Key& lhs, const Key& rhs) {
        if (!lhs._handle || !rhs._handle) {
            return lhs._handle == rhs._handle;
        }

        int result = EVP_PKEY_eq(lhs._handle.get(), rhs._handle.get());
        // See https://docs.openssl.org/3.1/man3/EVP_PKEY_eq//#return-values
        switch (result) {
            case 1: return true; // Keys are equal
            case 0: return false; // Keys are different
            case -1: throw error::key::RuntimeError("Failed to compare keys");
            case -2: throw error::key::RuntimeError("Operation is not supported");
            default: throw error::key::RuntimeError("Unexpected result from EVP_PKEY_eq");
        }
    }

    friend bool operator!=(const Key& lhs, const Key& rhs) {
        return !(lhs == rhs);
    }

    /**
     * @brief Returns the public key (only) from a private key.
     *
     * @return A unique_ptr to a Key object containing only the public key.
     *
     * @note This is a convenience method that extracts the public key from the private key.
     */
    std::unique_ptr<Key> pubkey() const;

protected:
    /**
     * @brief Sets an external EVP_PKEY handle for the key.
     * This method allows the Key object to wrap an existing EVP_PKEY handle.
     *
     * @param handle The external EVP_PKEY handle to set.
     * @param ownership The ownership semantics for the handle. If set to `ResourceOwnership::Transfer`, the Key will take ownership of the handle and free it when destroyed.
     *
     * @throws `error::key::RuntimeError` if the reference count increment fails.
     */
    void set_external_handle(EVP_PKEY* handle, const ResourceOwnership ownership) {
        if (!handle) {
            _handle.reset();
            return;
        }

        if (!should_own_resource(ownership)) {
            // If we are not transferring ownership, we need to increment the reference count.
            if (!EVP_PKEY_up_ref(handle)) {
                throw error::key::RuntimeError("Failed to increment reference count of the external key");
            }
        }
        _handle.reset(handle);
    }

    friend class Certificate;
    friend class CertificateRequest;
};

class PrivateKey : public Key {
public:
    // Default constructor - creates a new private key
    PrivateKey() : Key(true) {}

    // Constructor for external handle (does not create new key)
    explicit PrivateKey(EVP_PKEY* external_handle, const ResourceOwnership ownership) : Key(external_handle, ownership) {}

    // Move constructor
    PrivateKey(PrivateKey&& other) noexcept : Key(std::move(other)) {}

    // Move assignment
    PrivateKey& operator=(PrivateKey&& other) noexcept {
        // std::cout << "Moving PrivateKey " << other.key_id << " to " << key_id << std::endl;
        _handle = std::move(other._handle);
        key_id = std::move(other.key_id);
        other._handle.reset(); // Ensure moved-from key is in a valid state
        return *this;
    }

    // Constructor that loads from IoSink
    explicit PrivateKey(IoSink& sink, const char* password = nullptr) : Key(false) {
        load(sink, password);
    }

    virtual ~PrivateKey() {
        // std::cout << "Destroying PrivateKey " << key_id << std::endl;
    }

    virtual int print_ex(BIO* bio) const noexcept override {
        return EVP_PKEY_print_private(bio, _handle.get(), 0, NULL);
    }

    // Load private key from IoSink
    void load(IoSink& sink, const char* password = nullptr) override {
        auto new_key = PEM_read_bio_PrivateKey(sink.handle(), nullptr, nullptr,
            const_cast<void*>(static_cast<const void*>(password)));
        if (!new_key) {
            throw error::key::RuntimeError("Failed to load private key from " + sink.source());
        }
        // std::cout << "Loaded private key " << new_key << std::endl;
        _handle.reset(new_key);
    }

    // Save private key to IoSink
    void save(IoSink& sink) const override {
        if (!_handle) {
            throw error::key::LogicError("Invalid private key handle");
        }

        int ret = PEM_write_bio_PrivateKey(sink.handle(), _handle.get(),
                                         nullptr, nullptr, 0, 0, nullptr);
        if (ret == 0) {
            throw error::key::RuntimeError("Failed to save private key to " + sink.source());
        }
    }

    // Factory method to create a private key from file
    static std::unique_ptr<PrivateKey> from_file([[maybe_unused]]const std::string& filename,
                                                const char* password = nullptr) {
        try {
            IoSink sink; // Assuming IoSink can be constructed from filename
            return std::make_unique<PrivateKey>(sink, password);
        } catch (const std::exception& e) {
            return nullptr;
        }
    }

    // Factory method to create a private key from memory
    static std::unique_ptr<PrivateKey> from_memory([[maybe_unused]] const std::string& pem_data,
                                                 const char* password = nullptr) {
        try {
            IoSink sink; // Assuming IoSink can be constructed from memory
            return std::make_unique<PrivateKey>(sink, password);
        } catch (const std::exception& e) {
            return nullptr;
        }
    }
};

// Factory functions for creating keys
namespace factory {
    inline std::unique_ptr<Key> make_key() {
        try {
            return std::make_unique<Key>();
        } catch (const std::exception& e) {
            return nullptr;
        }
    }

    inline std::unique_ptr<PrivateKey> make_private_key() {
        try {
            return std::make_unique<PrivateKey>();
        } catch (const std::exception& e) {
            return nullptr;
        }
    }

    // Factory function to generate a key based on type
    template<typename KeyType, typename... Args,
        std::enable_if_t<
            std::is_invocable_v<decltype(traits::key_type_traits<KeyType>::generate_func), Args...>, int> = 0>
    inline EVP_PKEY* generate_key(Args&&... args) {
        static_assert(traits::is_key_type_supported_v<KeyType>, "Key type not supported");
        return traits::key_type_traits<KeyType>::generate_func(std::forward<Args>(args)...);
    }

    inline EVP_PKEY* generate_key_rsa(int bits = 1024) {
        using key_type = traits::RSA;
        return traits::key_type_traits<key_type>::generate_func(bits);
    }

    inline EVP_PKEY* generate_key_dsa(int pbits = 2048, int qbits = 256) {
        using key_type = traits::DSA;
        return traits::key_type_traits<key_type>::generate_func(pbits, qbits);
    }

    inline EVP_PKEY* generate_key_dh(traits::DH::KeyGroup group = traits::DH::KeyGroup::MODP_2048) {
        using key_type = traits::DH;
        return traits::key_type_traits<key_type>::generate_func(group);
    }

    inline EVP_PKEY* generate_key_ec(traits::EC::KeyGroup group = traits::EC::KeyGroup::P256) {
        using key_type = traits::EC;
        return traits::key_type_traits<key_type>::generate_func(group);
    }

    inline EVP_PKEY* generate_key_ed(traits::ED::KeyGroup group = traits::ED::KeyGroup::ED25519) {
        using key_type = traits::ED;
        return traits::key_type_traits<key_type>::generate_func(group);
    }
}

} // namespace sslpkix