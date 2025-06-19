#pragma once

#include <iostream>
#include <memory>
#include <functional>
#include <type_traits>
#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "sslpkix/iosink.h"

namespace sslpkix {

namespace detail {
    // Custom deleter for EVP_PKEY
    struct EVP_PKEY_Deleter {
        void operator()(EVP_PKEY* ptr) const noexcept {
            if (ptr) {
                EVP_PKEY_free(ptr);
            }
        }
    };

    using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>;

    // Helper function to increment reference count and return shared ownership
    inline std::shared_ptr<EVP_PKEY> make_shared_evp_pkey(EVP_PKEY* pkey) {
        if (!pkey) return nullptr;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        CRYPTO_add(&pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);
#else
        if (EVP_PKEY_up_ref(pkey) != 1) {
            return nullptr;
        }
#endif
        return std::shared_ptr<EVP_PKEY>(pkey, EVP_PKEY_Deleter{});
    }

    // Algorithm Type Detection
    inline int get_algorithm_type(EVP_PKEY* pkey) {
        if (!pkey) return 0;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        return EVP_PKEY_type(pkey->type);
#else
        return EVP_PKEY_base_id(pkey);
#endif
    }

    // Base template for cipher traits (specializations will be provided)
    template<typename CipherType>
    struct cipher_traits {
        static_assert(std::is_same_v<CipherType, void>, "Cipher type not supported");
    };

    // SFINAE helper to check if a cipher type is supported
    template<typename T, typename = void>
    struct is_cipher_supported : std::false_type {};

    template<typename T>
    struct is_cipher_supported<T, std::void_t<decltype(cipher_traits<T>::evp_pkey_type)>>
        : std::true_type {};

    template<typename T>
    constexpr bool is_cipher_supported_v = is_cipher_supported<T>::value;

    // Template-based cipher operations
    template<typename CipherType>
    class CipherOperations {
        static_assert(is_cipher_supported_v<CipherType>, "Cipher type not supported");

    public:
        static bool assign(EVP_PKEY* pkey, CipherType* key) {
            if (!pkey || !key) return false;
            int evp_pkey_type = cipher_traits<CipherType>::evp_pkey_type;
            return cipher_traits<CipherType>::assign_func(pkey, evp_pkey_type, key) != 0;
        }

        static bool copy(EVP_PKEY* pkey, CipherType* key) {
            if (!pkey || !key) return false;
            return cipher_traits<CipherType>::copy_func(pkey, key) != 0;
        }

        static constexpr int evp_type() {
            return cipher_traits<CipherType>::evp_pkey_type;
        }
    };

    // RSA cipher traits specialization
    #ifndef OPENSSL_NO_RSA
    template<>
    struct cipher_traits<RSA> {
        static constexpr int evp_pkey_type = EVP_PKEY_RSA;
        static constexpr auto assign_func = EVP_PKEY_assign;
        static constexpr auto copy_func = EVP_PKEY_set1_RSA;
        using native_type = RSA;
    };
    #endif

    // DSA cipher traits specialization
    #ifndef OPENSSL_NO_DSA
    template<>
    struct cipher_traits<DSA> {
        static constexpr int evp_pkey_type = EVP_PKEY_DSA;
        static constexpr auto assign_func = EVP_PKEY_assign;
        static constexpr auto copy_func = EVP_PKEY_set1_DSA;
        using native_type = DSA;
    };
    #endif

    // DH cipher traits specialization
    #ifndef OPENSSL_NO_DH
    template<>
    struct cipher_traits<DH> {
        static constexpr int evp_pkey_type = EVP_PKEY_DH;
        static constexpr auto assign_func = EVP_PKEY_assign;
        static constexpr auto copy_func = EVP_PKEY_set1_DH;
        using native_type = DH;
    };
    #endif

    // EC cipher traits specialization
    #ifndef OPENSSL_NO_EC
    template<>
    struct cipher_traits<EC_KEY> {
        static constexpr int evp_pkey_type = EVP_PKEY_EC;
        static constexpr auto assign_func = EVP_PKEY_assign;
        static constexpr auto copy_func = EVP_PKEY_set1_EC_KEY;
        using native_type = EC_KEY;
    };
    #endif

} // namespace detail

//
// NOTE: With OpenSSL, the private key also contains the public key information
//
class Key {
public:
    using handle_type = EVP_PKEY;

    struct Cipher {
        enum class Type {
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
            UNKNOWN = 0
        };
    };

protected:
    std::shared_ptr<EVP_PKEY> _handle{nullptr, detail::EVP_PKEY_Deleter{}};

public:
    // Default constructor
    Key() = default;

    // Copy constructor
    Key(const Key& other) : _handle(other._handle) {
        if (!_handle && other._handle) {
            throw std::bad_alloc();
        }
    }

    // Move constructor
    Key(Key&& other) noexcept = default;

    // Copy assignment
    Key& operator=(const Key& other) {
        if (this != &other) {
            _handle = other._handle;
        }
        return *this;
    }

    // Move assignment
    Key& operator=(Key&& other) noexcept = default;

    // Virtual destructor
    virtual ~Key() = default;

    // Get raw handle (for C API compatibility)
    handle_type* handle() const noexcept {
        return _handle.get();
    }

    // Check if key is valid
    bool is_valid() const noexcept {
        return _handle != nullptr;
    }

    // Create new key
    bool create() {
        auto new_key = detail::EVP_PKEY_ptr(EVP_PKEY_new());
        if (!new_key) {
            std::cerr << "Failed to create key" << std::endl;
            return false;
        }

        _handle = std::shared_ptr<EVP_PKEY>(new_key.release(), detail::EVP_PKEY_Deleter{});
        return true;
    }

    // Get algorithm type
    Cipher::Type algorithm() const {
        int algorithm = detail::get_algorithm_type(_handle.get());
        return static_cast<Cipher::Type>(algorithm);
    }

    // Get bit length
    int bit_length() const {
        return EVP_PKEY_bits(_handle.get());
    }

    // Template-based cipher operations
    template<typename CipherType>
    bool assign(CipherType* key) {
        static_assert(detail::is_cipher_supported_v<CipherType>,
                     "Cipher type not supported");
        return detail::CipherOperations<CipherType>::assign(_handle.get(), key);
    }

    template<typename CipherType>
    bool copy(CipherType* key) {
        static_assert(detail::is_cipher_supported_v<CipherType>,
                     "Cipher type not supported");
        return detail::CipherOperations<CipherType>::copy(_handle.get(), key);
    }

    // Type-safe cipher checking
    template<typename CipherType>
    bool is_cipher_type() const {
        static_assert(detail::is_cipher_supported_v<CipherType>,
                     "Cipher type not supported");
        return detail::get_algorithm_type(_handle.get()) ==
               detail::cipher_traits<CipherType>::evp_pkey_type;
    }

    // Get cipher-specific handle with type safety
    template<typename CipherType>
    CipherType* get_cipher_handle() const {
        static_assert(detail::is_cipher_supported_v<CipherType>,
                     "Cipher type not supported");

        if (!is_cipher_type<CipherType>()) {
            return nullptr;
        }

        // Use appropriate EVP_PKEY_get* function based on cipher type
        if constexpr (std::is_same_v<CipherType, RSA>) {
            #ifndef OPENSSL_NO_RSA
            return EVP_PKEY_get1_RSA(_handle.get());
            #endif
        } else if constexpr (std::is_same_v<CipherType, DSA>) {
            #ifndef OPENSSL_NO_DSA
            return EVP_PKEY_get1_DSA(_handle.get());
            #endif
        } else if constexpr (std::is_same_v<CipherType, DH>) {
            #ifndef OPENSSL_NO_DH
            return EVP_PKEY_get1_DH(_handle.get());
            #endif
        } else if constexpr (std::is_same_v<CipherType, EC_KEY>) {
            #ifndef OPENSSL_NO_EC
            return EVP_PKEY_get1_EC_KEY(_handle.get());
            #endif
        }
        return nullptr;
    }

    // Virtual methods for derived classes
    virtual bool load(IoSink& sink [[maybe_unused]], const char* password [[maybe_unused]]) {
        return false;
    }

    virtual bool save(IoSink& sink [[maybe_unused]]) const {
        return false;
    }

    // Comparison operators
    friend bool operator==(const Key& lhs, const Key& rhs) {
        if (!lhs._handle || !rhs._handle) {
            return lhs._handle == rhs._handle;
        }
        // TODO(jweyrich): do we need EVP_PKEY_cmp_parameters() too?
        return EVP_PKEY_cmp(lhs._handle.get(), rhs._handle.get()) == 1;
    }

    friend bool operator!=(const Key& lhs, const Key& rhs) {
        return !(lhs == rhs);
    }

    // Set external handle (for cases where we don't own the EVP_PKEY)
    void set_external_handle(EVP_PKEY* handle) {
        if (handle) {
            _handle = detail::make_shared_evp_pkey(handle);
        } else {
            _handle.reset();
        }
    }

protected:
    // Get shared handle for friends
    std::shared_ptr<EVP_PKEY> get_shared_handle() const {
        return _handle;
    }

    friend class Certificate;
    friend class CertificateRequest;
};

class PrivateKey : public Key {
public:
    PrivateKey() = default;
    virtual ~PrivateKey() = default;

    // Load private key from IoSink
    bool load(IoSink& sink, const char* password = nullptr) override {
        auto new_key = detail::EVP_PKEY_ptr(
            PEM_read_bio_PrivateKey(sink.handle(), nullptr, nullptr,
                                  const_cast<void*>(static_cast<const void*>(password)))
        );

        if (!new_key) {
            std::cerr << "Failed to load private key: " << sink.source() << std::endl;
            return false;
        }

        _handle = std::shared_ptr<EVP_PKEY>(new_key.release(), detail::EVP_PKEY_Deleter{});
        return true;
    }

    // Save private key to IoSink
    bool save(IoSink& sink) const override {
        if (!_handle) {
            return false;
        }

        int ret = PEM_write_bio_PrivateKey(sink.handle(), _handle.get(),
                                         nullptr, nullptr, 0, 0, nullptr);
        if (ret == 0) {
            std::cerr << "Failed to save private key: " << sink.source() << std::endl;
        }
        return ret != 0;
    }

    // Template-based factory methods
    template<typename CipherType>
    static std::unique_ptr<PrivateKey> create_from_cipher(CipherType* cipher_key) {
        static_assert(detail::is_cipher_supported_v<CipherType>,
                     "Cipher type not supported");

        auto key = std::make_unique<PrivateKey>();
        if (key->create() && key->assign(cipher_key)) {
            return key;
        }
        return nullptr;
    }

    // Factory method to create a private key from file
    static std::unique_ptr<PrivateKey> from_file([[maybe_unused]]const std::string& filename,
                                                const char* password = nullptr) {
        auto key = std::make_unique<PrivateKey>();
        IoSink sink; // Assuming IoSink can be constructed from filename
        if (key->load(sink, password)) {
            return key;
        }
        return nullptr;
    }

    // Factory method to create a private key from memory
    static std::unique_ptr<PrivateKey> from_memory([[maybe_unused]] const std::string& pem_data,
                                                 const char* password = nullptr) {
        auto key = std::make_unique<PrivateKey>();
        IoSink sink; // Assuming IoSink can be constructed from memory
        if (key->load(sink, password)) {
            return key;
        }
        return nullptr;
    }
};

// Factory functions for creating keys
namespace factory {
    inline std::unique_ptr<Key> make_key() {
        auto key = std::make_unique<Key>();
        if (key->create()) {
            return key;
        }
        return nullptr;
    }

    inline std::unique_ptr<PrivateKey> make_private_key() {
        return std::make_unique<PrivateKey>();
    }

    // Template-based key creation
    template<typename CipherType>
    std::unique_ptr<Key> make_key_for_cipher() {
        static_assert(detail::is_cipher_supported_v<CipherType>,
                     "Cipher type not supported");
        return make_key();
    }
}

} // namespace sslpkix