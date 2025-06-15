#pragma once

#include <iostream>
#include <memory>
#include <functional>
#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "sslpkix/iosink.h"
#include "sslpkix/common.h"

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
}

//
// NOTE: With OpenSSL, the private key also contains the public key information
//
class Key {
public:
    using handle_type = EVP_PKEY;

    struct Cipher {
        enum class Type {
            #ifndef OPENSSL_NO_RSA
            RSA = 1,
            #endif
            #ifndef OPENSSL_NO_DSA
            DSA = 2,
            #endif
            #ifndef OPENSSL_NO_DH
            DH = 3, // Diffie Hellman
            #endif
            #ifndef OPENSSL_NO_EC
            EC = 4,
            #endif
            UNKNOWN = 0
        };
    };

protected:
    std::shared_ptr<EVP_PKEY> _handle;
    bool _is_external_handle = false;

public:
    // Default constructor
    Key() = default;

    // Copy constructor
    Key(const Key& other)
        : _handle(other._handle)
        , _is_external_handle(other._is_external_handle) {
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
            _is_external_handle = other._is_external_handle;
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
        _is_external_handle = false;
        return true;
    }

    // Get algorithm type
    Cipher::Type algorithm() const {
        if (!_handle) return Cipher::Type::UNKNOWN;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        int algorithm = EVP_PKEY_type(_handle->type);
#else
        int algorithm = EVP_PKEY_base_id(_handle.get());
#endif

        switch (algorithm) {
            #ifndef OPENSSL_NO_RSA
            case EVP_PKEY_RSA: return Cipher::Type::RSA;
            #endif
            #ifndef OPENSSL_NO_DSA
            case EVP_PKEY_DSA: return Cipher::Type::DSA;
            #endif
            #ifndef OPENSSL_NO_DH
            case EVP_PKEY_DH: return Cipher::Type::DH;
            #endif
            #ifndef OPENSSL_NO_EC
            case EVP_PKEY_EC: return Cipher::Type::EC;
            #endif
            default: return Cipher::Type::UNKNOWN;
        }
    }

    #ifndef OPENSSL_NO_RSA
    bool assign(RSA* key) {
        if (!_handle || !key) return false;
        return EVP_PKEY_assign_RSA(_handle.get(), key) != 0;
    }

    bool copy(RSA* key) {
        if (!_handle || !key) return false;
        return EVP_PKEY_set1_RSA(_handle.get(), key) != 0;
    }
    #endif

    #ifndef OPENSSL_NO_DSA
    bool assign(DSA* key) {
        if (!_handle || !key) return false;
        return EVP_PKEY_assign_DSA(_handle.get(), key) != 0;
    }

    bool copy(DSA* key) {
        if (!_handle || !key) return false;
        return EVP_PKEY_set1_DSA(_handle.get(), key) != 0;
    }
    #endif

    #ifndef OPENSSL_NO_DH
    bool assign(DH* key) {
        if (!_handle || !key) return false;
        return EVP_PKEY_assign_DH(_handle.get(), key) != 0;
    }

    bool copy(DH* key) {
        if (!_handle || !key) return false;
        return EVP_PKEY_set1_DH(_handle.get(), key) != 0;
    }
    #endif

    #ifndef OPENSSL_NO_EC
    bool assign(EC_KEY* key) {
        if (!_handle || !key) return false;
        return EVP_PKEY_assign_EC_KEY(_handle.get(), key) != 0;
    }

    bool copy(EC_KEY* key) {
        if (!_handle || !key) return false;
        return EVP_PKEY_set1_EC_KEY(_handle.get(), key) != 0;
    }
    #endif

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

protected:
    // Set external handle (for cases where we don't own the EVP_PKEY)
    void set_external_handle(EVP_PKEY* handle) {
        if (handle) {
            _handle = detail::make_shared_evp_pkey(handle);
            _is_external_handle = true;
        } else {
            _handle.reset();
            _is_external_handle = false;
        }
    }

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
        _is_external_handle = false;
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
}

} // namespace sslpkix