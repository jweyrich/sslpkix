#pragma once

#include <iostream>
#include <memory>
#include <functional>
#include <type_traits>
#include <stdexcept>
#include <openssl/core_names.h>
#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "sslpkix/iosink.h"
#include "sslpkix/exception.h"

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

} // namespace detail

//
// NOTE: With OpenSSL, the private key also contains the public key information
//
class Key {
public:
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
    detail::handle_ptr _handle{nullptr, detail::EVP_PKEY_Deleter()};

    // Protected constructor for creating empty key (used by derived classes)
    explicit Key(bool create_handle) {
        if (create_handle) {
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
    // Default constructor - creates a new key
    Key() : Key(true) {}

    // Constructor for external handle (does not create new key)
    explicit Key(EVP_PKEY* external_handle) {
        key_id = static_key_counter++;
        // std::cout << "Creating key (external) " << key_id << std::endl;
        set_external_handle(external_handle);
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
    detail::handle_type* handle() const noexcept {
        return _handle.get();
    }

    // Check if key is valid
    bool is_valid() const noexcept {
        return _handle.get() != nullptr;
    }

    /**
     * @brief Returns true if the key has a public key.
     */
    bool has_public_key() const noexcept {
        if (!is_valid()) {
            return false;
        }
        auto ctx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(
            EVP_PKEY_CTX_new_from_pkey(NULL, _handle.get(), NULL),
            EVP_PKEY_CTX_free
        );
        return ctx && EVP_PKEY_public_check_quick(ctx.get()) == 1;
    }

    /**
     * @brief Returns true if the key has a private key.
     */
    bool has_private_key() const noexcept {
        if (!is_valid()) {
            return false;
        }
        auto ctx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(
            EVP_PKEY_CTX_new_from_pkey(NULL, _handle.get(), NULL),
            EVP_PKEY_CTX_free
        );
        return ctx && EVP_PKEY_private_check(ctx.get()) == 1;
    }

    // Get algorithm type
    Cipher::Type algorithm() const {
        int algorithm = detail::get_algorithm_type(_handle.get());
        return static_cast<Cipher::Type>(algorithm);
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
     * @brief Returns the base type of the key (EVP_PKEY_RSA, EVP_PKEY_DSA, etc.),
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
     * @note It does not create or copy the provided key.
     * @note This method increments the reference count of the existing key so it can be safely used and free'd elsewhere.
     * @param key The existing EVP_PKEY to assign.
     * @return true if the assignment was successful, false otherwise.
     */
    void assign(EVP_PKEY* key) {
        if (!key) {
            throw error::key::InvalidArgumentError("Cannot assign a null key");
        }
        auto provider = EVP_PKEY_get0_provider(key);
        if (!provider) {
            throw error::key::InvalidArgumentError("Cannot assign a legacy key");
        }
        if (!EVP_PKEY_up_ref(key)) {
            throw error::key::RuntimeError("Failed to increment reference count of the key");
        }
        _handle.reset(key);
    }

    /**
     * @brief Copies the contents of an existing key to this Key object.
     * @note This method creates a new EVP_PKEY by duplicating the existing key.
     * @param key The existing EVP_PKEY to copy.
     * @return true if the copy was successful, false otherwise.
     */
    void copy(const EVP_PKEY* key) {
        if (!key) {
            throw error::key::InvalidArgumentError("Cannot copy from a null key");
        }
        auto provider = EVP_PKEY_get0_provider(key);
        if (!provider) {
            throw error::key::InvalidArgumentError("Cannot copy from a legacy key");
        }
        EVP_PKEY* new_key = EVP_PKEY_dup(const_cast<EVP_PKEY*>(key));
        if (!new_key) {
            throw error::key::RuntimeError("Failed to copy key");
        }
        _handle.reset(new_key);
    }

    virtual int print_ex(BIO* bio) const noexcept {
        return EVP_PKEY_print_public(bio, _handle.get(), 0, NULL);
    }

    virtual int print(FILE* stream = stdout) const noexcept {
        BIO *bio_out = BIO_new_fp(stream, BIO_NOCLOSE);
        int ret = print_ex(bio_out);
        BIO_free(bio_out);
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
     * @brief Returns a public key from a private key.
     * @note This is a convenience method that extracts the public key from the private key.
     */
    std::unique_ptr<Key> pubkey() const;

protected:
    /**
     * @brief Set the external handle object
     * @note This method increments the reference count of the existing key so it can be safely used and free'd elsewhere.
     *
     * @param handle
     */
    void set_external_handle(EVP_PKEY* handle) {
        if (!handle) {
            _handle.reset();
            return;
        }

        if (!EVP_PKEY_up_ref(handle)) {
            throw error::key::RuntimeError("Failed to increment reference count of the external key");
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
    explicit PrivateKey(EVP_PKEY* external_handle) : Key(external_handle) {}

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
    // Move to a KeyGenerator class?
    EVP_PKEY* generate_key_ex(const char* key_type, const OSSL_PARAM* params = nullptr);

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

    inline EVP_PKEY* generate_key_rsa(int bits) {
        const OSSL_PARAM params[] = {
            OSSL_PARAM_int(OSSL_PKEY_PARAM_RSA_BITS, &bits),
            OSSL_PARAM_END
        };

        return factory::generate_key_ex("RSA", params);
    }

    inline EVP_PKEY* generate_key_dsa(int pbits, int qbits) {
        OSSL_PARAM params[] = {
            OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_PBITS, &pbits),
            OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_QBITS, &qbits),
            OSSL_PARAM_END
        };
        return factory::generate_key_ex("DSA", params);
    }

    inline EVP_PKEY* generate_key_dh(int group) {
        const char* group_name = OBJ_nid2sn(static_cast<int>(group));
        OSSL_PARAM params[] = {
            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char*>(group_name), 0),
            OSSL_PARAM_END
        };
        return factory::generate_key_ex("DH", params);
    }

    inline EVP_PKEY* generate_key_ec(int group) {
        const char* group_name = OBJ_nid2sn(static_cast<int>(group));
        OSSL_PARAM params[] = {
            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char*>(group_name), 0),
            OSSL_PARAM_END
        };
        return factory::generate_key_ex("EC", params);
    }

    inline EVP_PKEY* generate_key_ed25519() {
        return factory::generate_key_ex("ED25519");
    }
}

} // namespace sslpkix