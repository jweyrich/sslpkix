#pragma once

#include <iostream>
#include <memory>
#include <functional>
#include <type_traits>
#include <stdexcept>
#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "sslpkix/iosink.h"
#include "sslpkix/error.h"

namespace sslpkix {

// Custom exception for key-related errors
class KeyException : public std::runtime_error {
public:
    explicit KeyException(const std::string& message)
        : std::runtime_error(message)
        , _openssl_error_string(get_error_string()) {}

    std::string openssl_error_string() const {
        return _openssl_error_string;
    }

private:
    std::string _openssl_error_string;
};

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
            throw std::bad_alloc();
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

    // Get algorithm type
    Cipher::Type algorithm() const {
        int algorithm = detail::get_algorithm_type(_handle.get());
        return static_cast<Cipher::Type>(algorithm);
    }

    // Get bit length
    // Returns 0 if the size is not available or the key is not valid
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
        // TODO(jweyrich): do we need EVP_PKEY_cmp_parameters() too?
        return EVP_PKEY_cmp(lhs._handle.get(), rhs._handle.get()) == 1;
    }

    friend bool operator!=(const Key& lhs, const Key& rhs) {
        return !(lhs == rhs);
    }

protected:
    // Set external handle (for cases where we don't own the EVP_PKEY)
    void set_external_handle(EVP_PKEY* handle) {
        if (!handle) {
            _handle.reset();
            return;
        }

        // Increment reference count and create a new unique_ptr
        #if OPENSSL_VERSION_NUMBER < 0x10100000L
        CRYPTO_add(&handle->references, 1, CRYPTO_LOCK_EVP_PKEY);
        #else
        EVP_PKEY_up_ref(handle);
        #endif
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

    // Constructor that creates from cipher
    template<typename CipherType>
    explicit PrivateKey(CipherType* cipher_key) : Key(true) {
        static_assert(detail::is_cipher_supported_v<CipherType>,
                     "Cipher type not supported");
        if (!assign(cipher_key)) {
            throw KeyException("Failed to create private key from cipher. Reason: " + get_error_string());
        }
    }

    virtual ~PrivateKey() {
        // std::cout << "Destroying PrivateKey " << key_id << std::endl;
    }

    // Load private key from IoSink
    void load(IoSink& sink, const char* password = nullptr) override {
        auto new_key = PEM_read_bio_PrivateKey(sink.handle(), nullptr, nullptr,
            const_cast<void*>(static_cast<const void*>(password)));
        if (!new_key) {
            throw KeyException("Failed to load private key from " + sink.source() + ". Reason: " + get_error_string());
        }
        // std::cout << "Loaded private key " << new_key << std::endl;
        _handle.reset(new_key);
    }

    // Save private key to IoSink
    void save(IoSink& sink) const override {
        if (!_handle) {
            throw KeyException("Invalid private key handle");
        }

        int ret = PEM_write_bio_PrivateKey(sink.handle(), _handle.get(),
                                         nullptr, nullptr, 0, 0, nullptr);
        if (ret == 0) {
            throw KeyException("Failed to save private key to " + sink.source() + ". Reason: " + get_error_string());
        }
    }

    // Template-based factory methods
    template<typename CipherType>
    static std::unique_ptr<PrivateKey> create_from_cipher(CipherType* cipher_key) {
        static_assert(detail::is_cipher_supported_v<CipherType>,
                     "Cipher type not supported");

        try {
            return std::make_unique<PrivateKey>(cipher_key);
        } catch (const KeyException&) {
            return nullptr;
        }
    }

    // Factory method to create a private key from file
    static std::unique_ptr<PrivateKey> from_file([[maybe_unused]]const std::string& filename,
                                                const char* password = nullptr) {
        try {
            IoSink sink; // Assuming IoSink can be constructed from filename
            return std::make_unique<PrivateKey>(sink, password);
        } catch (const KeyException&) {
            return nullptr;
        }
    }

    // Factory method to create a private key from memory
    static std::unique_ptr<PrivateKey> from_memory([[maybe_unused]] const std::string& pem_data,
                                                 const char* password = nullptr) {
        try {
            IoSink sink; // Assuming IoSink can be constructed from memory
            return std::make_unique<PrivateKey>(sink, password);
        } catch (const KeyException&) {
            return nullptr;
        }
    }
};

// Factory functions for creating keys
namespace factory {
    inline std::unique_ptr<Key> make_key() {
        try {
            return std::make_unique<Key>();
        } catch (const KeyException&) {
            return nullptr;
        }
    }

    inline std::unique_ptr<PrivateKey> make_private_key() {
        try {
            return std::make_unique<PrivateKey>();
        } catch (const KeyException&) {
            return nullptr;
        }
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