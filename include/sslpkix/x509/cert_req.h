#pragma once

#include <iostream>
#include <memory>
#include <functional>
#include <stdexcept>
#include <openssl/x509v3.h>
#include "sslpkix/bio_wrapper.h"
#include "sslpkix/x509/digest.h"
#include "sslpkix/x509/key.h"
#include "sslpkix/x509/cert_name.h"

namespace sslpkix {

namespace error {
    namespace cert_req {
        using BadAllocError = BadAllocError;
        using RuntimeError = RuntimeError;
        using InvalidArgumentError = InvalidArgumentError;
        using LogicError = LogicError;
    } // cert_req
} // namespace error

class CertificateRequest {
public:
	// Custom deleter for OpenSSL X509_REQ
    struct Deleter {
		void operator()(X509_REQ* ptr) const noexcept {
			if (ptr) {
				X509_REQ_free(ptr);
			}
		}
	};

    using handle_type = X509_REQ;
    using unique_ptr_type = std::unique_ptr<handle_type, Deleter>;

    enum class Version : int {
        v1 = X509_REQ_VERSION_1,
        invalid = -1
    };

public:
    // Default constructor - creates a new certificate request
    CertificateRequest()
        : _handle(nullptr, Deleter{})
    {
        auto* new_handle = X509_REQ_new();
        if (!new_handle) {
            throw error::cert_req::BadAllocError("Failed to create certificate request");
        }

        _handle.reset(new_handle);
    }

    // Constructor that creates an empty/invalid certificate request (for loading from external sources)
    explicit CertificateRequest(std::nullptr_t)
        : _handle(nullptr, Deleter{})
    {
    }

    // Copy constructor
    CertificateRequest(const CertificateRequest& other)
        : _handle(nullptr, Deleter{})
    {
        if (other._handle) {
            auto other_handle = other._handle.get();

            EVP_PKEY *test_pkey = X509_REQ_get_pubkey(other_handle);
            if (!test_pkey) {
                throw error::cert_req::RuntimeError("X509_REQ_get_pubkey failed during copy construction");
            }
            EVP_PKEY_free(test_pkey);

            // IMPORTANT: This is a workaround to avoid a bug in OpenSSL.
            // X509_REQ_dup is not working as expected in OpenSSL 3.5.0 8 Apr 2025
            // auto* dup_handle = X509_REQ_dup(other_handle);
            X509_REQ *dup_handle = nullptr;
            {
                unsigned char *buf = nullptr;
                int len = i2d_X509_REQ(other_handle, &buf);
                const unsigned char *p = buf;
                dup_handle = d2i_X509_REQ(nullptr, &p, len);
                OPENSSL_free(buf);
            }
            if (!dup_handle) {
                throw error::cert_req::RuntimeError("Failed to duplicate certificate request during copy construction");
            }
            _handle.reset(dup_handle);
        }
    }

    // Move constructor
    CertificateRequest(CertificateRequest&& other) noexcept
        : _handle(std::move(other._handle))
    {
    }

    // Copy assignment operator
    CertificateRequest& operator=(const CertificateRequest& other) {
        if (this != &other) {
            CertificateRequest temp(other);
            *this = std::move(temp);
        }
        return *this;
    }

    // Move assignment operator
    CertificateRequest& operator=(CertificateRequest&& other) noexcept {
        if (this != &other) {
            _handle = std::move(other._handle);
        }
        return *this;
    }

    // Destructor (default is fine with RAII)
    ~CertificateRequest() = default;

    // Get raw handle (for C API compatibility)
    inline handle_type* handle() const noexcept {
        return _handle.get();
    }

    inline bool has_handle() const noexcept {
        return _handle.get() != nullptr;
    }

    // Explicit bool conversion
    explicit operator bool() const noexcept {
        return has_handle();
    }

    bool set_version(Version version) {
        if (!_handle) {
            throw error::cert_req::LogicError("Certificate request handle is null");
        }
        if (version == Version::invalid) {
            throw error::cert_req::InvalidArgumentError("Invalid certificate version");
        }

        long version_long = static_cast<long>(version);
        if (X509_REQ_set_version(_handle.get(), version_long) == 0) {
            throw error::cert_req::RuntimeError("Failed to set version to " + std::to_string(version_long));
        }

        return true;
    }

    Version version() const noexcept {
        auto version = X509_REQ_get_version(_handle.get());
        switch (version) {
            case X509_REQ_VERSION_1:
                return Version::v1;
            default:
                return Version::invalid;
        }
        return static_cast<Version>(version);
    }

    // Set public key
    void set_pubkey(Key& key) {
        if (!_handle) {
            throw error::cert_req::LogicError("Certificate request handle is null");
        }
        if (!key.has_handle()) {
            throw error::cert_req::InvalidArgumentError("Invalid key");
        }

        // X509_REQ_set_pubkey does not take ownership of the key
        // so we need to increment the reference count of the key.
        if (!EVP_PKEY_up_ref(key.handle())) {
            throw error::cert_req::RuntimeError("Failed to increment reference count of the key");
        }

        int ret = X509_REQ_set_pubkey(_handle.get(), key.handle());
        if (ret == 0) {
            throw error::cert_req::RuntimeError("Failed to set public key");
        }
    }

    // Get public key
    const Key pubkey() const {
        // Returns a pointer to the public key in the certificate request.
        // We are responsible for incrementing the reference count of the key. It's currently done in Key::Key(EVP_PKEY* handle)
        auto pubkey = X509_REQ_get0_pubkey(_handle.get());
        if (!pubkey) {
            throw error::cert_req::RuntimeError("Failed to get public key");
        }

        return Key{pubkey}; // Increments reference count
    }

    Key pubkey() {
        // Returns a pointer to the public key in the certificate request.
        // We are responsible for incrementing the reference count of the key. It's currently done in Key::Key(EVP_PKEY* handle)
        auto pubkey = X509_REQ_get0_pubkey(_handle.get());
        if (!pubkey) {
            throw error::cert_req::RuntimeError("Failed to get public key");
        }

        return Key{pubkey}; // Increments reference count
    }

    // Sign the certificate request. Can be used with a private key or a public key
    void sign(Key& key, Digest::type_e digest = Digest::TYPE_SHA1) {
        if (!_handle) {
            throw error::cert_req::LogicError("Certificate request handle is null");
        }
        if (!key.has_handle()) {
            throw error::cert_req::InvalidArgumentError("Invalid key");
        }
        if (!key.can_sign()) {
            throw error::cert_req::InvalidArgumentError("Key cannot sign");
        }

        const auto has_pub = key.has_public_key();
        const auto has_priv = key.has_private_key();
        const bool is_missing_pub_or_priv = !(has_pub || has_priv);
        if (is_missing_pub_or_priv) {
            throw error::cert_req::RuntimeError("Key is missing public or private part");
        }

        if (!X509_REQ_sign(_handle.get(), key.handle(), Digest::handle(digest))) {
            throw error::cert_req::RuntimeError("Failed to sign certificate request");
        }
    }

    // Add extensions
    void add_extensions(STACK_OF(X509_EXTENSION)* exts) {
        if (!_handle) {
            throw error::cert_req::LogicError("Certificate request handle is null");
        }

        if (X509_REQ_add_extensions(_handle.get(), exts) == 0) {
            throw error::cert_req::RuntimeError("Failed to add extensions");
        }
    }

    // Set subject
    void set_subject(CertificateName& subject) {
        if (!_handle) {
            throw error::cert_req::LogicError("Certificate request handle is null");
        }

        if (X509_REQ_set_subject_name(_handle.get(), subject.handle()) == 0) {
            throw error::cert_req::RuntimeError("Failed to set subject name");
        }
    }

    // Get subject
    const CertificateName subject() const {
        auto subject = X509_REQ_get_subject_name(_handle.get());
        if (!subject) {
            throw error::cert_req::RuntimeError("Failed to get subject name");
        }
        // Create a proper copy instead of wrapping external handle
        auto* duplicated = X509_NAME_dup(subject);
        if (!duplicated) {
            throw error::cert_req::RuntimeError("Failed to duplicate subject name");
        }
        return CertificateName{duplicated, ResourceOwnership::Transfer};
    }

    CertificateName subject() {
        auto subject = X509_REQ_get_subject_name(_handle.get());
        if (!subject) {
            throw error::cert_req::RuntimeError("Failed to get subject name");
        }
        // Create a proper copy instead of wrapping external handle
        auto* duplicated = X509_NAME_dup(subject);
        if (!duplicated) {
            throw error::cert_req::RuntimeError("Failed to duplicate subject name");
        }
        return CertificateName{duplicated, ResourceOwnership::Transfer};
    }

    // Verify signature
    bool verify_signature(Key& key) const {
        if (!_handle) {
            throw error::cert_req::LogicError("Certificate request handle is null");
        }
        if (!key.has_handle()) {
            throw error::cert_req::InvalidArgumentError("Invalid key");
        }
        return X509_REQ_verify(_handle.get(), key.handle()) == 1;
    }

    /**
     * @brief Checks if the provided key matches the private key in the certificate request.
     * @note It compares the public key in the certificate request with the public key in the provided key.
     */
    bool matches_private_key(const Key& key) const {
        if (!_handle) {
            throw error::cert_req::LogicError("Certificate request handle is null");
        }
        if (!key.has_handle()) {
            throw error::cert_req::InvalidArgumentError("Invalid key");
        }

        EVP_PKEY* this_pkey = X509_REQ_get0_pubkey(_handle.get());
        EVP_PKEY* provided_pkey = key.handle();

        int result = EVP_PKEY_eq(this_pkey, provided_pkey);
        // See https://docs.openssl.org/3.1/man3/EVP_PKEY_eq//#return-values
        switch (result) {
            case 1: return true; // Keys are equal
            case 0: return false; // Keys are different
            case -1: throw error::cert_req::RuntimeError("Failed to compare keys");
            case -2: throw error::cert_req::RuntimeError("Operation is not supported");
            default: throw error::cert_req::RuntimeError("Unexpected result from EVP_PKEY_eq");
        }
    }

    bool print_ex(BIO* bio, int name_fmt_flags = XN_FLAG_COMPAT, int cert_skip_flags = X509_FLAG_COMPAT) const noexcept {
        return X509_REQ_print_ex(bio, _handle.get(), name_fmt_flags, cert_skip_flags) == 1;
    }

    bool print(FILE* stream = stdout) const noexcept {
        auto bio_out = BioWrapper(BIO_new_fp(stream, BIO_NOCLOSE));
        const auto ret = print_ex(bio_out.get());
        return ret;
    }

    // Load from IoSink
    virtual void load(IoSink& sink) {
        auto* new_handle = PEM_read_bio_X509_REQ(sink.handle(), nullptr, nullptr, nullptr);
        if (!new_handle) {
            throw error::cert_req::RuntimeError("Failed to load certificate request from " + sink.source());
        }

        _handle.reset(new_handle);
    }

    // Save to IoSink
    virtual void save(IoSink& sink) const {
        if (!_handle) {
            throw error::cert_req::LogicError("Certificate request handle is null");
        }

        if (!X509_REQ_print(sink.handle(), _handle.get()) ||
            !PEM_write_bio_X509_REQ(sink.handle(), _handle.get()))
        {
            throw error::cert_req::RuntimeError("Failed to save certificate request to " + sink.source());
        }
    }

private:
    unique_ptr_type _handle;
};

} // namespace sslpkix