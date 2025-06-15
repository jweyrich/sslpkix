#pragma once

#include <iostream>
#include <memory>
#include <functional>
#include <openssl/x509.h>
#include "sslpkix/x509/digest.h"
#include "sslpkix/x509/key.h"
#include "sslpkix/x509/cert_name.h"

namespace sslpkix {

class CertificateRequest {
public:
    using handle_type = X509_REQ;

	// Custom deleter for OpenSSL X509_NAME
    struct Deleter {
		void operator()(X509_REQ* ptr) const noexcept {
			if (ptr) {
				X509_REQ_free(ptr);
			}
		}
	};

    using unique_ptr_type = std::unique_ptr<X509_REQ, Deleter>;

public:
    // Default constructor
    CertificateRequest()
        : _handle(nullptr, Deleter{})
        , _version(0)
    {
    }

    // Copy constructor
    CertificateRequest(const CertificateRequest& other)
        : _handle(nullptr, Deleter{})
        , _version(0)
    {
        if (other._handle) {
            auto* dup_handle = X509_REQ_dup(other._handle.get());
            if (!dup_handle) {
                throw std::bad_alloc();
            }
            _handle.reset(dup_handle);
            reload_data();
        }
    }

    // Move constructor
    CertificateRequest(CertificateRequest&& other) noexcept
        : _handle(std::move(other._handle))
        , _version(other._version)
        , _serial(other._serial)
        , _pubkey(std::move(other._pubkey))
        , _subject(std::move(other._subject))
    {
        other._version = 0;
        other._serial = 0;
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
            _version = other._version;
            _serial = other._serial;
            _pubkey = std::move(other._pubkey);
            _subject = std::move(other._subject);

            other._version = 0;
            other._serial = 0;
        }
        return *this;
    }

    // Destructor (default is fine with RAII)
    ~CertificateRequest() = default;

    // Get raw handle (for C API compatibility)
    handle_type* handle() const noexcept {
        return _handle.get();
    }

    // Check if the certificate request is valid
    explicit operator bool() const noexcept {
        return _handle != nullptr;
    }

    // Create a new certificate request
    bool create() {
        auto* new_handle = X509_REQ_new();
        if (!new_handle) {
            std::cerr << "Failed to create certificate request" << std::endl;
            return false;
        }

        _handle.reset(new_handle);
        reload_data();
        return true;
    }

    // Set version
    bool set_version(long version) {
        if (!_handle) {
            std::cerr << "Invalid certificate request handle" << std::endl;
            return false;
        }

        if (X509_REQ_set_version(_handle.get(), version) == 0) {
            std::cerr << "Failed to set version" << std::endl;
            return false;
        }

        _version = version;
        return true;
    }

    // Get version
    long version() const noexcept {
        return _version;
    }

    // Set public key
    bool set_pubkey(Key& key) {
        if (!_handle) {
            std::cerr << "Invalid certificate request handle" << std::endl;
            return false;
        }

        if (X509_REQ_set_pubkey(_handle.get(), key.handle()) == 0) {
            std::cerr << "Failed to set public key" << std::endl;
            return false;
        }

        _pubkey.set_external_handle(key.handle());
        return true;
    }

    // Get public key
    const Key& pubkey() const noexcept {
        return _pubkey;
    }

    Key& pubkey() noexcept {
        return _pubkey;
    }

    // Sign the certificate request
    bool sign(PrivateKey& key, Digest::type_e digest = Digest::TYPE_SHA1) {
        if (!_handle) {
            std::cerr << "Invalid certificate request handle" << std::endl;
            return false;
        }

        if (!X509_REQ_sign(_handle.get(), key.handle(), Digest::handle(digest))) {
            std::cerr << "Failed to sign certificate request" << std::endl;
            return false;
        }

        return true;
    }

    // Add extensions
    bool add_extensions(STACK_OF(X509_EXTENSION)* exts) {
        if (!_handle) {
            std::cerr << "Invalid certificate request handle" << std::endl;
            return false;
        }

        return X509_REQ_add_extensions(_handle.get(), exts) != 0;
    }

    // Set subject
    bool set_subject(CertificateName& subject) {
        if (!_handle) {
            std::cerr << "Invalid certificate request handle" << std::endl;
            return false;
        }

        if (X509_REQ_set_subject_name(_handle.get(), subject.handle()) == 0) {
            std::cerr << "Failed to set subject name" << std::endl;
            return false;
        }

        _subject.wrap_external(X509_REQ_get_subject_name(_handle.get()));
        return true;
    }

    // Get subject
    const CertificateName& subject() const noexcept {
        return _subject;
    }

    CertificateName& subject() noexcept {
        return _subject;
    }

    // Verify signature
    bool verify_signature(Key& key) const {
        if (!_handle) {
            return false;
        }

        return X509_REQ_verify(_handle.get(), key.handle()) != 0;
    }

    // Check private key
    bool check_private_key(PrivateKey& key) const {
        if (!_handle) {
            return false;
        }

        return X509_REQ_check_private_key(_handle.get(), key.handle()) != 0;
    }

    // Load from IoSink
    virtual bool load(IoSink& sink) {
        auto* new_handle = PEM_read_bio_X509_REQ(sink.handle(), nullptr, nullptr, nullptr);
        if (!new_handle) {
            std::cerr << "Failed to load certificate request: " << sink.source() << std::endl;
            return false;
        }

        _handle.reset(new_handle);
        reload_data();
        return true;
    }

    // Save to IoSink
    virtual bool save(IoSink& sink) const {
        if (!_handle) {
            std::cerr << "Invalid certificate request handle" << std::endl;
            return false;
        }

        if (!X509_REQ_print(sink.handle(), _handle.get()) ||
            !PEM_write_bio_X509_REQ(sink.handle(), _handle.get())) {
            std::cerr << "Failed to save certificate request: " << sink.source() << std::endl;
            return false;
        }

        return true;
    }

private:
    // Reload internal data from handle
    void reload_data() {
        if (!_handle) {
            return;
        }

        _version = X509_REQ_get_version(_handle.get());
        _pubkey.set_external_handle(X509_REQ_get_pubkey(_handle.get()));
        _subject.wrap_external(X509_REQ_get_subject_name(_handle.get()));
    }

private:
    unique_ptr_type _handle;
    long _version{0};
    long _serial{0};
    Key _pubkey;
    CertificateName _subject;
};

} // namespace sslpkix