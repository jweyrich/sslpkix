#pragma once

#include <iostream>
#include <memory>
#include <stdexcept>
#include <utility>
#include <openssl/x509v3.h>
#include "sslpkix/x509/digest.h"
#include "sslpkix/x509/key.h"
#include "sslpkix/x509/cert_name.h"

namespace sslpkix {

class Certificate {
public:
	using handle_type = X509;

	// Custom deleter for OpenSSL X509
	struct Deleter {
		void operator()(X509* ptr) const noexcept {
			if (ptr) {
				X509_free(ptr);
			}
		}
	};

    using handle_ptr = std::unique_ptr<X509, Deleter>;

    enum class Version : int {
        v2 = 2,
        v3 = 3,
        invalid = -1
    };

public:
    // Default constructor
    Certificate() = default;

    // Copy constructor
    Certificate(const Certificate& other) {
        if (other._handle) {
            auto* duplicated = X509_dup(other._handle.get());
            if (!duplicated) {
                throw std::bad_alloc();
            }
            _handle.reset(duplicated);
            reload_data();
        }
    }

    // Move constructor
    Certificate(Certificate&& other) noexcept = default;

    // Copy assignment
    Certificate& operator=(const Certificate& other) {
        if (this != &other) {
            Certificate temp(other);
            *this = std::move(temp);
        }
        return *this;
    }

    // Move assignment
    Certificate& operator=(Certificate&& other) noexcept = default;

    // Destructor
    ~Certificate() = default;

    // Get raw handle (const version preferred)
    const handle_type* handle() const noexcept {
        return _handle.get();
    }

    // Get raw handle (non-const for OpenSSL functions that need it)
    handle_type* handle() noexcept {
        return _handle.get();
    }

    // Check if certificate is valid/loaded
    bool is_valid() const noexcept {
        return _handle != nullptr;
    }

    // Explicit bool conversion
    explicit operator bool() const noexcept {
        return is_valid();
    }

    // Create new certificate
    bool create() {
        auto* new_cert = X509_new();
        if (!new_cert) {
            std::cerr << "Failed to create certificate\n";
            return false;
        }
        _handle.reset(new_cert);
        reload_data();
        return true;
    }

    bool set_version(Version version) {
        if (!_handle) return false;

        int ret = X509_set_version(_handle.get(), static_cast<long>(version));
        if (ret == 0) {
            std::cerr << "Failed to set version\n";
            return false;
        }
        _version = version;
        return true;
    }

    Version version() const noexcept {
        return _version;
    }

    bool set_serial(long serial) {
        if (!_handle) return false;

        ASN1_INTEGER_set(X509_get_serialNumber(_handle.get()), serial);
        _serial = serial;
        return true;
    }

    long serial() const noexcept {
        return _serial;
    }

    bool set_valid_since(int days) {
        if (!_handle) return false;

        X509_gmtime_adj(X509_get_notBefore(_handle.get()),
                       static_cast<long>(60) * 60 * 24 * days);
        return true;
    }

    bool set_valid_until(int days) {
        if (!_handle) return false;

        X509_gmtime_adj(X509_get_notAfter(_handle.get()),
                       static_cast<long>(60) * 60 * 24 * days);
        return true;
    }

    bool set_pubkey(const Key& key) {
        if (!_handle) return false;

        int ret = X509_set_pubkey(_handle.get(), key.handle());
        if (ret == 0) {
            std::cerr << "Failed to set public key\n";
            return false;
        }
        _pubkey.set_external_handle(key.handle());
        return true;
    }

    const Key& pubkey() const noexcept {
        return _pubkey;
    }

    Key& pubkey() noexcept {
        return _pubkey;
    }

    bool sign(const PrivateKey& key, Digest::type_e digest = Digest::TYPE_SHA1) {
        if (!_handle) return false;

        if (!X509_sign(_handle.get(), key.handle(), Digest::handle(digest))) {
            std::cerr << "Failed to sign certificate\n";
            return false;
        }
        return true;
    }

    bool add_extension(int nid, const char* value) {
        if (!_handle || !value) return false;

        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, _handle.get(), _handle.get(), nullptr, nullptr, 0);

        auto* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, const_cast<char*>(value));
        if (!ext) {
            std::cerr << "Failed to create extension: " << nid << '\n';
            return false;
        }

        // Use RAII for extension cleanup
        std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)>
            ext_guard(ext, &X509_EXTENSION_free);

        if (X509_add_ext(_handle.get(), ext, -1) == 0) {
            std::cerr << "Failed to add extension: " << nid << '\n';
            return false;
        }

        return true;
    }

    bool add_extension(X509_EXTENSION* ext) {
        if (!_handle || !ext) return false;

        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, _handle.get(), _handle.get(), nullptr, nullptr, 0);

        return X509_add_ext(_handle.get(), ext, -1) != 0;
    }

    bool set_subject(const CertificateName& subject) {
        if (!_handle) return false;

        if (X509_set_subject_name(_handle.get(), subject.handle()) == 0) {
            return false;
        }
        _subject.wrap_external(X509_get_subject_name(_handle.get()));
        return true;
    }

    const CertificateName& subject() const noexcept {
        return _subject;
    }

    CertificateName& subject() noexcept {
        return _subject;
    }

    bool set_issuer(const CertificateName& issuer) {
        if (!_handle) return false;

        if (X509_set_issuer_name(_handle.get(), issuer.handle()) == 0) {
            std::cerr << "Failed to set issuer name" << std::endl;
            return false;
        }
        _issuer.wrap_external(X509_get_issuer_name(_handle.get()));
        return true;
    }

    const CertificateName& issuer() const noexcept {
        return _issuer;
    }

    CertificateName& issuer() noexcept {
        return _issuer;
    }

    bool verify_signature(const Key& key) const {
        if (!_handle) return false;
        return X509_verify(_handle.get(), key.handle()) != 0;
    }

    bool check_private_key(const PrivateKey& key) const {
        if (!_handle) return false;
        return X509_check_private_key(_handle.get(), key.handle()) != 0;
    }

    virtual bool load(IoSink& sink) {
        auto* cert = PEM_read_bio_X509(sink.handle(), nullptr, nullptr, nullptr);
        if (!cert) {
            std::cerr << "Failed to load certificate: " << sink.source() << '\n';
            return false;
        }

        _handle.reset(cert);
        reload_data();
        return true;
    }

    virtual bool save(const IoSink& sink) const {
        if (!_handle) return false;

        if (!X509_print(sink.handle(), _handle.get()) ||
            !PEM_write_bio_X509(sink.handle(), _handle.get())) {
            std::cerr << "Failed to save certificate: " << sink.source() << '\n';
            return false;
        }
        return true;
    }

    // Equality operators
    friend bool operator==(const Certificate& lhs, const Certificate& rhs) {
        // Handle null cases
        if (!lhs._handle && !rhs._handle) return true;
        if (!lhs._handle || !rhs._handle) return false;

        return X509_cmp(lhs._handle.get(), rhs._handle.get()) == 0 &&
               lhs._subject == rhs._subject &&
               lhs._issuer == rhs._issuer;
    }

    friend bool operator!=(const Certificate& lhs, const Certificate& rhs) {
        return !(lhs == rhs);
    }

    // Swap function for copy-and-swap idiom
    friend void swap(Certificate& a, Certificate& b) noexcept {
        using std::swap;
        swap(a._handle, b._handle);
        swap(a._version, b._version);
        swap(a._serial, b._serial);
        swap(a._pubkey, b._pubkey);
        swap(a._subject, b._subject);
        swap(a._issuer, b._issuer);
    }

private:
    void reload_data() {
        if (!_handle) {
            _version = Version::invalid;
            _serial = 0;
            return;
        }

        _version = static_cast<Version>(X509_get_version(_handle.get()));
        _serial = ASN1_INTEGER_get(X509_get_serialNumber(_handle.get()));

        // Handle potential overflow warning
        if (_serial == 0xffffffffL) {
            std::cerr << "Warning: Certificate serial number is too large to fit in a long\n";
        }

        _pubkey.set_external_handle(X509_get_pubkey(_handle.get()));
        _subject.wrap_external(X509_get_subject_name(_handle.get()));
        _issuer.wrap_external(X509_get_issuer_name(_handle.get()));
    }

private:
    handle_ptr _handle;
    Version _version{Version::invalid};
    long _serial{0};
    Key _pubkey;
    CertificateName _subject;
    CertificateName _issuer;
};

} // namespace sslpkix