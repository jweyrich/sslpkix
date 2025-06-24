#pragma once

#include <iostream>
#include <memory>
#include <stdexcept>
#include <utility>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include "sslpkix/x509/digest.h"
#include "sslpkix/x509/key.h"
#include "sslpkix/x509/cert_name.h"
#include "sslpkix/error.h"

namespace sslpkix {

namespace detail {
    time_t asn1_time_to_time_t(const ASN1_TIME* time);
} // namespace detail

class Certificate {
public:
	// Custom deleter for OpenSSL X509
	struct Deleter {
		void operator()(X509* ptr) const noexcept {
			if (ptr) {
				X509_free(ptr);
			}
		}
	};

    using handle_type = X509;
    using handle_ptr = std::unique_ptr<handle_type, Deleter>;

    enum class Version : int {
        v1 = X509_VERSION_1,
        v2 = X509_VERSION_2,
        v3 = X509_VERSION_3,
        invalid = -1
    };

public:
    // Default constructor - creates a new certificate
    Certificate() {
        auto* new_cert = X509_new();
        if (!new_cert) {
            throw std::bad_alloc();
        }
        _handle.reset(new_cert);
    }

    // Constructor for creating certificate from existing X509 handle
    explicit Certificate(X509* cert_handle) {
        if (!cert_handle) {
            throw std::invalid_argument("Certificate handle cannot be null");
        }
        _handle.reset(cert_handle);
    }

    // Copy constructor
    Certificate(const Certificate& other) {
        if (!other.is_valid()) {
            throw std::invalid_argument("Certificate handle cannot be null");
        }
        if (!other.has_required_fields()) {
            throw std::runtime_error("Cannot duplicate certificate. Reason: " + get_error_string());
        }

        if (other._handle) {
            auto* duplicated = X509_dup(other._handle.get());
            if (!duplicated) {
                throw std::runtime_error("Failed to duplicate certificate. Reason: " + get_error_string());
            }
            _handle.reset(duplicated);
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
    virtual ~Certificate() = default;

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
        return _handle.get() != nullptr;
    }

    // Explicit bool conversion
    explicit operator bool() const noexcept {
        return is_valid();
    }

    bool has_required_fields() const noexcept {
        if (!_handle) {
            return false;
        }

        // Check if the certificate has all the required fields
        // If any of the fields are missing, the certificate cannot be duplicated
        // The version field of certificates, certificate requests and CRLs has a DEFAULT value of v1(0) meaning the field should be omitted for version 1.
        const ASN1_INTEGER* serial_number = X509_get0_serialNumber(_handle.get());
        long serial = ASN1_INTEGER_get(serial_number);
        if (serial == -1) {
            ERR_raise(ERR_LIB_USER, 1);
            ERR_raise_data(ERR_LIB_USER, 2, "Certificate is missing serialNumber");
            return false;
        }

        const ASN1_TIME* not_before = X509_get0_notBefore(_handle.get());
        time_t not_before_time = detail::asn1_time_to_time_t(not_before);
        if (not_before_time == -1) {
            ERR_raise(ERR_LIB_USER, 1);
            ERR_raise_data(ERR_LIB_USER, 2, "Certificate is missing notBefore");
            return false;
        }

        const ASN1_TIME* not_after = X509_get0_notAfter(_handle.get());
        time_t not_after_time = detail::asn1_time_to_time_t(not_after);
        if (not_after_time == -1) {
            ERR_raise(ERR_LIB_USER, 1);
            ERR_raise_data(ERR_LIB_USER, 2, "Certificate is missing notAfter");
            return false;
        }

        const X509_NAME* subject = X509_get_subject_name(_handle.get());
        int subject_common_name = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
        if (subject_common_name == -1) {
            ERR_raise(ERR_LIB_USER, 1);
            ERR_raise_data(ERR_LIB_USER, 2, "Certificate is missing subject");
            return false;
        }

        const X509_NAME* issuer = X509_get_issuer_name(_handle.get());
        int issuer_common_name = X509_NAME_get_index_by_NID(issuer, NID_commonName, -1);
        if (issuer_common_name == -1) {
            ERR_raise(ERR_LIB_USER, 1);
            ERR_raise_data(ERR_LIB_USER, 2, "Certificate is missing issuer");
            return false;
        }

        // NOTE: X509_get0_pubkey does not increment the reference count of the returned EVP_PKEY.
        EVP_PKEY* pubkey = X509_get0_pubkey(_handle.get());
        if (!pubkey) {
            ERR_raise(ERR_LIB_USER, 1);
            ERR_raise_data(ERR_LIB_USER, 2, "Certificate is missing public key");
            return false;
        }

        // Check if the certificate has a valid signature
        if (!is_signed()) {
            ERR_raise(ERR_LIB_USER, 1);
            ERR_raise_data(ERR_LIB_USER, 2, "Certificate is missing signature");
            return false;
        }

        return true;
    }

    bool is_signed() const noexcept {
        // Check if the signature algorithm is set
        const X509_ALGOR* alg = X509_get0_tbs_sigalg(_handle.get());
        if (!alg || OBJ_obj2nid(alg->algorithm) == NID_undef)
            return false;

        // Check if the actual signature value exists
        const ASN1_BIT_STRING* sig = nullptr;
        X509_get0_signature(&sig, nullptr, _handle.get());
        if (!sig || sig->length == 0)
            return false;

        return true;
    }

    /**
     * @brief Checks if the certificate is self-signed.
     * @note For success the issuer and subject names must match, the components of the authority key identifier (if present)
     * must match the subject key identifier etc. The signature itself is actually verified only if verify_signature is 1, as
     * for explicitly trusted certificates this verification is not worth the effort.
     */
    bool is_self_signed() const noexcept {
        return X509_self_signed(_handle.get(), 1) == 1;
    }

    void set_version(Version version) {
        if (!_handle) {
            throw std::logic_error("Certificate handle is null");
        }
        if (version == Version::invalid) {
            throw std::invalid_argument("Invalid certificate version");
        }

        long version_long = static_cast<long>(version);
        int ret = X509_set_version(_handle.get(), version_long);
        if (ret == 0) {
            throw std::runtime_error("Failed to set certificate version to " + std::to_string(version_long) + ". Reason: " + get_error_string());
        }
    }

    Version version() const noexcept {
        auto version = X509_get_version(_handle.get());
        return static_cast<Version>(version);
    }

    void set_serial(long serial) {
        if (!_handle) {
            throw std::logic_error("Certificate handle is null");
        }

        ASN1_INTEGER* serial_number = X509_get_serialNumber(_handle.get());
        int result = ASN1_INTEGER_set(serial_number, serial);
        if (result == 0) {
            throw std::runtime_error("Failed to set certificate serial number. Reason: " + get_error_string());
        }
    }

    long serial() const {
        ASN1_INTEGER* serial_number = X509_get_serialNumber(_handle.get());
        auto serial = ASN1_INTEGER_get(serial_number);

        // Handle potential overflow warning
        if (serial == 0xffffffffL) {
            throw std::overflow_error("Certificate serial number is too large to fit in a long");
        }
        return serial;
    }

    void set_valid_since(int days) {
        if (!_handle) {
            throw std::logic_error("Certificate handle is null");
        }

        ASN1_TIME* not_before = X509_getm_notBefore(_handle.get());
        ASN1_TIME* result = X509_gmtime_adj(not_before, static_cast<long>(60) * 60 * 24 * days);
        if (!result) {
            throw std::runtime_error("Failed to set certificate valid since. Reason: " + get_error_string());
        }
    }

    void set_valid_until(int days) {
        if (!_handle) {
            throw std::logic_error("Certificate handle is null");
        }

        ASN1_TIME* not_after = X509_getm_notAfter(_handle.get());
        ASN1_TIME* result = X509_gmtime_adj(not_after, static_cast<long>(60) * 60 * 24 * days);
        if (!result) {
            throw std::runtime_error("Failed to set certificate valid until. Reason: " + get_error_string());
        }
    }

    void set_pubkey(const Key& key) {
        if (!_handle) {
            throw std::logic_error("Certificate handle is null");
        }
        if (!key.is_valid()) {
            throw std::invalid_argument("Invalid key");
        }

        // X509_set_pubkey does not take ownership of the key
        // so we need to increment the reference count of the key.
        EVP_PKEY_up_ref(key.handle());

        int ret = X509_set_pubkey(_handle.get(), key.handle());
        if (ret == 0) {
            throw std::runtime_error("Failed to set public key. Reason: " + get_error_string());
        }
    }

    const Key pubkey() const {
        // Returns a pointer to the public key in the certificate request.
        // We are responsible for incrementing the reference count of the key. It's currently done in Key::Key(EVP_PKEY* handle)
        auto pubkey = X509_get0_pubkey(_handle.get());
        if (!pubkey) {
            throw std::runtime_error("Failed to get public key. Reason: " + get_error_string());
        }

        return Key{pubkey}; // Increments reference count
    }

    Key pubkey() {
        // Returns a pointer to the public key in the certificate request.
        // We are responsible for incrementing the reference count of the key. It's currently done in Key::Key(EVP_PKEY* handle)
        auto pubkey = X509_get0_pubkey(_handle.get());
        if (!pubkey) {
            throw std::runtime_error("Failed to get public key. Reason: " + get_error_string());
        }

        return Key{pubkey}; // Increments reference count
    }

    void sign(const Key& key, Digest::type_e digest = Digest::TYPE_SHA1) {
        if (!_handle) {
            throw std::logic_error("Certificate handle is null");
        }
        if (!key.is_valid()) {
            throw std::invalid_argument("Invalid key");
        }
        if (!key.can_sign()) {
            throw std::invalid_argument("Key cannot sign");
        }

        const auto has_pub = key.has_public_key();
        const auto has_priv = key.has_private_key();
        const bool is_missing_pub_or_priv = !(has_pub || has_priv);
        if (is_missing_pub_or_priv) {
            throw std::runtime_error("Key is missing public or private part");
        }

        if (!X509_sign(_handle.get(), key.handle(), Digest::handle(digest))) {
            throw std::runtime_error("Failed to sign certificate. Reason: " + get_error_string());
        }
    }

    void add_extension(int nid, const char* value) {
        if (!_handle) {
            throw std::logic_error("Certificate handle is null");
        }
        if (!value) {
            throw std::invalid_argument("Extension value cannot be null");
        }

        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, _handle.get(), _handle.get(), nullptr, nullptr, 0);

        auto* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, const_cast<char*>(value));
        if (!ext) {
            throw std::runtime_error("Failed to create extension with NID: " + std::to_string(nid) + ". Reason: " + get_error_string());
        }

        // Use RAII for extension cleanup
        std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)>
            ext_guard(ext, &X509_EXTENSION_free);

        if (X509_add_ext(_handle.get(), ext, -1) == 0) {
            throw std::runtime_error("Failed to add extension with NID: " + std::to_string(nid) + ". Reason: " + get_error_string());
        }
    }

    void add_extension(X509_EXTENSION* ext) {
        if (!_handle) {
            throw std::logic_error("Certificate handle is null");
        }
        if (!ext) {
            throw std::invalid_argument("Extension cannot be null");
        }

        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, _handle.get(), _handle.get(), nullptr, nullptr, 0);

        if (X509_add_ext(_handle.get(), ext, -1) == 0) {
            throw std::runtime_error("Failed to add extension. Reason: " + get_error_string());
        }
    }

    void set_subject(const CertificateName& subject) {
        if (!_handle) {
            throw std::logic_error("Certificate handle is null");
        }
        if (!subject.is_valid()) {
            throw std::invalid_argument("Invalid subject");
        }

        if (X509_set_subject_name(_handle.get(), subject.handle()) == 0) {
            throw std::runtime_error("Failed to set subject name. Reason: " + get_error_string());
        }
    }

    const CertificateName subject() const {
        auto subject = X509_get_subject_name(_handle.get());
        if (!subject) {
            throw std::runtime_error("Failed to get subject name. Reason: " + get_error_string());
        }
        // Create a proper copy instead of wrapping external handle
        auto* duplicated = X509_NAME_dup(subject);
        if (!duplicated) {
            throw std::runtime_error("Failed to duplicate subject name. Reason: " + get_error_string());
        }
        return CertificateName{duplicated}; // Takes ownership
    }

    CertificateName subject() {
        auto subject = X509_get_subject_name(_handle.get());
        if (!subject) {
            throw std::runtime_error("Failed to get subject name. Reason: " + get_error_string());
        }
        // Create a proper copy instead of wrapping external handle
        auto* duplicated = X509_NAME_dup(subject);
        if (!duplicated) {
            throw std::runtime_error("Failed to duplicate subject name. Reason: " + get_error_string());
        }
        return CertificateName{duplicated}; // Takes ownership
    }

    void set_issuer(const CertificateName& issuer) {
        if (!_handle) {
            throw std::logic_error("Certificate handle is null");
        }
        if (!issuer.is_valid()) {
            throw std::invalid_argument("Invalid issuer");
        }

        if (X509_set_issuer_name(_handle.get(), issuer.handle()) == 0) {
            throw std::runtime_error("Failed to set issuer name. Reason: " + get_error_string());
        }
    }

    const CertificateName issuer() const {
        auto issuer = X509_get_issuer_name(_handle.get());
        if (!issuer) {
            throw std::runtime_error("Failed to get issuer name. Reason: " + get_error_string());
        }
        // Create a proper copy instead of wrapping external handle
        auto* duplicated = X509_NAME_dup(issuer);
        if (!duplicated) {
            throw std::runtime_error("Failed to duplicate issuer name. Reason: " + get_error_string());
        }
        return CertificateName{duplicated}; // Takes ownership
    }

    CertificateName issuer() {
        auto issuer = X509_get_issuer_name(_handle.get());
        if (!issuer) {
            throw std::runtime_error("Failed to get issuer name. Reason: " + get_error_string());
        }
        // Create a proper copy instead of wrapping external handle
        auto* duplicated = X509_NAME_dup(issuer);
        if (!duplicated) {
            throw std::runtime_error("Failed to duplicate issuer name. Reason: " + get_error_string());
        }
        return CertificateName{duplicated}; // Takes ownership
    }

    bool verify_signature(const Key& key) const {
        if (!_handle) {
            throw std::logic_error("Certificate handle is null");
        }
        if (!key.is_valid()) {
            throw std::invalid_argument("Invalid key");
        }
        return X509_verify(_handle.get(), key.handle()) == 1;
    }

    /**
     * @brief Checks if the provided key matches the private key in the certificate.
     * @note It compares the public key in the certificate with the public key in the provided key.
     */
    bool matches_private_key(const Key& key) const {
        if (!_handle) {
            throw std::logic_error("Certificate handle is null");
        }
        if (!key.is_valid()) {
            throw std::invalid_argument("Invalid key");
        }

        EVP_PKEY* this_pkey = X509_get0_pubkey(_handle.get());
        EVP_PKEY* provided_pkey = key.handle();
        return EVP_PKEY_cmp(this_pkey, provided_pkey) == 1;
    }

    bool print_ex(BIO* bio, int name_fmt_flags = XN_FLAG_COMPAT, int cert_print_flags = X509_FLAG_COMPAT) const noexcept {
        return X509_print_ex(bio, _handle.get(), name_fmt_flags, cert_print_flags) == 1;
    }

    bool print(FILE* stream = stdout) const noexcept {
        BIO *bio_out = BIO_new_fp(stream, BIO_NOCLOSE);
        const auto ret = print_ex(bio_out);
        BIO_free(bio_out);
        return ret;
    }

    virtual void load(IoSink& sink) {
        if (!sink.is_open()) {
            throw std::invalid_argument("IoSink is not open");
        }

        auto* cert = PEM_read_bio_X509(sink.handle(), nullptr, nullptr, nullptr);
        if (!cert) {
            throw std::runtime_error("Failed to load certificate from: " + sink.source() + ". Reason: " + get_error_string());
        }

        _handle.reset(cert);
    }

    virtual void save(const IoSink& sink) const {
        if (!_handle) {
            throw std::logic_error("Certificate handle is null");
        }
        if (!sink.is_open()) {
            throw std::invalid_argument("IoSink is not open");
        }

        if (!X509_print(sink.handle(), _handle.get()) ||
            !PEM_write_bio_X509(sink.handle(), _handle.get())) {
            throw std::runtime_error("Failed to save certificate to: " + sink.source() + ". Reason: " + get_error_string());
        }
    }

    // Equality operators
    friend bool operator==(const Certificate& lhs, const Certificate& rhs) {
        // Handle null cases
        if (!lhs._handle && !rhs._handle) return true;
        if (!lhs._handle || !rhs._handle) return false;

        // TODO(jweyrich): Do we need to REALLY compare anything besides the handle?
        return X509_cmp(lhs._handle.get(), rhs._handle.get()) == 0 &&
               lhs.subject() == rhs.subject() &&
               lhs.issuer() == rhs.issuer();
    }

    friend bool operator!=(const Certificate& lhs, const Certificate& rhs) {
        return !(lhs == rhs);
    }

    // Swap function for copy-and-swap idiom
    friend void swap(Certificate& a, Certificate& b) noexcept {
        using std::swap;
        swap(a._handle, b._handle);
    }

private:
    handle_ptr _handle{nullptr, Deleter()};
};

} // namespace sslpkix