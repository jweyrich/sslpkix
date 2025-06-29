#pragma once

#include <iostream>
#include <string>
#include <memory>
#include <stdexcept>
#include <cassert>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include "sslpkix/bio_wrapper.h"
#include "sslpkix/exception.h"

namespace sslpkix {

namespace error {
    namespace cert_name {
        using RuntimeError = RuntimeError;
        using BadAllocError = BadAllocError;
        using InvalidArgumentError = InvalidArgumentError;
        using LogicError = LogicError;
    } // cert_name
} // namespace error

class CertificateName {
public:
    // More info at http://www.umich.edu/~x509/ssleay/x509_name.html
    using handle_type = X509_NAME;

    // Custom deleter for OpenSSL X509_NAME
    struct Deleter {
		bool should_delete = true;

		void operator()(X509_NAME* ptr) const noexcept {
			if (ptr && should_delete) {
				X509_NAME_free(ptr);
			}
		}
	};

    using handle_ptr = std::unique_ptr<X509_NAME, Deleter>;

private:
    handle_ptr handle_{nullptr, Deleter{true}};

public:
    // Constructors
    CertificateName() {
        auto* new_handle = X509_NAME_new();
        if (!new_handle) {
            throw error::cert_name::BadAllocError("Failed to create new certificate name");
        }
        reset(new_handle);
    }

    /**
     * @brief This constructor initializes a CertificateName object using an existing X509_NAME handle.
     * It optionally transfers ownership of the handle, managing its lifecycle with a custom deleter.
     *
     * @param external_handle The existing X509_NAME handle to wrap. If you pass a null handle, it will create an empty CertificateName.
     * @param transfer_ownership If true, the CertificateName will take ownership of the handle
     *
     * @throws `error::cert_name::BadAllocError` if the handle is null and transfer_ownership is true
     * @throws `std::runtime_error` if the handle is null and transfer_ownership is false
     */
    explicit CertificateName(X509_NAME* external_handle, bool transfer_ownership = true) : handle_(external_handle, Deleter{transfer_ownership}) {}

    // Copy constructor - deep copy
    CertificateName(const CertificateName& other) {
        if (other.handle_) {
            auto* duplicated = X509_NAME_dup(other.handle_.get());
            if (!duplicated) {
                throw error::cert_name::BadAllocError("Failed to duplicate certificate name");
            }
            reset(duplicated);
        } else {
            // If other is empty, create a new empty certificate name
            auto* new_handle = X509_NAME_new();
            if (!new_handle) {
                throw error::cert_name::BadAllocError("Failed to create new certificate name");
            }
            reset(new_handle);
        }
    }

    // Move constructor
    CertificateName(CertificateName&&) noexcept = default;

    // Copy assignment
    CertificateName& operator=(const CertificateName& other) {
        if (this != &other) {
            CertificateName temp(other);
            *this = std::move(temp);
        }
        return *this;
    }

    // Move assignment
    CertificateName& operator=(CertificateName&&) noexcept = default;

    // Legacy method name for compatibility
    inline const X509_NAME* handle() const noexcept {
        return handle_.get();
    }

    inline X509_NAME* handle() noexcept {
        return handle_.get();
    }

    inline bool has_handle() const noexcept {
        return handle_.get() != nullptr;
    }

    // Explicit bool conversion
    explicit operator bool() const noexcept {
        return has_handle();
    }

    /**
     * @brief Add an entry to the certificate name
     * @note If it fails to add the entry, throw an exception of type error::cert_name::RuntimeError
     */
    void add_entry_by_nid(int nid, const std::string& value) {
        if (value.empty()) {
            throw error::cert_name::InvalidArgumentError("Empty string is not allowed for certificate name entry (nid=" + std::to_string(nid) + ")");
        }

        const int result = X509_NAME_add_entry_by_NID(
            handle_.get(),
            nid,
            MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(value.c_str()),
            -1, -1, 0
        );

        if (result != 1) {
            throw error::cert_name::RuntimeError("Failed to add entry (nid=" + std::to_string(nid) + ", value=" + value + ") to certificate name");
        }
    }

    /**
     * @brief Add an entry to the certificate name
     * @note If it fails to add the entry, throw an exception of type error::cert_name::RuntimeError
     */
    void add_entry_by_txt(const std::string& field, const std::string& value) {
        const int result = X509_NAME_add_entry_by_txt(
            handle_.get(),
            field.c_str(),
            MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(value.c_str()),
            -1, -1, 0
        );

        if (result != 1) {
           throw error::cert_name::RuntimeError("Failed to add entry (field=" + field + ", value=" + value + ") to certificate name");
        }
    }

    // Legacy method names for compatibility
    void add_entry(int nid, const std::string& value) {
        add_entry_by_nid(nid, value);
    }

    void add_entry(const std::string& field, const std::string& value) {
        add_entry_by_txt(field, value);
    }

    /**
     * @brief Get the number of entries in the certificate name
     * @note If handle is null, return 0
     */
    int entry_count() const noexcept {
        return handle_ ? X509_NAME_entry_count(handle_.get()) : 0;
    }

    /**
     * @brief Find an entry by NID
     * @note If start_pos is -1, start from the beginning
     */
    int find_entry_by_nid(int nid, int start_pos = -1) const noexcept {
        return handle_ ? X509_NAME_get_index_by_NID(handle_.get(), nid, start_pos) : -1;
    }

    // Legacy method name
    int find_entry(int nid) const noexcept {
        return find_entry_by_nid(nid);
    }

    /**
     * @brief Get an entry by index
     * @note If index is out of bounds, return nullptr
     */
    X509_NAME_ENTRY* get_entry(int index) const noexcept {
        return handle_ ? X509_NAME_get_entry(handle_.get(), index) : nullptr;
    }

    // Legacy method name
    X509_NAME_ENTRY* entry(int index) const noexcept {
        return get_entry(index);
    }

    /**
     * @brief Get entry value as string
     * @note If entry is not found, return empty string
     */
    std::string get_entry_value(int nid) const {
        if (!handle_) {
            return {};
        }

        const int size = X509_NAME_get_text_by_NID(handle_.get(), nid, nullptr, 0);
        if (size <= 0) {
            return {};
        }

        auto buffer = std::make_unique<char[]>(size + 1);
        X509_NAME_get_text_by_NID(handle_.get(), nid, buffer.get(), size + 1);

        return std::string(buffer.get());
    }

    /**
     * @brief Get entry value into provided buffer
     * @note If buffer is null, return the size of the entry value
     */
    int get_entry_value(int nid, char* buffer, int buffer_size) const noexcept {
        return handle_ ? X509_NAME_get_text_by_NID(handle_.get(), nid, buffer, buffer_size) : -1;
    }

    // Legacy method names
    std::string entry_value(int nid) const {
        return get_entry_value(nid);
    }

    /**
     * @brief Get entry value into provided buffer
     * @note If buffer is null, return the size of the entry value
     */
    int entry_value(int nid, char* buffer, int size) const noexcept {
        return get_entry_value(nid, buffer, size);
    }

    // String representations
    std::string to_string() const {
        if (!handle_) {
            return {};
        }

        constexpr int buffer_size = 512;  // Increased for longer names
        char buffer[buffer_size];
        const char* result = X509_NAME_oneline(handle_.get(), buffer, buffer_size);
        return result ? std::string(result) : std::string{};
    }

    // Legacy method name
    std::string one_line() const {
        return to_string();
    }

    /**
     * @brief Print the certificate name to a BIO
     */
    bool print_ex(BIO* bio, int indent = 0, int flags = XN_FLAG_COMPAT) const noexcept {
        const int result = X509_NAME_print_ex(bio, handle_.get(), indent, flags);
        return result > 0;
    }

    bool print(FILE* stream = stdout) const noexcept {
        auto bio_out = BioWrapper(BIO_new_fp(stream, BIO_NOCLOSE));
        const auto ret = print_ex(bio_out.get());
        return ret;
    }

    // Legacy method name
    bool one_line_print(BIO* bio, int indent = 0) const noexcept {
        return print_ex(bio, indent, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
    }

    // Common field accessors
    std::string country() const { return get_entry_value(NID_countryName); }
    std::string state() const { return get_entry_value(NID_stateOrProvinceName); }
    std::string locality() const { return get_entry_value(NID_localityName); }
    std::string organization() const { return get_entry_value(NID_organizationName); }
    std::string organizational_unit() const { return get_entry_value(NID_organizationalUnitName); }
    std::string common_name() const { return get_entry_value(NID_commonName); }
    std::string email() const { return get_entry_value(NID_pkcs9_emailAddress); }

    // Common field setters
    void set_country(const std::string& value) { add_entry_by_nid(NID_countryName, value); }
    void set_state(const std::string& value) { add_entry_by_nid(NID_stateOrProvinceName, value); }
    void set_locality(const std::string& value) { add_entry_by_nid(NID_localityName, value); }
    void set_organization(const std::string& value) { add_entry_by_nid(NID_organizationName, value); }
    void set_organizational_unit(const std::string& value) { add_entry_by_nid(NID_organizationalUnitName, value); }
    void set_common_name(const std::string& value) { add_entry_by_nid(NID_commonName, value); }
    void set_email(const std::string& value) { add_entry_by_nid(NID_pkcs9_emailAddress, value); }

    // Comparison operators
    friend bool operator==(const CertificateName& lhs, const CertificateName& rhs) {
        // Both null
        if (!lhs.handle_ && !rhs.handle_) {
            return true;
        }
        // One null, one not
        if (!lhs.handle_ || !rhs.handle_) {
            return false;
        }
        // Both valid - compare
        int result = X509_NAME_cmp(lhs.handle_.get(), rhs.handle_.get());

#if OPENSSL_VERSION_NUMBER < 0x30100000L
        /*
         * Bug in OpenSSL < 3.1.0
         *
         * In June 2023, OpenSSL 3.1.0 merged a fix (commit 1cfc919) that updates the comparison
         * logic to properly handle cases where both names are empty. Before this patch, comparing
         * two empty X509_NAME objects returned -2 (error), instead of 0 (equal).
         * Since OpenSSL 3.1.0, X509_NAME_cmp correctly returns 0 when both names are empty.
         *
         * See https://mta.openssl.org/pipermail/openssl-commits/2023-June/039218.html
         */
        if (result == -2) {
            unsigned char* enc1 = nullptr;
            int len1 = i2d_X509_NAME(lhs.handle_.get(), &enc1);
            if (len1 < 0) {
                throw error::cert_name::RuntimeError("Failed to encode lhs certificate name");
            }

            unsigned char* enc2 = nullptr;
            int len2 = i2d_X509_NAME(rhs.handle_.get(), &enc2);
            if (len2 < 0) {
                OPENSSL_free(enc1);
                throw error::cert_name::RuntimeError("Failed to encode rhs certificate name");
            }

            OPENSSL_free(enc1);
            OPENSSL_free(enc2);

            const int EMPTY_DER_SIZE = 2;
            if (len1 == EMPTY_DER_SIZE && len2 == EMPTY_DER_SIZE) {
                // If both are empty, they're equal
                return true;
            } else if (len1 == EMPTY_DER_SIZE || len2 == EMPTY_DER_SIZE) {
                // If one is empty, they're not equal
                return false;
            }
        }
#endif

        // See https://docs.openssl.org/master/man3/X509_NAME_cmp/#return-values
        if (result == -2) {
            throw error::cert_name::RuntimeError("Failed to compare certificate names");
        }

        return result == 0; // 0 means equal, -1 means less than, 1 means greater than
    }

    friend bool operator!=(const CertificateName& lhs, const CertificateName& rhs) {
        return !(lhs == rhs);
    }

    friend bool operator<(const CertificateName& lhs, const CertificateName& rhs) {
        // Handle null cases consistently
        if (!lhs.handle_ && !rhs.handle_) return false;
        if (!lhs.handle_) return true;
        if (!rhs.handle_) return false;

        int result = X509_NAME_cmp(lhs.handle_.get(), rhs.handle_.get());

#if OPENSSL_VERSION_NUMBER < 0x30100000L
        /*
         * Bug in OpenSSL < 3.1.0
         *
         * In June 2023, OpenSSL 3.1.0 merged a fix (commit 1cfc919) that updates the comparison
         * logic to properly handle cases where both names are empty. Before this patch, comparing
         * two empty X509_NAME objects returned -2 (error), instead of 0 (equal).
         * Since OpenSSL 3.1.0, X509_NAME_cmp correctly returns 0 when both names are empty.
         *
         * See https://mta.openssl.org/pipermail/openssl-commits/2023-June/039218.html
         */
        if (result == -2) {
            unsigned char* enc1 = nullptr;
            int len1 = i2d_X509_NAME(lhs.handle_.get(), &enc1);
            if (len1 < 0) {
                throw error::cert_name::RuntimeError("Failed to encode lhs certificate name");
            }

            unsigned char* enc2 = nullptr;
            int len2 = i2d_X509_NAME(rhs.handle_.get(), &enc2);
            if (len2 < 0) {
                throw error::cert_name::RuntimeError("Failed to encode rhs certificate name");
            }

            OPENSSL_free(enc1);
            OPENSSL_free(enc2);

            const int EMPTY_DER_SIZE = 2;
            if (len1 == EMPTY_DER_SIZE && len2 == EMPTY_DER_SIZE) {
                // If both are empty, they're equal
                return false; // lhs < rhs is false
            } else if (len1 == EMPTY_DER_SIZE || len2 == EMPTY_DER_SIZE) {
                // If one is empty, they're not equal
                // If lhs is empty, it's less than rhs, otherwise it's greater
                return len1 == EMPTY_DER_SIZE;
            }
        }
#endif

        // See https://docs.openssl.org/master/man3/X509_NAME_cmp/#return-values
        if (result == -2) {
            throw error::cert_name::RuntimeError("Failed to compare certificate names");
        }

        return result < 0;
    }

protected:
    /**
     * @brief Reset with new handle (takes ownership)
     */
    void reset(X509_NAME* handle = nullptr) {
        handle_.reset(handle);
    }

    friend class Certificate;
    friend class CertificateRequest;
};

// Hash function for use in unordered containers
struct CertificateNameHash {
    std::size_t operator()(const CertificateName& name) const noexcept {
        if (!name) {
            return 0;
        }

        // Use the one-line string representation for hashing
        const std::string str = name.to_string();
        return std::hash<std::string>{}(str);
    }
};

} // namespace sslpkix

// Specialization for std::hash
namespace std {
    template<>
    struct hash<sslpkix::CertificateName> {
        std::size_t operator()(const sslpkix::CertificateName& name) const noexcept {
            return sslpkix::CertificateNameHash{}(name);
        }
    };
}