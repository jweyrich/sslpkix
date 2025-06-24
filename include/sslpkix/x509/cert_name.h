#pragma once

#include <iostream>
#include <string>
#include <memory>
#include <stdexcept>
#include <cassert>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include "sslpkix/error.h"

namespace sslpkix {

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
            throw std::bad_alloc();
        }
        reset(new_handle);
    }

    /**
     * @brief Constructor for external handle (does not create new name)
     * @note 1. Does not increment reference count
     * @note 2. Does not take ownership
     */
    explicit CertificateName(X509_NAME* external_handle) : handle_(external_handle, Deleter{false}) {}

    // Copy constructor - deep copy
    CertificateName(const CertificateName& other) {
        if (other.handle_) {
            auto* duplicated = X509_NAME_dup(other.handle_.get());
            if (!duplicated) {
                throw std::runtime_error("Failed to duplicate X509_NAME. Reason: " + get_error_string());
            }
            reset(duplicated);
        } else {
            // If other is empty, create a new empty certificate name
            auto* new_handle = X509_NAME_new();
            if (!new_handle) {
                throw std::bad_alloc();
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
    const X509_NAME* handle() const noexcept {
        return handle_.get();
    }

    X509_NAME* handle() noexcept {
        return handle_.get();
    }

    // Check if certificate name is valid
    bool is_valid() const noexcept {
        return handle_.get() != nullptr;
    }

    // Explicit bool conversion
    explicit operator bool() const noexcept {
        return is_valid();
    }

    /**
     * @brief Add an entry to the certificate name
     * @note If it fails to add the entry, throw an exception of type std::runtime_error
     */
    void add_entry_by_nid(int nid, const std::string& value) {
        if (value.empty()) {
            throw std::invalid_argument("Empty string is not allowed for certificate name entry (nid=" + std::to_string(nid) + ")");
        }

        const int result = X509_NAME_add_entry_by_NID(
            handle_.get(),
            nid,
            MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(value.c_str()),
            -1, -1, 0
        );

        if (result != 1) {
            throw std::runtime_error("Failed to add entry (nid=" + std::to_string(nid) + ", value=" + value + ") to certificate name. Reason: " + get_error_string());
        }
    }

    /**
     * @brief Add an entry to the certificate name
     * @note If it fails to add the entry, throw an exception of type std::runtime_error
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
           throw std::runtime_error("Failed to add entry (field=" + field + ", value=" + value + ") to certificate name. Reason: " + get_error_string());
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
        BIO *bio_out = BIO_new_fp(stream, BIO_NOCLOSE);
        const auto ret = print_ex(bio_out);
        BIO_free(bio_out);
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
    friend bool operator==(const CertificateName& lhs, const CertificateName& rhs) noexcept {
        // Both null
        if (!lhs.handle_ && !rhs.handle_) {
            return true;
        }
        // One null, one not
        if (!lhs.handle_ || !rhs.handle_) {
            return false;
        }
        // Both valid - compare
        return X509_NAME_cmp(lhs.handle_.get(), rhs.handle_.get()) == 0;
    }

    friend bool operator!=(const CertificateName& lhs, const CertificateName& rhs) noexcept {
        return !(lhs == rhs);
    }

    friend bool operator<(const CertificateName& lhs, const CertificateName& rhs) noexcept {
        // Handle null cases consistently
        if (!lhs.handle_ && !rhs.handle_) return false;
        if (!lhs.handle_) return true;
        if (!rhs.handle_) return false;

        return X509_NAME_cmp(lhs.handle_.get(), rhs.handle_.get()) < 0;
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