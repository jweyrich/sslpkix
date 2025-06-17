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

    using unique_ptr_type = std::unique_ptr<X509_NAME, Deleter>;

private:
    unique_ptr_type handle_ = unique_ptr_type(nullptr, Deleter{true});

public:
    // Constructors
    CertificateName() = default;

    // Create from existing X509_NAME (takes ownership)
    explicit CertificateName(X509_NAME* handle) : handle_(handle, Deleter{true}) {
        if (!handle_) {
            throw std::invalid_argument("Cannot create CertificateName from null handle");
        }
    }

    // Copy constructor - deep copy
    CertificateName(const CertificateName& other) {
        if (other.handle_) {
            reset(X509_NAME_dup(other.handle_.get()));
            if (!handle_) {
                throw std::runtime_error("Failed to duplicate X509_NAME");
            }
        }
    }

    // Move constructor
    CertificateName(CertificateName&&) noexcept = default;

    // Copy assignment
    CertificateName& operator=(const CertificateName& other) {
        if (this != &other) {
            if (other.handle_) {
                reset(X509_NAME_dup(other.handle_.get()));
                if (!handle_) {
                    throw std::runtime_error("Failed to duplicate X509_NAME");
                }
            } else {
                reset();
            }
        }
        return *this;
    }

    // Move assignment
    CertificateName& operator=(CertificateName&&) noexcept = default;

    bool create() {
        auto* new_handle = X509_NAME_new();
        if (!new_handle) {
            std::cerr << "Failed to create certificate name" << std::endl;
            return false;
        }

        handle_.reset(new_handle);
        return true;
    }

    // Legacy method name for compatibility
    const X509_NAME* handle() const noexcept {
        return handle_.get();
    }

    X509_NAME* handle() noexcept {
        return handle_.get();
    }

    // Check if valid
    explicit operator bool() const noexcept {
        return static_cast<bool>(handle_);
    }

    // Entry management
    bool add_entry_by_nid(int nid, const std::string& value) {
        const int result = X509_NAME_add_entry_by_NID(
            handle_.get(),
            nid,
            MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(value.c_str()),
            -1, -1, 0
        );

        return result == 1;
    }

    bool add_entry_by_txt(const std::string& field, const std::string& value) {
        const int result = X509_NAME_add_entry_by_txt(
            handle_.get(),
            field.c_str(),
            MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(value.c_str()),
            -1, -1, 0
        );

        return result == 1;
    }

    // Legacy method names for compatibility
    bool add_entry(int nid, const std::string& value) {
        return add_entry_by_nid(nid, value);
    }

    bool add_entry(const std::string& field, const std::string& value) {
        return add_entry_by_txt(field, value);
    }

    // Query methods
    int entry_count() const noexcept {
        return handle_ ? X509_NAME_entry_count(handle_.get()) : 0;
    }

    int find_entry_by_nid(int nid, int start_pos = -1) const noexcept {
        return handle_ ? X509_NAME_get_index_by_NID(handle_.get(), nid, start_pos) : -1;
    }

    // Legacy method name
    int find_entry(int nid) const noexcept {
        return find_entry_by_nid(nid);
    }

    X509_NAME_ENTRY* get_entry(int index) const noexcept {
        return handle_ ? X509_NAME_get_entry(handle_.get(), index) : nullptr;
    }

    // Legacy method name
    X509_NAME_ENTRY* entry(int index) const noexcept {
        return get_entry(index);
    }

    // Get entry value as string
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

    // Get entry value into provided buffer
    int get_entry_value(int nid, char* buffer, int buffer_size) const noexcept {
        return handle_ ? X509_NAME_get_text_by_NID(handle_.get(), nid, buffer, buffer_size) : -1;
    }

    // Legacy method names
    std::string entry_value(int nid) const {
        return get_entry_value(nid);
    }

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

    bool print_to_bio(BIO* bio, int indent = 0) const noexcept {
        if (!handle_ || !bio) {
            return false;
        }

        const int result = X509_NAME_print(bio, handle_.get(), indent);
        return result > 0;
    }

    // Legacy method name
    bool one_line_print(BIO* bio, int indent = 0) const noexcept {
        return print_to_bio(bio, indent);
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
    bool set_country(const std::string& value) { return add_entry_by_nid(NID_countryName, value); }
    bool set_state(const std::string& value) { return add_entry_by_nid(NID_stateOrProvinceName, value); }
    bool set_locality(const std::string& value) { return add_entry_by_nid(NID_localityName, value); }
    bool set_organization(const std::string& value) { return add_entry_by_nid(NID_organizationName, value); }
    bool set_organizational_unit(const std::string& value) { return add_entry_by_nid(NID_organizationalUnitName, value); }
    bool set_common_name(const std::string& value) { return add_entry_by_nid(NID_commonName, value); }
    bool set_email(const std::string& value) { return add_entry_by_nid(NID_pkcs9_emailAddress, value); }

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
    // Reset with new handle (takes ownership)
    void reset(X509_NAME* handle = nullptr) {
        handle_.reset(handle);
    }

    // Wrap external handle (does not take ownership)
    void wrap_external(X509_NAME* handle) {
        handle_ = unique_ptr_type(handle, Deleter{false});
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