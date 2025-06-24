#pragma once

#include <iostream>
#include <memory>
#include <functional>
#include <stdexcept>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include "sslpkix/error.h"
#include "sslpkix/x509/cert.h"

namespace sslpkix {

class CertificateStoreException : public std::runtime_error {
public:
    explicit CertificateStoreException(const std::string& msg)
        : std::runtime_error(msg)
        , _internal_error_string(get_error_string()) {}

    std::string internal_error_string() const {
        return _internal_error_string;
    }

private:
    std::string _internal_error_string;
};

class CertificateStoreContextException : public std::runtime_error {
public:
    explicit CertificateStoreContextException(const std::string& msg)
        : std::runtime_error(msg)
        , _internal_error_string(get_error_string()) {}

    std::string internal_error_string() const {
        return _internal_error_string;
    }

private:
    std::string _internal_error_string;
};

class CertificateVerifierException : public std::runtime_error {
public:
    explicit CertificateVerifierException(const X509_STORE_CTX* ctx, const std::string& msg)
        : std::runtime_error(msg)
        , _internal_error_string(internal_error_string(ctx)) {}

    // Override what()
    const char* what() const noexcept override {
        _msg = std::string(std::runtime_error::what()) + ". Reason: " + _internal_error_string;
        return _msg.c_str();
    }

    std::string internal_error_string() const {
        return _internal_error_string;
    }

    std::string internal_error_string(const X509_STORE_CTX* ctx) const {
        int err = X509_STORE_CTX_get_error(ctx);
        return X509_verify_cert_error_string(err);
    }

private:
    std::string _internal_error_string;
    mutable std::string _msg;
};

class CertificateStore {
public:
    // Custom deleters for OpenSSL X509_STORE
    struct Deleter {
        void operator()(X509_STORE* store) const noexcept {
            if (store) {
                X509_STORE_free(store);
            }
        }
    };

	// More info at http://www.umich.edu/~x509/ssleay/x509_store.html
	using handle_type = X509_STORE;
    using handle_ptr = std::unique_ptr<handle_type, Deleter>;

public:
    CertificateStore() {
        auto new_handle = handle_ptr(X509_STORE_new(), Deleter());
        if (!new_handle) {
            throw CertificateStoreException("Failed to create certificate store");
        }

        // The callback is only needed for more descriptive error messages, etc
        #if 0
        X509_STORE_set_verify_cb_func(new_handle.get(), verify_callback);
        #endif

        _handle = std::move(new_handle);
    }

    // Move constructor and assignment
    CertificateStore(CertificateStore&&) = default;
    CertificateStore& operator=(CertificateStore&&) = default;

    // Explicitly delete copy operations (non-copyable)
    CertificateStore(const CertificateStore&) = delete;
    CertificateStore& operator=(const CertificateStore&) = delete;

    ~CertificateStore() = default;

    handle_type* handle() const noexcept {
        return _handle.get();
    }

    bool is_valid() const noexcept {
        return _handle.get() != nullptr;
    }

    void set_flags(long flags) {
        if (_handle) {
            X509_STORE_set_flags(_handle.get(), flags);
        }
    }

    /*
    // More info at http://www.openssl.org/docs/crypto/X509_VERIFY_PARAM_set_flags.html
    bool set_param(const X509_VERIFY_PARAM* param) {
        if (!_handle) {
            return false;
        }

        // auto param = std::unique_ptr<X509_VERIFY_PARAM, decltype(&X509_VERIFY_PARAM_free)>(nullptr, X509_VERIFY_PARAM_free);
        // if (!param) {
        //     throw CertificateStoreException("Failed to create X509_VERIFY_PARAM");
        // }
        int ret = X509_STORE_set1_param(_handle.get(), param);
        if (ret != 1) {
            throw CertificateStoreException("Failed to set X509_VERIFY_PARAM");
        }
        return true;
    }
    */

    bool add_trusted_cert(Certificate& cert) {
        if (!_handle) {
            return false;
        }

        int ret = X509_STORE_add_cert(_handle.get(), cert.handle());
        return ret != 0;
    }

private:
    handle_ptr _handle;
};

class CertificateStoreContext {
public:
    // Custom deleters for OpenSSL X509_STORE_CTX
    struct Deleter {
        void operator()(X509_STORE_CTX* ctx) const noexcept {
            if (ctx) {
                X509_STORE_CTX_free(ctx);
            }
        }
    };

    // More info at http://www.umich.edu/~x509/ssleay/x509_store_ctx.html
    using handle_type = X509_STORE_CTX;
    using handle_ptr = std::unique_ptr<handle_type, Deleter>;

public:
    CertificateStoreContext() {
        auto new_handle = handle_ptr(X509_STORE_CTX_new(), Deleter());
        if (!new_handle) {
            throw CertificateStoreContextException("Failed to create certificate store context");
        }

        _handle = std::move(new_handle);
    }

    // Move constructor and assignment
    CertificateStoreContext(CertificateStoreContext&&) = default;
    CertificateStoreContext& operator=(CertificateStoreContext&&) = default;

    // Explicitly delete copy operations (non-copyable)
    CertificateStoreContext(const CertificateStoreContext&) = delete;
    CertificateStoreContext& operator=(const CertificateStoreContext&) = delete;

    ~CertificateStoreContext() = default;

    handle_type* handle() const noexcept {
        return _handle.get();
    }

    bool is_valid() const noexcept {
        return _handle.get() != nullptr;
    }

private:
    handle_ptr _handle;
};

class CertificateVerifier {
public:
    // More info: http://www.openssl.org/docs/apps/verify.html#VERIFY_OPERATION
    bool verify(
        const CertificateStore& store,
        const CertificateStoreContext& ctx,
        Certificate& cert,
        [[maybe_unused]] unsigned long flags = 0,
        int purpose = -1)
    {
        if (!store.is_valid() || !ctx.is_valid()) {
            throw CertificateVerifierException(ctx.handle(), "Invalid store or context");
        }

        auto* pctx = ctx.handle();
        int ret = X509_STORE_CTX_init(pctx, store.handle(), nullptr, nullptr);
        if (!ret) {
            throw CertificateVerifierException(ctx.handle(), "Failed to initialize certificate store context");
        }

        // TODO(jweyrich): Would be good to integrate this with CertificateStoreContext's X509_STORE_CTX deleter,
        // or at least have an off-the-shelf RAII wrapper for X509_STORE_CTX_cleanup.
        auto cleanup_guard = std::unique_ptr<X509_STORE_CTX, std::function<void(X509_STORE_CTX*)>>(pctx, [](X509_STORE_CTX* ctx) {
            if (ctx) {
                X509_STORE_CTX_cleanup(ctx);
            }
        });

        if (purpose >= 0) {
            X509_STORE_CTX_set_purpose(pctx, purpose);
        }

        // Set the certificate to be checked
        X509_STORE_CTX_set_cert(pctx, cert.handle());

        // Check the certificate
        ret = X509_verify_cert(pctx);
        if (ret != 1) {
            throw CertificateVerifierException(ctx.handle(), "Certificate verification failed");
        }

        return ret == 1;
    }
};

} // namespace sslpkix