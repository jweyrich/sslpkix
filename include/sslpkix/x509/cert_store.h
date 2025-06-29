#pragma once

#include <iostream>
#include <memory>
#include <functional>
#include <stdexcept>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include "sslpkix/exception.h"
#include "sslpkix/x509/cert.h"

namespace sslpkix {

namespace error {
    namespace cert_store {
        using BadAllocError = BadAllocError;
        using RuntimeError = RuntimeError;
    } // cert_store

    namespace cert_store_context {
        using BadAllocError = BadAllocError;
        using RuntimeError = RuntimeError;
    } // cert_store_context

    namespace cert_verifier {
        using InvalidArgumentError = InvalidArgumentError;
        class RuntimeError : public ::sslpkix::error::RuntimeError {
        public:
            explicit RuntimeError(const X509_STORE_CTX* ctx, const std::string& msg)
                : ::sslpkix::error::RuntimeError(msg, make_error_string(ctx))
                {}

        private:
            std::string make_error_string(const X509_STORE_CTX* ctx) const {
                int err = X509_STORE_CTX_get_error(ctx);
                return X509_verify_cert_error_string(err);
            }
        };
    } // cert_verifier
} // namespace error

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
            throw error::cert_store::BadAllocError("Failed to create certificate store");
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

        // auto param = std::unique_ptr<X509_VERIFY_PARAM, decltype(&X509_VERIFY_PARAM_free)>(..., X509_VERIFY_PARAM_free);
        // if (!param) {
        //     throw error::cert_store::BadAllocError("Failed to create new verify parameter");
        // }
        int ret = X509_STORE_set1_param(_handle.get(), param);
        if (ret != 1) {
            throw error::cert_store::RuntimeError("Failed to set verify parameter");
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
                X509_STORE_CTX_cleanup(ctx);
                X509_STORE_CTX_free(ctx);
            }
        }
    };

    // More info at http://www.umich.edu/~x509/ssleay/x509_store_ctx.html
    using handle_type = X509_STORE_CTX;
    using handle_ptr = std::unique_ptr<handle_type, Deleter>;

public:
    CertificateStoreContext(const CertificateStore& store) : _store(store) {
        auto new_handle = handle_ptr(X509_STORE_CTX_new(), Deleter());
        if (!new_handle) {
            throw error::cert_store_context::BadAllocError("Failed to create certificate store context");
        }

        int ret = X509_STORE_CTX_init(new_handle.get(), store.handle(), nullptr, nullptr);
        if (!ret) {
            throw error::cert_store_context::RuntimeError("Failed to initialize certificate store context");
        }

        _handle = std::move(new_handle);
    }

    // Explicitly delete move operations (non-movable)
    CertificateStoreContext(CertificateStoreContext&&) = delete;
    CertificateStoreContext& operator=(CertificateStoreContext&&) = delete;

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

protected:
    const CertificateStore& store() const noexcept {
        return _store;
    }

private:
    handle_ptr _handle;
    const CertificateStore& _store;

    friend class CertificateVerifier;
};

class CertificateVerifier {
public:
    CertificateVerifier() : _store(), _store_ctx(_store) {}

    // Explicitly delete copy operations (non-copyable)
    // More info: http://www.openssl.org/docs/apps/verify.html#VERIFY_OPERATION
    bool verify(
        Certificate& cert,
        [[maybe_unused]] unsigned long flags = 0,
        int purpose = -1)
    {
        const auto& store = _store_ctx.store();
        const auto ctx = _store_ctx.handle();

        if (!store.is_valid() || !ctx) {
            throw error::cert_verifier::InvalidArgumentError("Invalid store or context");
        }

        int ret = X509_STORE_CTX_init(ctx, store.handle(), nullptr, nullptr);
        if (!ret) {
            throw error::cert_verifier::RuntimeError(ctx, "Failed to initialize certificate store context");
        }

        if (purpose >= 0) {
            X509_STORE_CTX_set_purpose(ctx, purpose);
        }

        // Set the certificate to be checked
        X509_STORE_CTX_set_cert(ctx, cert.handle());

        // Check the certificate
        ret = X509_verify_cert(ctx);
        if (ret != 1) {
            throw error::cert_verifier::RuntimeError(ctx, "Certificate verification failed");
        }

        return ret == 1;
    }

    const CertificateStore& store() const noexcept {
        return _store;
    }

    CertificateStore& store() noexcept {
        return _store;
    }

    const CertificateStoreContext& store_ctx() const noexcept {
        return _store_ctx;
    }

    CertificateStoreContext& store_ctx() noexcept {
        return _store_ctx;
    }
private:
    CertificateStore _store;
    CertificateStoreContext _store_ctx;
};

} // namespace sslpkix