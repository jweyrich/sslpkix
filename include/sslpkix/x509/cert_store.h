#pragma once

#include <iostream>
#include <memory>
#include <functional>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include "sslpkix/x509/cert.h"

namespace sslpkix {

class CertificateStore {
public:
	// More info at http://www.umich.edu/~x509/ssleay/x509_store.html
	using handle_type = X509_STORE;

    // Custom deleters for OpenSSL X509_STORE
    struct Deleter {
        void operator()(X509_STORE* store) const noexcept {
            if (store) {
                X509_STORE_free(store);
            }
        }
    };

    using unique_handle = std::unique_ptr<handle_type, Deleter>;

public:
    CertificateStore() = default;

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
        return _handle != nullptr;
    }

    bool create() {
        auto new_handle = unique_handle(X509_STORE_new());
        if (!new_handle) {
            std::cerr << "Failed to create certificate store\n";
            return false;
        }

        // The callback is only needed for more descriptive error messages, etc
        #if 0
        X509_STORE_set_verify_cb_func(new_handle.get(), verify_callback);
        #endif

        _handle = std::move(new_handle);
        return true;
    }

    void set_flags(long flags) {
        if (_handle) {
            X509_STORE_set_flags(_handle.get(), flags);
        }
    }

    /*
    // More info at http://www.openssl.org/docs/crypto/X509_VERIFY_PARAM_set_flags.html
    bool set_param() {
        if (!_handle) return false;

        auto vpm = std::unique_ptr<X509_VERIFY_PARAM,
                                   decltype(&X509_VERIFY_PARAM_free)>(
            nullptr, X509_VERIFY_PARAM_free);

        if (vpm) {
            X509_STORE_set1_param(_handle.get(), vpm.get());
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

    void reset() {
        _handle.reset();
    }

private:
    unique_handle _handle;
};

class CertificateStoreContext {
public:
	// More info at http://www.umich.edu/~x509/ssleay/x509_store_ctx.html
	using handle_type = X509_STORE_CTX;

    // Custom deleters for OpenSSL X509_STORE_CTX
    struct Deleter {
        void operator()(X509_STORE_CTX* ctx) const noexcept {
            if (ctx) {
                X509_STORE_CTX_free(ctx);
            }
        }
    };

    using unique_handle = std::unique_ptr<handle_type, Deleter>;

public:
    CertificateStoreContext() = default;

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
        return _handle != nullptr;
    }

    bool create() {
        auto new_handle = unique_handle(X509_STORE_CTX_new());
        if (!new_handle) {
            std::cerr << "Failed to create certificate store context\n";
            return false;
        }

        _handle = std::move(new_handle);
        return true;
    }

    void reset() {
        _handle.reset();
    }

private:
    unique_handle _handle;
};

class CertificateVerifier {
public:
    // More info: http://www.openssl.org/docs/apps/verify.html#VERIFY_OPERATION
    bool verify(
        CertificateStore& store,
        CertificateStoreContext& ctx,
        Certificate& cert,
        [[maybe_unused]] unsigned long flags = 0,
        int purpose = -1)
    {
        if (!store.is_valid() || !ctx.is_valid()) {
            std::cerr << "Invalid store or context\n";
            return false;
        }

        auto* pctx = ctx.handle();
        int ret = X509_STORE_CTX_init(pctx, store.handle(), nullptr, nullptr);
        if (!ret) {
            std::cerr << "Failed to initialize certificate store context\n";
            return false;
        }

        // RAII cleanup helper
        auto cleanup_guard = std::unique_ptr<X509_STORE_CTX,
                                           std::function<void(X509_STORE_CTX*)>>(
            pctx, [](X509_STORE_CTX* ctx) {
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

        if (ret < 0) {
            std::cerr << "Error: " << X509_STORE_CTX_get_error(pctx) << '\n';
        }

        return ret == 1;
    }
};

} // namespace sslpkix