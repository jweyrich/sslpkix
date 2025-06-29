#pragma once

#include <openssl/bio.h>

namespace sslpkix {

class BioWrapper {
public:
    explicit BioWrapper(BIO *bio) : _bio(bio) {}
    ~BioWrapper() {
        if (_bio != nullptr) {
            BIO_free(_bio);
        }
    }
    BioWrapper(const BioWrapper &) = delete;
    BioWrapper &operator=(const BioWrapper &) = delete;

    [[nodiscard]] BIO *get() const noexcept { return _bio; }
    [[nodiscard]] explicit operator BIO *() const noexcept { return _bio; }
    [[nodiscard]] explicit operator bool() const noexcept { return _bio != nullptr; }

    bool operator==(const BioWrapper &other) const noexcept {
        return _bio == other._bio;
    }

    bool operator==(const BIO* other) const noexcept {
        return _bio == other;
    }

    bool operator!=(const BioWrapper &other) const noexcept {
        return _bio != other._bio;
    }

    bool operator!=(const BIO* other) const noexcept {
        return _bio != other;
    }

private:
    BIO *_bio;
};

} // namespace sslpkix
