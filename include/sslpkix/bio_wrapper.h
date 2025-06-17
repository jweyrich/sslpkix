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
    BIO *get() const { return _bio; }
    BioWrapper(const BioWrapper &) = delete;
    BioWrapper &operator=(const BioWrapper &) = delete;

private:
    BIO *_bio;
};

} // namespace sslpkix
