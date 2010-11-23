#pragma once

#include <cassert>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "sslpkix/iosink.h"
#include "sslpkix/common.h"

namespace sslpkix {

class Key {
public:
	Key() : _key(NULL), _is_extern(false) {
	}
	virtual ~Key() {
		release();
	}
	EVP_PKEY *handle() {
		assert(_key != NULL);
		return _key;
	}
	bool create() {
		release();
		_key = EVP_PKEY_new();
		if (_key == NULL)
			std::cerr << "Failed to create key" << std::endl;
		return _key != NULL;
	}
	bool assign(RSA *rsa) {
		return EVP_PKEY_assign_RSA(_key, rsa) != 0;
	}
	virtual bool load(IoSink& sink UNUSED) {
		return false;
	}
	virtual bool save(IoSink& sink UNUSED) const {
		return false;
	}
protected:
	void release() {
		if (_key != NULL && !_is_extern) {
			EVP_PKEY_free(_key);
			_key = NULL;
		}
		_is_extern = false;
	}
	void set(EVP_PKEY *key) {
		release();
		_key = key;
		_is_extern = true;
	}
	EVP_PKEY *_key;
	bool _is_extern;
	friend class Certificate;
	friend class CertificateRequest;
};

class PrivateKey : public Key {
public:
	PrivateKey() {
	}
	virtual ~PrivateKey() {
	}
	virtual bool load(IoSink& sink, const char *password) {
		release();
		_key = PEM_read_bio_PrivateKey(sink.handle(), NULL, NULL, (void *)password);
		if (_key == NULL)
			std::cerr << "Failed to load private key: " << sink.source() << std::endl;
		return _key != NULL;
	}
	virtual bool save(IoSink& sink) {
		if (_key == NULL)
			return false;
		int ret = PEM_write_bio_PrivateKey(sink.handle(), _key, NULL, NULL, 0, 0, NULL);
		if (ret == 0)
			std::cerr << "Failed to save private key: " << sink.source() << std::endl;
		return ret != 0;
	}
};

} // namespace sslpkix
