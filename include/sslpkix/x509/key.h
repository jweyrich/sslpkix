#pragma once

//#include <cassert>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "sslpkix/iosink.h"
#include "sslpkix/common.h"

namespace sslpkix {

class Key {
public:
	typedef EVP_PKEY handle_type;
public:
	Key() : _handle(NULL), _is_extern(false) {
	}
	virtual ~Key() {
		release();
	}
	handle_type *handle() {
		//assert(_handle != NULL);
		return _handle;
	}
	bool create() {
		release();
		_handle = EVP_PKEY_new();
		if (_handle == NULL)
			std::cerr << "Failed to create key" << std::endl;
		return _handle != NULL;
	}
	bool assign(RSA *rsa) {
		return EVP_PKEY_assign_RSA(_handle, rsa) != 0;
	}
	virtual bool load(IoSink& sink UNUSED) {
		return false;
	}
	virtual bool save(IoSink& sink UNUSED) const {
		return false;
	}
	friend bool operator==(const Key& lhs, const Key& rhs);
	friend bool operator!=(const Key& lhs, const Key& rhs);
protected:
	void release() {
		if (_handle != NULL && !_is_extern) {
			EVP_PKEY_free(_handle);
			_handle = NULL;
		}
		_is_extern = false;
	}
	void set(handle_type *handle) {
		release();
		_handle = handle;
		_is_extern = true;
	}
protected:
	handle_type *_handle;
	bool _is_extern;
	friend class Certificate;
	friend class CertificateRequest;
};

bool operator==(const Key& lhs, const Key& rhs) {
	// TODO(jweyrich): do we need EVP_PKEY_cmp_parameters() too?
	return EVP_PKEY_cmp(lhs._handle, rhs._handle) == 1;
}
bool operator!=(const Key& lhs, const Key& rhs) {
	return !(lhs == rhs);
}

class PrivateKey : public Key {
public:
	PrivateKey() {
	}
	virtual ~PrivateKey() {
	}
	virtual bool load(IoSink& sink, const char *password) {
		release();
		_handle = PEM_read_bio_PrivateKey(sink.handle(), NULL, NULL, (void *)password);
		if (_handle == NULL)
			std::cerr << "Failed to load private key: " << sink.source() << std::endl;
		return _handle != NULL;
	}
	virtual bool save(IoSink& sink) {
		if (_handle == NULL)
			return false;
		int ret = PEM_write_bio_PrivateKey(sink.handle(), _handle, NULL, NULL, 0, 0, NULL);
		if (ret == 0)
			std::cerr << "Failed to save private key: " << sink.source() << std::endl;
		return ret != 0;
	}
};

} // namespace sslpkix
