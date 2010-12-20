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
	typedef enum {
		TYPE_UNKNOWN = 0,
		#ifndef OPENSSL_NO_RSA
		TYPE_RSA = 1,
		#endif
		#ifndef OPENSSL_NO_DSA
		TYPE_DSA = 2,
		#endif
		#ifndef OPENSSL_NO_DH
		TYPE_DH = 3, // Diffie Hellman
		#endif
		#ifndef OPENSSL_NO_EC
		TYPE_EC = 4,
		#endif
	} type_e;
public:
	Key() : _handle(NULL), _is_external_handle(false) {
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
	type_e type() const {
		int type = EVP_PKEY_type(_handle->type);
		switch (type) {
			#ifndef OPENSSL_NO_RSA
			case EVP_PKEY_RSA: return TYPE_RSA;
			#endif
			#ifndef OPENSSL_NO_DSA
			case EVP_PKEY_DSA: return TYPE_DSA;
			#endif
			#ifndef OPENSSL_NO_DH
			case EVP_PKEY_DH: return TYPE_DH;
			#endif
			#ifndef OPENSSL_NO_EC
			case EVP_PKEY_EC: return TYPE_EC;
			#endif
			default: return TYPE_UNKNOWN;
		}
	}
	#ifndef OPENSSL_NO_RSA
	bool assign(RSA *key) {
		return EVP_PKEY_assign_RSA(_handle, key) != 0;
	}
	bool copy(RSA *key) {
		return EVP_PKEY_set1_RSA(_handle, key) != 0;
	}
	#endif
	#ifndef OPENSSL_NO_DSA
	bool assign(DSA *key) {
		return EVP_PKEY_assign_DSA(_handle, key) != 0;
	}
	bool copy(DSA *key) {
		return EVP_PKEY_set1_DSA(_handle, key) != 0;
	}
	#endif
	#ifndef OPENSSL_NO_DH
	bool assign(DH *key) {
		return EVP_PKEY_assign_DH(_handle, key) != 0;
	}
	bool copy(DH *key) {
		return EVP_PKEY_set1_DH(_handle, key) != 0;
	}
	#endif
	#ifndef OPENSSL_NO_EC
	bool assign(EC_KEY *key) {
		return EVP_PKEY_assign_EC_KEY(_handle, key) != 0;
	}
	bool copy(EC_KEY *key) {
		return EVP_PKEY_set1_EC_KEY(_handle, key) != 0;
	}
	#endif
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
		if (_handle != NULL && !_is_external_handle) {
			EVP_PKEY_free(_handle);
		}
		_handle = NULL;
		_is_external_handle = false;
	}
	void set_handle(handle_type *handle) {
		release();
		_handle = handle;
		_is_external_handle = true;
	}
protected:
	handle_type *_handle;
	bool _is_external_handle;
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
