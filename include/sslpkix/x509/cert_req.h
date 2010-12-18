#pragma once

//#include <cassert>
#include <iostream>
#include <openssl/x509.h>
#include "sslpkix/x509/key.h"
#include "sslpkix/x509/cert_name.h"

namespace sslpkix {

class CertificateRequest {
public:
	typedef X509_REQ handle_type;
public:
	CertificateRequest() : _handle(NULL) {
	}
	virtual ~CertificateRequest() {
		release();
	}
	handle_type *handle() {
		//assert(_handle != NULL);
		return _handle;
	}
	bool create() {
		release();
		_handle = X509_REQ_new();
		if (_handle == NULL)
			std::cerr << "Failed to create cerificate request" << std::endl;
		return _handle != NULL;
	}
	bool set_version(long version) {
		int ret = X509_REQ_set_version(_handle, version);
		return ret != 0;
	}
	long version() const {
		return X509_REQ_get_version(_handle);
	}
	bool set_pubkey(Key& key) {
		// update local
		_pubkey.set(key.handle());
		// update certificate
		int ret = X509_REQ_set_pubkey(_handle, key.handle());
		if (ret == 0)
			std::cerr << "Failed to set public key" << std::endl;
		return ret != 0;
	}
	Key& pubkey() {
		// update local
		_pubkey.set(X509_REQ_get_pubkey(_handle));
		return _pubkey;
	}
	bool sign(PrivateKey& key) {
		if (!X509_REQ_sign(_handle, key.handle(), EVP_sha1())) {
			std::cerr << "Failed to sign" << std::endl;
			return false;
		}
		return true;
	}
	bool add_extensions(STACK_OF(X509_EXTENSION) *exts) {
		X509_REQ_add_extensions(_handle, exts);
		return true;
	}
	bool set_subject(CertificateName& subject) {
		// update local
		_subject.set(subject.handle());
		// update certificate
		X509_REQ_set_subject_name(_handle, subject.handle());
		return true;
	}
	CertificateName& subject() {
		// update local
		_subject.set(X509_REQ_get_subject_name(_handle));
		return _subject;
	}
	bool verify(PrivateKey& key) {
		int ret = X509_REQ_verify(_handle, key.handle());
		return ret != 0;
	}
	bool check_private_key(PrivateKey& key) {
		int ret = X509_REQ_check_private_key(_handle, key.handle());
		return ret != 0;
	}
	virtual bool load(IoSink& sink) {
		release();
		_handle = PEM_read_bio_X509_REQ(sink.handle(), NULL, NULL, NULL);
		if (_handle == NULL)
			std::cerr << "Failed to load certificate request: " << sink.source() << std::endl;
		return _handle != NULL;
	}
	virtual bool save(IoSink& sink) const {
		if (_handle == NULL)
			return false;
		if (!X509_REQ_print(sink.handle(), _handle) || !PEM_write_bio_X509_REQ(sink.handle(), _handle)) {
			std::cerr << "Failed to save certificate request: " << sink.source() << std::endl;
			return false;
		}
		return true;
	}
protected:
	void release() {
		if (_handle != NULL) {
			X509_REQ_free(_handle);
			_handle = NULL;
		}
	}
protected:
	handle_type *_handle;
	Key _pubkey;
	CertificateName _subject;
};

} // namespace sslpkix
