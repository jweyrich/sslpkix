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
	CertificateRequest() : _handle(NULL), _version(0) {
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
		if (_handle == NULL) {
			std::cerr << "Failed to create cerificate request" << std::endl;
			return false;
		}
		reload_data();
		return true;
	}
	bool set_version(long version) {
		int ret = X509_REQ_set_version(_handle, version);
		if (ret == 0) {
			std::cerr << "Failed to set version" << std::endl;
			return false;
		}
		_version = version;
		return true;
	}
	long version() const {
		return _version;
	}
	bool set_pubkey(Key& key) {
		int ret = X509_REQ_set_pubkey(_handle, key.handle());
		if (ret == 0) {
			std::cerr << "Failed to set public key" << std::endl;
			return false;
		}
		_pubkey.set_handle(key.handle());
		return true;
	}
	Key& pubkey() {
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
		X509_REQ_set_subject_name(_handle, subject.handle());
		_subject.set_handle(X509_REQ_get_subject_name(_handle));
		return true;
	}
	CertificateName& subject() {
		return _subject;
	}
	bool verify_signature(Key& key) const {
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
		if (_handle == NULL) {
			std::cerr << "Failed to load certificate request: " << sink.source() << std::endl;
			return false;
		}
		reload_data();
		return true;
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
	void reload_data() {
		_version = X509_REQ_get_version(_handle);
		_pubkey.set_handle(X509_REQ_get_pubkey(_handle));
		_subject.set_handle(X509_REQ_get_subject_name(_handle));
	}
protected:
	handle_type *_handle;
	long _version;
	long _serial;
	Key _pubkey;
	CertificateName _subject;
};

} // namespace sslpkix
