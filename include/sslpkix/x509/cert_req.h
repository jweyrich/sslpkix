#pragma once

#include <cassert>
#include <iostream>
#include <openssl/x509.h>

class CertificateRequest {
public:
	CertificateRequest() : _req(NULL) {
	}
	virtual ~CertificateRequest() {
		release();
	}
	X509_REQ *handle() {
		assert(_req != NULL);
		return _req;
	}
	bool create() {
		release();
		_req = X509_REQ_new();
		if (_req == NULL)
			std::cerr << "Failed to create cerificate request" << std::endl;
		return _req != NULL;
	}
	bool set_version(long version) {
		int ret = X509_REQ_set_version(_req, version);
		return ret != 0;
	}
	long version() const {
		return X509_REQ_get_version(_req);
	}
	bool set_pubkey(Key& key) {
		// update local
		_pubkey.set(key.handle());
		// update certificate
		int ret = X509_REQ_set_pubkey(_req, key.handle());
		if (ret == 0)
			std::cerr << "Failed to set public key" << std::endl;
		return ret != 0;
	}
	Key& pubkey() {
		// update local
		_pubkey.set(X509_REQ_get_pubkey(_req));
		return _pubkey;
	}
	bool sign(PrivateKey& key) {
		if (!X509_REQ_sign(_req, key.handle(), EVP_sha1())) {
			std::cerr << "Failed to sign" << std::endl;
			return false;
		}
		return true;
	}
	bool add_extensions(STACK_OF(X509_EXTENSION) *exts) {
		X509_REQ_add_extensions(_req, exts);
		return true;
	}
	bool set_subject(CertificateName& subject) {
		// update local
		_subject.set(subject.handle());
		// update certificate
		X509_REQ_set_subject_name(_req, subject.handle());
		return true;
	}
	CertificateName& subject() {
		// update local
		_subject.set(X509_REQ_get_subject_name(_req));
		return _subject;
	}
	bool verify(PrivateKey& key) {
		int ret = X509_REQ_verify(_req, key.handle());
		return ret != 0;
	}
	bool check_private_key(PrivateKey& key) {
		int ret = X509_REQ_check_private_key(_req, key.handle());
		return ret != 0;
	}
	virtual bool load(IoSink& sink) {
		release();
		_req = PEM_read_bio_X509_REQ(sink.handle(), NULL, NULL, NULL);
		if (_req == NULL)
			std::cerr << "Failed to load certificate request: " << sink.source() << std::endl;
		return _req != NULL;
	}
	virtual bool save(IoSink& sink) const {
		if (_req == NULL)
			return false;
		if (!X509_REQ_print(sink.handle(), _req) || !PEM_write_bio_X509_REQ(sink.handle(), _req)) {
			std::cerr << "Failed to save certificate request: " << sink.source() << std::endl;
			return false;
		}
		return true;
	}
protected:
	void release() {
		if (_req != NULL) {
			X509_REQ_free(_req);
			_req = NULL;
		}
	}
	X509_REQ *_req;
	Key _pubkey;
	CertificateName _subject;
};
