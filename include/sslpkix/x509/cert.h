#pragma once

#include <cassert>
#include <iostream>
#include <openssl/x509v3.h>

class Certificate {
public:
	Certificate() : _cert(NULL) {
	}
	virtual ~Certificate() {
		release();
	}
	X509 *handle() {
		assert(_cert != NULL);
		return _cert;
	}
	bool create() {
		release();
		_cert = X509_new();
		if (_cert == NULL) {
			std::cerr << "Failed to create certificate" << std::endl;
		} else {
			_subject.set(X509_get_subject_name(_cert));
			_issuer.set(X509_get_issuer_name(_cert));
		}
		return _cert != NULL;
	}
	bool set_version(long version) {
		int ret = X509_set_version(_cert, version);
		return ret != 0;
	}
	long version() const {
		return X509_get_version(_cert);
	}
	bool set_serial(long serial) {
		ASN1_INTEGER_set(X509_get_serialNumber(_cert), serial);
		return true;
	}
	long serial() const {
		return ASN1_INTEGER_get(X509_get_serialNumber(_cert));
	}
	bool set_valid_since(int days) {
		X509_gmtime_adj(X509_get_notBefore(_cert), (long)60 * 60 * 24 * days);
		return true;
	}
	bool set_valid_until(int days) {
		X509_gmtime_adj(X509_get_notAfter(_cert), (long)60 * 60 * 24 * days);
		return true;
	}
	bool set_pubkey(Key& key) {
		// update local
		_pubkey.set(key.handle());
		// update certificate
		int ret = X509_set_pubkey(_cert, key.handle());
		if (ret == 0) {
			std::cerr << "Failed to set public key" << std::endl;
			return false;
		}
		_subject.set(X509_get_subject_name(_cert));
		_issuer.set(X509_get_issuer_name(_cert));
		return true;
	}
	Key& pubkey() {
		// update local
		_pubkey.set(X509_get_pubkey(_cert));
		return _pubkey;
	}
	bool sign(PrivateKey& key) {
		if (!X509_sign(_cert, key.handle(), EVP_sha1())) {
			std::cerr << "Failed to sign" << std::endl;
			return false;
		}
		return true;
	}
	bool add_extension(int nid, const char *value) {
		X509V3_CTX ctx;
		// This sets the 'context' of the extensions.
		// No configuration database
		X509V3_set_ctx_nodb(&ctx);
		// Issuer and subject certs: both the target since it is self signed,
		// no request and no CRL
		X509V3_set_ctx(&ctx, _cert, _cert, NULL, NULL, 0);
		X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char *)value);
		if (ext == NULL) {
			std::cerr << "Failed to add extension: " << nid << std::endl;
			return false;
		}
		X509_add_ext(_cert, ext, -1);
		X509_EXTENSION_free(ext);
		return true;
	}
	bool add_extension(X509_EXTENSION *ext) {
		if (ext == NULL)
			return false;
		X509V3_CTX ctx;
		// This sets the 'context' of the extensions.
		// No configuration database
		X509V3_set_ctx_nodb(&ctx);
		// Issuer and subject certs: both the target since it is self signed,
		// no request and no CRL
		X509V3_set_ctx(&ctx, _cert, _cert, NULL, NULL, 0);
		X509_add_ext(_cert, ext, -1);
		return true;
	}
	bool set_subject(CertificateName& subject) {
		// update certificate
		X509_set_subject_name(_cert, subject.handle());
		// update local
		_subject.set(X509_get_subject_name(_cert));
		return true;
	}
	CertificateName& subject() {
		return _subject;
	}
	bool set_issuer(CertificateName& issuer) {
		// update certificate
		X509_set_issuer_name(_cert, issuer.handle());
		// update local
		_issuer.set(X509_get_issuer_name(_cert));
		return true;
	}
	CertificateName& issuer() {
		return _issuer;
	}
	bool verify(PrivateKey& key) { // TODO(jweyrich): should be a const method?
		int ret = X509_verify(_cert, key.handle());
		return ret != 0;
	}
	bool check_private_key(PrivateKey& key) { // TODO(jweyrich): should be a const method?
		int ret = X509_check_private_key(_cert, key.handle());
		return ret != 0;
	}
	virtual bool load(IoSink& sink) {
		release();
		_cert = PEM_read_bio_X509(sink.handle(), NULL, NULL, NULL);
		if (_cert == NULL) {
			std::cerr << "Failed to load certificate: " << sink.source() << std::endl;
			return false;
		}
		_subject.set(X509_get_subject_name(_cert));
		_issuer.set(X509_get_issuer_name(_cert));
		return true;
	}
	virtual bool save(IoSink& sink) const {
		if (_cert == NULL)
			return false;
		if (!X509_print(sink.handle(), _cert) || !PEM_write_bio_X509(sink.handle(), _cert)) {
			std::cerr << "Failed to save certificate: " << sink.source() << std::endl;
			return false;
		}
		return true;
	}
protected:
	void release() {
		if (_cert != NULL) {
			X509_free(_cert);
			_cert = NULL;
		}
	}
	X509 *_cert;
	Key _pubkey;
	CertificateName _subject;
	CertificateName _issuer;
};
