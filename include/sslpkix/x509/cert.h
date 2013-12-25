#pragma once

//#include <cassert>
#include <iostream>
#include <openssl/x509v3.h>
#include "sslpkix/x509/digest.h"
#include "sslpkix/x509/key.h"
#include "sslpkix/x509/cert_name.h"

namespace sslpkix {

class Certificate {
public:
	typedef X509 handle_type;
	struct Version {
		enum EnumType {
			v2 = 2,
			v3 = 3,
			invalid = -1
		};
	};
public:
	Certificate()
		: _handle(NULL)
		, _version(Version::invalid)
		, _serial(0)
	{
	}
	Certificate(const Certificate& other)
		: _handle(NULL)
		, _version(Version::invalid)
		, _serial(0)
	{
		_handle = X509_dup(other.handle());
		if (_handle == NULL) {
			// std::cerr << "Failed to copy certificate" << std::endl;
			throw std::bad_alloc();
		}
		reload_data();
	}
	Certificate& operator=(Certificate other) {
		release();
		swap(*this, other);
		return *this;
	}
	friend void swap(Certificate& a, Certificate& b) { // nothrow
		using std::swap; // enable ADL
		swap(a._handle, b._handle);
		swap(a._version, b._version);
		swap(a._serial, b._serial);
		swap(a._pubkey, b._pubkey);
		swap(a._subject, b._subject);
		swap(a._issuer, b._issuer);
	}
	virtual ~Certificate() {
		release();
	}
	handle_type *handle() const {
		//assert(_handle != NULL);
		return _handle;
	}
	bool create() {
		release();
		_handle = X509_new();
		if (_handle == NULL) {
			std::cerr << "Failed to create certificate" << std::endl;
			return false;
		}
		reload_data();
		return true;
	}
	bool set_version(Version::EnumType version) {
		int ret = X509_set_version(_handle, static_cast<long>(version));
		if (ret == 0) {
			std::cerr << "Failed to set version" << std::endl;
			return false;
		}
		_version = version;
		return true;
	}
	Version::EnumType version() const {
		return _version;
	}
	bool set_serial(long serial) {
		ASN1_INTEGER_set(X509_get_serialNumber(_handle), serial);
		_serial = serial;
		return true;
	}
	long serial() const {
		return _serial;
	}
	bool set_valid_since(int days) {
		X509_gmtime_adj(X509_get_notBefore(_handle), (long)60 * 60 * 24 * days);
		return true;
	}
	bool set_valid_until(int days) {
		X509_gmtime_adj(X509_get_notAfter(_handle), (long)60 * 60 * 24 * days);
		return true;
	}
	bool set_pubkey(Key& key) {
		int ret = X509_set_pubkey(_handle, key.handle());
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
	bool sign(PrivateKey& key, Digest::type_e digest = Digest::TYPE_SHA1) {
		if (!X509_sign(_handle, key.handle(), Digest::handle(digest))) {
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
		X509V3_set_ctx(&ctx, _handle, _handle, NULL, NULL, 0);
		X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char *)value);
		if (ext == NULL) {
			std::cerr << "Failed to add extension: " << nid << std::endl;
			return false;
		}
		X509_add_ext(_handle, ext, -1);
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
		X509V3_set_ctx(&ctx, _handle, _handle, NULL, NULL, 0);
		X509_add_ext(_handle, ext, -1);
		return true;
	}
	bool set_subject(CertificateName& subject) {
		X509_set_subject_name(_handle, subject.handle());
		_subject.set_handle(X509_get_subject_name(_handle));
		return true;
	}
	CertificateName& subject() {
		return _subject;
	}
	bool set_issuer(CertificateName& issuer) {
		X509_set_issuer_name(_handle, issuer.handle());
		_issuer.set_handle(X509_get_issuer_name(_handle));
		return true;
	}
	CertificateName& issuer() {
		return _issuer;
	}
	bool verify_signature(Key& key) const {
		int ret = X509_verify(_handle, key.handle());
		return ret != 0;
	}
	bool check_private_key(PrivateKey& key) const {
		int ret = X509_check_private_key(_handle, key.handle());
		return ret != 0;
	}
	virtual bool load(IoSink& sink) {
		release();
		_handle = PEM_read_bio_X509(sink.handle(), NULL, NULL, NULL);
		if (_handle == NULL) {
			std::cerr << "Failed to load certificate: " << sink.source() << std::endl;
			return false;
		}
		reload_data();
		return true;
	}
	virtual bool save(IoSink& sink) const {
		if (_handle == NULL)
			return false;
		if (!X509_print(sink.handle(), _handle) || !PEM_write_bio_X509(sink.handle(), _handle)) {
			std::cerr << "Failed to save certificate: " << sink.source() << std::endl;
			return false;
		}
		return true;
	}
	friend bool operator==(const Certificate& lhs, const Certificate& rhs) {
		return X509_cmp(lhs._handle, rhs._handle) == 0 &&
			lhs._subject == rhs._subject &&
			lhs._issuer == rhs._issuer;
	}
	friend bool operator!=(const Certificate& lhs, const Certificate& rhs) {
		return !(lhs == rhs);
	}
protected:
	void release() {
		if (_handle != NULL) {
			X509_free(_handle);
			_handle = NULL;
		}
	}
	void reload_data() {
		_version = static_cast<Version::EnumType>(X509_get_version(_handle));
		_serial = ASN1_INTEGER_get(X509_get_serialNumber(_handle));
		// TODO(jweyrich): Find a better way to give these warnings to the user.
		switch (_serial) {
			//case 0: std::cerr << "The certificate serial is possibly NULL." << std::endl; break;
			case 0xffffffffL: std::cerr << "The certificate serial is too large to fit in a long." << std::endl; break;
		}
		_pubkey.set_handle(X509_get_pubkey(_handle));
		_subject.set_handle(X509_get_subject_name(_handle));
		_issuer.set_handle(X509_get_issuer_name(_handle));
	}
protected:
	handle_type *_handle;
	Version::EnumType _version;
	long _serial;
	Key _pubkey;
	CertificateName _subject;
	CertificateName _issuer;
};

} // namespace sslpkix
