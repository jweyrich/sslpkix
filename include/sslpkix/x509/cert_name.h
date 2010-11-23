#pragma once

#include <iostream>
#include <string>
#include <openssl/x509.h>

// TODO(jweyrich): implement X509_NAME_dup, X509_NAME_cmp, X509_NAME_hash, X509_NAME_delete_entry

class CertificateName {
	// More info: http://www.umich.edu/~x509/ssleay/x509_name.html
public:
	CertificateName() : _name(NULL), _is_extern(false) {
	}
	~CertificateName() {
		release();
	}
	X509_NAME *handle() {
		assert(_name != NULL);
		return _name;
	}
	bool create() {
		release();
		_name = X509_NAME_new();
		if (_name == NULL)
			std::cerr << "Failed to create certificate name" << std::endl;
		return _name != NULL;
	}
	/*
	bool copy(CertificateName& name) {
		// TODO(jweyrich): update the certificate pointer too? (check by printing the cert afterwards)
		int ret = X509_NAME_set(&_name, name.handle());
		if (ret == 0)
			std::cerr << "Failed to copy certificate name" << std::endl;
		return ret != 0;
	}
	*/
	bool add_entry(int nid, const char *value) {
		int ret = X509_NAME_add_entry_by_NID(_name, nid, MBSTRING_ASC,
			(unsigned char *)value, -1, -1, 0);
		if (ret == 0)
			std::cerr << "Failed to add entry: " << nid << std::endl;
		return ret != 0;
	}
	bool add_entry(const char *field, const char *value) {
		int ret = X509_NAME_add_entry_by_txt(_name, field, MBSTRING_ASC,
			(const unsigned char *)value, -1, -1, 0);
		if (ret == 0)
			std::cerr << "Failed to add entry: " << field << std::endl;
		return ret != 0;
	}
	int entry_count() const {
		return X509_NAME_entry_count(_name);
	}
	int find_entry(int nid) const {
		return X509_NAME_get_index_by_NID(_name, nid, -1);
	}
	X509_NAME_ENTRY *entry(int index) const {
		return X509_NAME_get_entry(_name, index);
	}
	int entry_value(int nid, char *buffer, int size) const {
		return X509_NAME_get_text_by_NID(_name, nid, buffer, size);
	}
	std::string entry_value(int nid) const {
		// TODO(jweyrich): should we use a fixed size to avoid performance penalty?
		int size = X509_NAME_get_text_by_NID(_name, nid, NULL, 0);
		if (size <= 0)
			return "";
		char *buffer = new char[size+1];
		X509_NAME_get_text_by_NID(_name, nid, buffer, size+1);
		std::string result;
		result.assign(buffer);
		delete [] buffer;
		return result;
	}
	std::string one_line() const {
		char buffer[256];
		return X509_NAME_oneline(_name, buffer, 256);
	}
	bool one_line_print(BIO *bio, int indent = 0) const {
		int ret = X509_NAME_print(bio, _name, indent);
		return ret != 0;
	}
	// Common entries
	std::string country() const { return entry_value(NID_countryName); }
	std::string state() const { return entry_value(NID_stateOrProvinceName); }
	std::string locality() const { return entry_value(NID_localityName); }
	std::string organization() const { return entry_value(NID_organizationName); }
	std::string common_name() const { return entry_value(NID_commonName); }
	std::string email() const { return entry_value(NID_pkcs9_emailAddress); }
	bool set_country(const char *value) { return add_entry(NID_countryName, value); }
	bool set_state(const char *value) { return add_entry(NID_stateOrProvinceName, value); }
	bool set_locality(const char *value) { return add_entry(NID_localityName, value); }
	bool set_organization(const char *value) { return add_entry(NID_organizationName, value); }
	bool set_common_name(const char *value) { return add_entry(NID_commonName, value); }
	bool set_email(const char *value) { return add_entry(NID_pkcs9_emailAddress, value); }
protected:
	void release() {
		if (_name != NULL && !_is_extern) {
			X509_NAME_free(_name);
			_name = NULL;
		}
		_is_extern = false;
	}
	void set(X509_NAME *name) {
		release();
		_name = name;
		_is_extern = true;
	}
	X509_NAME *_name;
	bool _is_extern;
	friend class Certificate;
	friend class CertificateRequest;
};
