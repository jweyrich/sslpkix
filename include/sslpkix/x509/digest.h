#pragma once

#include <openssl/evp.h>

namespace sslpkix {

class Digest {
public:
	typedef EVP_MD handle_type;
	typedef enum {
		#ifndef OPENSSL_NO_MD2
		TYPE_MD2 = 1,
		#endif
		#ifndef OPENSSL_NO_MD4
		TYPE_MD4 = 2,
		#endif
		#ifndef OPENSSL_NO_MD5
		TYPE_MD5 = 3,
		#endif
		#ifndef OPENSSL_NO_SHA
		TYPE_SHA = 4,
		TYPE_SHA1 = 5,
		TYPE_DSS = 6,
		TYPE_DSS1 = 7,
		TYPE_ECDSA = 8,
		#endif
		#ifndef OPENSSL_NO_SHA256
		TYPE_SHA224 = 9,
		TYPE_SHA256 = 10,
		#endif
		#ifndef OPENSSL_NO_SHA512
		TYPE_SHA384 = 11,
		TYPE_SHA512 = 12,
		#endif
		#ifndef OPENSSL_NO_MDC2
		TYPE_MDC2 = 13,
		#endif
		#ifndef OPENSSL_NO_RIPEMD
		TYPE_RIPEMD160 = 14,
		#endif
		TYPE_NULL = 0
	} type_e;
public:
	static const handle_type *get(const char *name) {
		return EVP_get_digestbyname(name);
	}
	static const handle_type *get(type_e digest) {
		switch (digest) {
			case TYPE_NULL: return EVP_md_null();
			#ifndef OPENSSL_NO_MD2
			case TYPE_MD2: return EVP_md2();
			#endif
			#ifndef OPENSSL_NO_MD4
			case TYPE_MD4: return EVP_md4();
			#endif
			#ifndef OPENSSL_NO_MD5
			case TYPE_MD5: return EVP_md5();
			#endif
			#ifndef OPENSSL_NO_SHA
			case TYPE_SHA: return EVP_sha();
			case TYPE_SHA1: return EVP_sha1();
			case TYPE_DSS: return EVP_dss();
			case TYPE_DSS1: return EVP_dss1();
			case TYPE_ECDSA: return EVP_ecdsa();
			#endif
			#ifndef OPENSSL_NO_SHA256
			case TYPE_SHA224: return EVP_sha224();
			case TYPE_SHA256: return EVP_sha256();
			#endif
			#ifndef OPENSSL_NO_SHA512
			case TYPE_SHA384: return EVP_sha384();
			case TYPE_SHA512: return EVP_sha512();
			#endif
			#ifndef OPENSSL_NO_MDC2
			case TYPE_MDC2: return EVP_mdc2();
			#endif
			#ifndef OPENSSL_NO_RIPEMD
			case TYPE_RIPEMD160: return EVP_ripemd160();
			#endif
			default: return EVP_md_null();
		}
	}
};

} // namespace sslpkix
