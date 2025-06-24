#pragma once

#include <openssl/opensslv.h>
#include <openssl/evp.h>

namespace sslpkix {

class Digest {
public:
	typedef EVP_MD handle_type;
	typedef enum {
		TYPE_NULL = 0,
		# ifndef OPENSSL_NO_MD2
		TYPE_MD2,
		# endif
		# ifndef OPENSSL_NO_MD4
		TYPE_MD4,
		# endif
		# ifndef OPENSSL_NO_MD5
		TYPE_MD5,
		TYPE_MD5_SHA1,
		# endif
		# ifndef OPENSSL_NO_BLAKE2
		TYPE_BLAKE2B512,
		TYPE_BLAKE2S256,
		# endif
		TYPE_SHA1,
		TYPE_SHA224,
		TYPE_SHA256,
		TYPE_SHA384,
		TYPE_SHA512,
		TYPE_SHA512_224,
		TYPE_SHA512_256,
		TYPE_SHA3_224,
		TYPE_SHA3_256,
		TYPE_SHA3_384,
		TYPE_SHA3_512,
		TYPE_SHAKE128,
		TYPE_SHAKE256,
		#ifndef OPENSSL_NO_MDC2
		TYPE_MDC2,
		#endif
		# ifndef OPENSSL_NO_RMD160
		TYPE_RIPEMD160,
		# endif
		# ifndef OPENSSL_NO_WHIRLPOOL
		TYPE_WHIRLPOOL,
		# endif
		# ifndef OPENSSL_NO_SM3
		TYPE_SM3,
		# endif
	} type_e;
public:
	static const handle_type *handle(const char *name) {
		return EVP_get_digestbyname(name);
	}
	static const handle_type *handle(type_e digest) {
		switch (digest) {
			case TYPE_NULL: return EVP_md_null();
			# ifndef OPENSSL_NO_MD2
			case TYPE_MD2: return EVP_md2();
			# endif
			# ifndef OPENSSL_NO_MD4
			case TYPE_MD4: return EVP_md4(); // ok
			# endif
			# ifndef OPENSSL_NO_MD5
			case TYPE_MD5: return EVP_md5();
			case TYPE_MD5_SHA1: return EVP_md5_sha1();
			# endif
			# ifndef OPENSSL_NO_BLAKE2
			case TYPE_BLAKE2B512: return EVP_blake2b512();
			case TYPE_BLAKE2S256: return EVP_blake2s256();
			# endif
			case TYPE_SHA1: return EVP_sha1();
			case TYPE_SHA224: return EVP_sha224();
			case TYPE_SHA256: return EVP_sha256();
			case TYPE_SHA384: return EVP_sha384();
			case TYPE_SHA512: return EVP_sha512();
			case TYPE_SHA512_224: return EVP_sha512_224();
			case TYPE_SHA512_256: return EVP_sha512_256();
			case TYPE_SHA3_224: return EVP_sha3_224();
			case TYPE_SHA3_256: return EVP_sha3_256();
			case TYPE_SHA3_384: return EVP_sha3_384();
			case TYPE_SHA3_512: return EVP_sha3_512();
			case TYPE_SHAKE128: return EVP_shake128();
			case TYPE_SHAKE256: return EVP_shake256();
			# ifndef OPENSSL_NO_MDC2
			case TYPE_MDC2: return EVP_mdc2();
			# endif
			# ifndef OPENSSL_NO_RMD160
			case TYPE_RIPEMD160: return EVP_ripemd160();
			# endif
			# ifndef OPENSSL_NO_WHIRLPOOL
			case TYPE_WHIRLPOOL: return EVP_whirlpool();
			# endif
			# ifndef OPENSSL_NO_SM3
			case TYPE_SM3: return EVP_sm3();
			# endif
			default: return EVP_md_null();
		}
	}
};

} // namespace sslpkix
