#include "sslpkix/sslpkix.h"
#include <iostream>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>
#if defined(_WIN32)
#  include <NTSecAPI.h>
#endif

namespace sslpkix {

bool startup(void) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	OpenSSL_add_all_algorithms(); // Add all cipher and digest algorithms
	ERR_load_crypto_strings();
	//ERR_load_OBJ_strings();
#else
	uint64_t opts = 0
		| OPENSSL_INIT_NO_ADD_ALL_CIPHERS
		| OPENSSL_INIT_NO_ADD_ALL_DIGESTS
		| OPENSSL_INIT_LOAD_CONFIG
		| OPENSSL_INIT_ENGINE_OPENSSL
		| OPENSSL_INIT_ENGINE_RDRAND
		;
	OPENSSL_init_crypto(opts, NULL);
#endif
	return true;
}

void shutdown(void) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	X509V3_EXT_cleanup();

	// Quote from the official documentation: OBJ_cleanup() was deprecated in OpenSSL 1.1.0 by OPENSSL_init_crypto(3) and should not be used.
	OBJ_cleanup(); // for any OBJ_create
	ERR_free_strings(); // for ERR_load_crypto_strings
	EVP_cleanup(); // for OpenSSL_add_all_algorithms
	RAND_cleanup();
	CRYPTO_cleanup_all_ex_data();
#else
	// FIXME(jweyrich): Figure out if we're missing a cleanup to avoid the curent memory leaks.
	// Test using: valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all -s --num-callers=40 ./run_tests
	X509V3_EXT_cleanup();
#endif
}

bool seed_prng(void) {
#if defined(_WIN32)
	char buffer[1024];
	// RtlGenRandom is provided by ADVAPI32.DLL on Windows >= XP.
	// Windows's rand_s() internally calls RtlGenRandom.
	// Python's urandom() uses /dev/[u]random on Unix-based systems and CryptGenRandom on Windows systems.
	// Crypto++ uses RtlGenRandom on Windows.
	RtlGenRandom(&buffer, sizeof(buffer));
	RAND_add(buffer, sizeof(buffer), sizeof(buffer));
#elif defined(__linux__)
	// Stick to /dev/urandom on Linux, because /dev/random is blocking :-(
	RAND_load_file("/dev/urandom", 1024);
#else
	RAND_load_file("/dev/random", 1024);
#endif
	int ok = RAND_status();
	if (ok != 1) {
		std::cerr << "Error seeding PRNG: not enough data" << std::endl;
		return false;
	}
	return true;
}

void print_errors(FILE *file) {
	ERR_print_errors_fp(file);
}

bool add_custom_object(const char *oid, const char *sn, const char *ln, int *out_nid) {
	if (out_nid == NULL)
		return false;
	int nid = OBJ_create(oid, sn, ln);
	if (nid == NID_undef) {
		std::cerr << "Error creating object: " << oid << " " << sn << " " << ln << std::endl;
		return false;
	}
	X509V3_EXT_add_alias(nid, NID_netscape_comment);
	*out_nid = nid;
	return true;
}

} // namespace sslpkix
