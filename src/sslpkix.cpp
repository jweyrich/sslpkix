#include "sslpkix/sslpkix.h"
#include <iostream>
#include <openssl/err.h>
#include <openssl/rand.h>
#if defined(_WIN32)
#  include <NTSecAPI.h>
#endif

namespace sslpkix {

bool startup(void) {
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	OpenSSL_add_all_algorithms(); // Add all cipher and digest algorithms
	ERR_load_crypto_strings();
	//ERR_load_OBJ_strings();
	return true;
}

void shutdown(void) {
	X509V3_EXT_cleanup();
	OBJ_cleanup(); // for any OBJ_create
	ERR_free_strings(); // for ERR_load_crypto_strings
	EVP_cleanup(); // for OpenSSL_add_all_algorithms
	RAND_cleanup();
	CRYPTO_cleanup_all_ex_data();
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
	return true;
}

void print_errors(FILE *file) {
	ERR_print_errors_fp(file);
}

bool add_custom_object(const char *oid, const char *sn, const char *ln, int *out_nid) {
	if (out_nid == NULL)
		return false;
	int nid = OBJ_create(oid, sn, ln);
	if (nid == 0) {
		std::cerr << "Error creating object: " << oid << " " << sn << " " << ln << std::endl;
		return false;
	}
	X509V3_EXT_add_alias(nid, NID_netscape_comment);
	*out_nid = nid;
	return true;
}

} // namespace sslpkix
