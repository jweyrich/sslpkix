#include "sslpkix/sslpkix.h"
#include <iostream>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>
#include <openssl/provider.h>
#if defined(_WIN32)
#  include <NTSecAPI.h>
#endif

namespace sslpkix {

static OSSL_PROVIDER* g_provider = nullptr;

bool startup(void) {
	uint64_t opts = 0
		| OPENSSL_INIT_ADD_ALL_CIPHERS
		| OPENSSL_INIT_ADD_ALL_DIGESTS
		| OPENSSL_INIT_LOAD_CONFIG
		| OPENSSL_INIT_ENGINE_OPENSSL
		| OPENSSL_INIT_ENGINE_RDRAND
		;
	int init_result = OPENSSL_init_crypto(opts, NULL);
	if (init_result != 1) {
		std::cerr << "Error initializing OpenSSL: " << ERR_get_error() << std::endl;
		return false;
	}
	g_provider = OSSL_PROVIDER_load(nullptr, "default");
	if (!g_provider) {
		std::cerr << "Error loading OpenSSL provider: " << ERR_get_error() << std::endl;
		return false;
	}
	return true;
}

void shutdown(void) {
	// TODO(jweyrich): Figure out if we're missing a cleanup to avoid the curent memory leaks.
	// Test using: valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all -s --num-callers=40 ./run_tests
	if (g_provider) {
		OSSL_PROVIDER_unload(g_provider);
		g_provider = nullptr;
	}
	OPENSSL_cleanup();
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

bool add_custom_object(const char *oid, const char *sn, const char *ln, int *out_nid) {
	if (out_nid == NULL)
		return false;
	int nid = OBJ_create(oid, sn, ln);
	if (nid == NID_undef) {
		std::cerr << "Error creating object: " << oid << ", " << sn << ", " << ln << std::endl;
		return false;
	}
	X509V3_EXT_add_alias(nid, NID_netscape_comment);
	*out_nid = nid;
	return true;
}

} // namespace sslpkix
