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

/**
 * @brief Cleanup the SSLPKIX library.
 * @note This function is called automatically when the program exits.
 */
void cleanup(void) {
	// TODO(jweyrich): Figure out if we're missing a cleanup to avoid the curent memory leaks.
	// Test using: valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all -s --num-callers=40 ./run_tests
	if (g_provider) {
		OSSL_PROVIDER_unload(g_provider);
		g_provider = nullptr;
	}
	// The OPENSSL_cleanup() function deinitialises OpenSSL (both libcrypto and libssl)
	OPENSSL_cleanup();
}


void initialize(void) {
	uint64_t opts = 0
		| OPENSSL_INIT_ADD_ALL_CIPHERS
		| OPENSSL_INIT_ADD_ALL_DIGESTS
		| OPENSSL_INIT_LOAD_CONFIG
		| OPENSSL_INIT_ENGINE_OPENSSL
		| OPENSSL_INIT_ENGINE_RDRAND
		;
	int init_result = OPENSSL_init_crypto(opts, NULL);
	if (init_result != 1) {
		throw std::runtime_error("Error initializing OpenSSL: " + std::to_string(ERR_get_error()));
	}
	g_provider = OSSL_PROVIDER_load(nullptr, "default");
	if (!g_provider) {
		throw std::runtime_error("Error loading OpenSSL provider: " + std::to_string(ERR_get_error()));
	}

	int atexit_result = atexit(cleanup);
	if (atexit_result != 0) {
		throw std::runtime_error("Error registering cleanup function: " + std::to_string(atexit_result));
	}
}

void seed_prng(void) {
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
		throw std::runtime_error("Error seeding PRNG: not enough data");
	}
}

int add_custom_object(const char *oid, const char *sn, const char *ln, int alias_nid) {
	int nid = OBJ_create(oid, sn, ln);
	if (nid == NID_undef) {
		throw std::runtime_error("Error creating object: " + std::string(oid) + ", " + std::string(sn) + ", " + std::string(ln));
	}
	if (alias_nid != NID_undef) {
		X509V3_EXT_add_alias(nid, alias_nid);
	}
	return nid;
}

} // namespace sslpkix
