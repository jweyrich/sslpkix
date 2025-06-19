#include <catch2/catch_test_macros.hpp>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include "sslpkix/sslpkix.h"

static int prime_generation_callback(int p, int n, BN_GENCB *arg) {
	(void)n;
	(void)arg;
	char c;
	switch (p) {
		default: c = 'B'; break;
		case 0: c = '.'; break;
		case 1: c = '+'; break;
		case 2: c = '*'; break;
		case 3: c = '\n'; break;
	}
	fputc(c, stderr);
	return 1;
}

struct TestFixture {
	sslpkix::CertificateName issuer;
	sslpkix::CertificateName name;
	sslpkix::PrivateKey key;
	sslpkix::Certificate cert;
	std::string key_data;
	std::string cert_data;

	TestFixture() {
		setup_issuer();
		setup_name();
		setup_key();
		setup_certificate();
	}

private:
	void setup_issuer() {
		REQUIRE_NOTHROW(issuer.set_common_name("janeroe.example.com"));
		REQUIRE_NOTHROW(issuer.set_email("jane.roe@example.com"));
		REQUIRE_NOTHROW(issuer.set_country("US"));
		REQUIRE_NOTHROW(issuer.set_state("CA"));
		REQUIRE_NOTHROW(issuer.set_locality("Palo Alto"));
		REQUIRE_NOTHROW(issuer.set_organization("Jane Roe's CA Pty."));
	}

	void setup_name() {
		REQUIRE_NOTHROW(name.set_common_name("johndoe.example.com"));
		REQUIRE_NOTHROW(name.set_email("john.doe@example.com"));
		REQUIRE_NOTHROW(name.set_country("BR"));
		REQUIRE_NOTHROW(name.set_state("RS"));
		REQUIRE_NOTHROW(name.set_locality("Porto Alegre"));
		REQUIRE_NOTHROW(name.set_organization("John Doe's Company Pty."));
	}

	void setup_key() {
		REQUIRE(key.create());
		RSA *rsa_keypair = RSA_new();
		REQUIRE(rsa_keypair != nullptr);
		BIGNUM *f4 = BN_new();
		REQUIRE(f4 != nullptr);
		REQUIRE(BN_set_word(f4, RSA_F4) == 1); // Use the fourth Fermat Number

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		BN_GENCB *cb = BN_GENCB_new();
		REQUIRE(cb != nullptr);
#else
		BN_GENCB autocb;
		BN_GENCB *cb = &autocb;
#endif
		BN_GENCB_set(cb, prime_generation_callback, nullptr);
		REQUIRE(RSA_generate_key_ex(rsa_keypair, 1024, f4, cb) == 1);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		BN_GENCB_free(cb);
#endif

		REQUIRE(key.copy(rsa_keypair));
		BN_free(f4);
		RSA_free(rsa_keypair);

		// Save key data to memory
		sslpkix::MemorySink key_sink;
		REQUIRE(key_sink.open_rw());
		REQUIRE(key.save(key_sink));
		key_data = key_sink.read_all();
	}

	void setup_certificate() {
		REQUIRE(cert.create());
		REQUIRE(cert.set_version(sslpkix::Certificate::Version::v3));
		REQUIRE(cert.set_pubkey(key));
		REQUIRE(cert.set_serial(31337L)); // Hardcoded serial - Never do this in production!
		REQUIRE(cert.set_issuer(issuer));
		REQUIRE(cert.set_subject(name));
		REQUIRE(cert.set_valid_since(0));
		REQUIRE(cert.set_valid_until(5)); // Valid for 5 days from now
		REQUIRE(cert.sign(key));

		// Save certificate data to memory
		sslpkix::MemorySink cert_sink;
		REQUIRE(cert_sink.open_rw());
		REQUIRE(cert.save(cert_sink));
		cert_data = cert_sink.read_all();
	}
};

TEST_CASE_METHOD(TestFixture, "Certificate creation", "[certificate][creation]")
{
	// Verify the certificate was created properly
	REQUIRE(cert_data.size() > 0);
	REQUIRE(key_data.size() > 0);

	// Test copy constructor
	sslpkix::Certificate certCopy1(cert);
	REQUIRE(certCopy1 == cert);

	// Test assignment operator
	sslpkix::Certificate certCopy2;
	certCopy2 = cert;
	REQUIRE(certCopy2 == cert);
}

TEST_CASE_METHOD(TestFixture, "IoSink operators", "[iosink][operators]")
{
	// Test reading certificate data from memory
	sslpkix::MemorySink cert_mem_read;
	REQUIRE(cert_mem_read.open_ro(cert_data.c_str(), cert_data.size()));
	std::string cert_string;
	cert_mem_read >> cert_string; // IoSink to std::string
	REQUIRE(cert_string == cert_data);

	std::stringstream sstream;

	// Test writing to memory sink
	sslpkix::MemorySink cert_mem_write;
	REQUIRE(cert_mem_write.open_rw());
	cert_mem_write << cert_string; // std::string to IoSink
	sstream << cert_mem_write; // IoSink to std::stringstream
	REQUIRE(sstream.str() == cert_string);

	// Reset the stringstream
	sstream.str(std::string());

	// Test with key data
	sslpkix::MemorySink key_mem_read;
	REQUIRE(key_mem_read.open_ro(key_data.c_str(), key_data.size()));
	std::string key_string;
	key_mem_read >> key_string; // IoSink to std::string
	REQUIRE(key_string == key_data);

	// Test stringstream operations
	std::stringstream key_sstream;
	key_sstream << key_data;
	sslpkix::MemorySink key_mem_write;
	REQUIRE(key_mem_write.open_rw());
	key_sstream >> key_mem_write; // std::istream to IoSink

	std::string key_string_roundtrip;
	key_mem_write >> key_string_roundtrip; // IoSink to std::string
	REQUIRE(key_string_roundtrip == key_data);
}

TEST_CASE("CertificateName entries", "[certificate_name][entries]")
{
	sslpkix::CertificateName name;

	REQUIRE_NOTHROW(name.set_common_name("John Doe"));
	REQUIRE(name.common_name() == "John Doe");

	REQUIRE_NOTHROW(name.set_country("BR"));
	REQUIRE(name.country() == "BR");

	REQUIRE_NOTHROW(name.set_email("john.doe@example.com"));
	REQUIRE(name.email() == "john.doe@example.com");

	REQUIRE_NOTHROW(name.set_locality("Sao Paulo"));
	REQUIRE(name.locality() == "Sao Paulo");

	REQUIRE_NOTHROW(name.set_organization("Independent"));
	REQUIRE(name.organization() == "Independent");

	REQUIRE_NOTHROW(name.set_state("SP"));
	REQUIRE(name.state() == "SP");
}

TEST_CASE("RSA key generation", "[key][generation][rsa]")
{
	sslpkix::PrivateKey key;
	REQUIRE(key.create());
	RSA *rsa_keypair = RSA_new();
	REQUIRE(rsa_keypair != nullptr);
	BIGNUM *f4 = BN_new();
	REQUIRE(f4 != nullptr);
	REQUIRE(BN_set_word(f4, RSA_F4) == 1); // Use the fourth Fermat Number

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	BN_GENCB *cb = BN_GENCB_new();
	REQUIRE(cb != nullptr);
#else
	BN_GENCB autocb;
	BN_GENCB *cb = &autocb;
#endif
	BN_GENCB_set(cb, prime_generation_callback, nullptr);
	REQUIRE(RSA_generate_key_ex(rsa_keypair, 512, f4, cb) == 1);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	BN_GENCB_free(cb);
#endif

	REQUIRE(key.copy(rsa_keypair));
	BN_free(f4);
	RSA_free(rsa_keypair);

	// Test copy constructor
	sslpkix::PrivateKey keyCopy1(key);
	REQUIRE(keyCopy1 == key);
}
