#include <cstdlib>
#include <iostream>
#include "sslpkix/sslpkix.h"

#define CATCH_CONFIG_RUNNER
#include "catch.hpp"

static void rsa_callback(int p, int n, void *arg) {
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
}

TEST_CASE("certificate/creation/1", "Certificate creation")
{
	//
	// Create issuer
	//

	sslpkix::CertificateName issuer;
	REQUIRE(issuer.create());
	REQUIRE(issuer.set_common_name("janeroe.example.com"));
	REQUIRE(issuer.set_email("jane.roe@example.com"));
	REQUIRE(issuer.set_country("US"));
	REQUIRE(issuer.set_state("CA"));
	REQUIRE(issuer.set_locality("Palo Alto"));
	REQUIRE(issuer.set_organization("Jane Roe's CA Pty."));

	//
	// Create subject
	//

	sslpkix::CertificateName subject;
	REQUIRE(subject.create());
	REQUIRE(subject.set_common_name("johndoe.example.com"));
	REQUIRE(subject.set_email("john.doe@example.com"));
	REQUIRE(subject.set_country("BR"));
	REQUIRE(subject.set_state("RS"));
	REQUIRE(subject.set_locality("Porto Alegre"));
	REQUIRE(subject.set_organization("John Doe's Company Pty."));

	//
	// Add a custom extensions - This is not required.
	//

	int nid;
	const char *oid = "1.2.3.4.5.31";
	const char *short_name = "CTE";
	const char *long_name = "customTextEntry";
	const char *value = "Some value here";
	REQUIRE(sslpkix::add_custom_object(oid, short_name, long_name, &nid));
	REQUIRE(subject.add_entry(short_name, value));
	REQUIRE(subject.entry_value(nid) == value);

	//
	// Generate the key pair
	//

	sslpkix::PrivateKey key;
	REQUIRE(key.create());
	RSA *rsa_keypair = RSA_new();
	REQUIRE(rsa_keypair != NULL);
	BIGNUM *f4 = BN_new();
	REQUIRE(f4 != NULL);
	REQUIRE(BN_set_word(f4, RSA_F4) != 0);
	REQUIRE(RSA_generate_key_ex(rsa_keypair, 1024, f4, NULL) != 0);
	REQUIRE(key.copy(rsa_keypair));
	BN_free(f4);
	f4 = NULL;
	RSA_free(rsa_keypair);
	rsa_keypair = NULL;

	sslpkix::FileSink key_file;
	REQUIRE(key_file.open("JohnDoe.key", "wb"));
	REQUIRE(key.save(key_file));
	key_file.close();

	//
	// Create the certificate
	//

	sslpkix::Certificate cert;
	REQUIRE(cert.create());

	// Adjust version
	REQUIRE(cert.set_version(sslpkix::Certificate::Version::v3));

	// Adjust keys
	REQUIRE(cert.set_pubkey(key));

	// Use a hardcoded serial - Never do this in production code!
	REQUIRE(cert.set_serial(31337L));

	// Adjust issuer and subject
	REQUIRE(cert.set_issuer(issuer));
	REQUIRE(cert.set_subject(subject));

	// Valid for 5 days from now
	REQUIRE(cert.set_valid_since(0));
	REQUIRE(cert.set_valid_until(5));

	// Self-sign this certificate
	REQUIRE(cert.sign(key));

	// Save it
	sslpkix::FileSink cert_file;
	REQUIRE(cert_file.open("JohnDoe.crt", "wb"));
	REQUIRE(cert.save(cert_file));
	cert_file.close();
}

TEST_CASE("iosink/operators", "IoSink operators")
{
	sslpkix::FileSink cert_file;
	REQUIRE(cert_file.open("JohnDoe.crt", "rb"));
	std::string cert_string;
	cert_file >> cert_string; // IoSink to std::string
	//std::cout << cert_string << std::endl;
	cert_file.close();
	// TODO(jweyrich): Test whether operator>> was successful. How?

	std::stringstream sstream;

	sslpkix::MemorySink cert_mem;
	REQUIRE(cert_mem.open_rw());
	cert_mem << cert_string; // std::string to IoSink
	sstream << cert_mem; // IoSink to std::stringstream
	cert_mem.close();
	REQUIRE(sstream.str() == cert_string);

	// Reset the stringstream
	sstream.str(std::string());

	sslpkix::MemorySink key_mem;
	REQUIRE(key_mem.open_rw());
	std::filebuf fbuf;
	fbuf.open("JohnDoe.key", std::ios::in);
	std::istream istream(&fbuf);
	istream >> key_mem; // std::istream to IoSink
	std::string key_string;
	key_mem >> key_string; // IoSink to std::string
	//std::cout << key_string << std::endl;

	istream.clear(); // Clear EOF flag (required before C++11)
	istream.seekg(0); // Rewind the std::iostream
	sstream << istream.rdbuf(); // std::istream to std::stringstream
	//std::cout << sstream.str() << std::endl;

	REQUIRE(sstream.str() == key_string);

	fbuf.close();
	key_mem.close();
}

TEST_CASE("certificate_name/entries", "CertificateName entries")
{
	sslpkix::CertificateName name;
	REQUIRE(name.create());
	REQUIRE(name.set_common_name("John Doe"));
	REQUIRE(name.common_name() == "John Doe");
	REQUIRE(name.set_country("BR"));
	REQUIRE(name.country() == "BR");
	REQUIRE(name.set_email("john.doe@example.com"));
	REQUIRE(name.email() == "john.doe@example.com");
	REQUIRE(name.set_locality("Sao Paulo"));
	REQUIRE(name.locality() == "Sao Paulo");
	REQUIRE(name.set_organization("Independent"));
	REQUIRE(name.organization() == "Independent");
	REQUIRE(name.set_state("SP"));
	REQUIRE(name.state() == "SP");
}

TEST_CASE("key/generation/rsa", "RSA key generation")
{
	sslpkix::PrivateKey key;
	REQUIRE(key.create());
	RSA *rsa_keypair = RSA_new();
	REQUIRE(rsa_keypair != NULL);
	BIGNUM *f4 = BN_new();
	REQUIRE(f4 != NULL);
	REQUIRE(BN_set_word(f4, RSA_F4) != 0);
	REQUIRE(RSA_generate_key_ex(rsa_keypair, 512, f4, NULL) != 0);
	REQUIRE(key.copy(rsa_keypair));
	BN_free(f4);
	f4 = NULL;
	RSA_free(rsa_keypair);
	rsa_keypair = NULL;
}

TEST_CASE("certificate_name/extensions", "CertificateName extension")
{
	int nid;
	const char *oid = "1.2.3.4.5.31";
	const char *short_name = "CTE";
	const char *long_name = "customTextEntry";
	const char *value = "Some value here";

	REQUIRE(sslpkix::add_custom_object(oid, short_name, long_name, &nid));
	sslpkix::CertificateName name;
	REQUIRE(name.create());
	REQUIRE(name.add_entry(short_name, value));
	int index;
	REQUIRE((index = name.find_entry(nid)) != -1);
	REQUIRE(name.entry(index) != NULL);
	REQUIRE(name.entry_count() == 1);
	REQUIRE(name.entry_value(nid) == value);
}

int main(int argc, char *const argv[])
{
	bool success = sslpkix::startup();
	if (!success) {
		std::cerr << "ERROR: Failed to initialize SSLPKIX." << std::endl;
		exit(EXIT_FAILURE);
	}

	int result = Catch::Session().run(argc, argv);

	sslpkix::shutdown();

	return result;
}
