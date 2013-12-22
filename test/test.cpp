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
	RSA *rsa_key = RSA_generate_key(1024, RSA_F4, rsa_callback, NULL);
	REQUIRE(rsa_key != NULL);
	REQUIRE(key.copy(rsa_key));
	RSA_free(rsa_key);
	rsa_key = NULL;

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
	RSA *rsa_key = RSA_generate_key(512, RSA_F4, rsa_callback, NULL);
	REQUIRE(rsa_key != NULL);
	REQUIRE(key.copy(rsa_key));
	RSA_free(rsa_key);
	rsa_key = NULL;
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
