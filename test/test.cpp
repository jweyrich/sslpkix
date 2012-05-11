#include <cstdlib>
#include <iostream>
#include "sslpkix/sslpkix.h"
#include "catch_with_main.hpp"

__attribute__((constructor)) static void init() {
	bool success = sslpkix::startup();
	if (!success) {
		std::cerr << "Failed to initialize SSLPKIX." << std::endl;
		exit(EXIT_FAILURE);
	}
}

__attribute__((destructor)) static void term() {
	sslpkix::shutdown();
}

static void rsa_callback(int p, int n, void *arg) {
	(void)n;
	(void)arg;
	char c = 'B';
	if (p == 0) c='.';
	if (p == 1) c='+';
	if (p == 2) c='*';
	if (p == 3) c='\n';
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

TEST_CASE("key/generate/rsa", "RSA key generation")
{
	sslpkix::PrivateKey key;
	REQUIRE(key.create());
	RSA *rsa_key = RSA_generate_key(512, RSA_F4, rsa_callback, NULL);
	REQUIRE(rsa_key != NULL);
	REQUIRE(key.copy(rsa_key));
	RSA_free(rsa_key);
	rsa_key = NULL;
}

// TEST_CASE("certificate_name/extensions", "CertificateName extension tests")
// {
// 	 sslpkix::CertificateName name;
// 	 REQUIRE(name.create());
// 	 REQUIRE(name.add_entry("custom_text_entry", "my_custom_text_entry"));
// 	 //REQUIRE(name.entry("custom_text_entry") == "my_custom_text_entry");
// }
