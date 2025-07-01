#include <catch2/catch_test_macros.hpp>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include "sslpkix/sslpkix.h"

struct TestObjects {
	std::unique_ptr<sslpkix::CertificateName> subject;
	std::unique_ptr<sslpkix::CertificateName> issuer;

	std::unique_ptr<sslpkix::PrivateKey> private_key;
	std::unique_ptr<sslpkix::Key> public_key;
	std::unique_ptr<sslpkix::Certificate> cert;
};

struct TestFixture {
	TestFixture() = default;
	~TestFixture() = default;
	TestFixture(const TestFixture&) = delete;
	TestFixture& operator=(const TestFixture&) = delete;
	TestFixture(TestFixture&&) = delete;
	TestFixture& operator=(TestFixture&&) = delete;

protected:
	TestObjects make_test_objects(bool is_self_signed = false) {
		auto issuer = create_issuer();
		auto subject = is_self_signed ? create_issuer() : create_subject();
		auto keypair = sslpkix::factory::generate_key_rsa(512);
		auto private_key = std::make_unique<sslpkix::PrivateKey>(keypair);
		auto public_key = private_key->pubkey();
		auto cert = create_certificate(*subject, *issuer, *public_key);
		sign_certificate(*cert, *private_key);

		return {
			.subject = std::move(subject),
			.issuer = std::move(issuer),
			.private_key = std::move(private_key),
			.public_key = std::move(public_key),
			.cert = std::move(cert),
		};
	}

	std::unique_ptr<sslpkix::CertificateName> create_issuer() {
		auto name = std::make_unique<sslpkix::CertificateName>();

		REQUIRE_NOTHROW(name->set_common_name("janeroe.example.com"));
		REQUIRE_NOTHROW(name->set_email("jane.roe@example.com"));
		REQUIRE_NOTHROW(name->set_country("US"));
		REQUIRE_NOTHROW(name->set_state("CA"));
		REQUIRE_NOTHROW(name->set_locality("Palo Alto"));
		REQUIRE_NOTHROW(name->set_organization("Jane Roe's CA Pty."));

		return name;
	}

	std::unique_ptr<sslpkix::CertificateName> create_subject() {
		auto name = std::make_unique<sslpkix::CertificateName>();

		REQUIRE_NOTHROW(name->set_common_name("johndoe.example.com"));
		REQUIRE_NOTHROW(name->set_email("john.doe@example.com"));
		REQUIRE_NOTHROW(name->set_country("BR"));
		REQUIRE_NOTHROW(name->set_state("RS"));
		REQUIRE_NOTHROW(name->set_locality("Porto Alegre"));
		REQUIRE_NOTHROW(name->set_organization("John Doe's Company Pty."));

		return name;
	}

	std::unique_ptr<sslpkix::Certificate> create_certificate(
		const sslpkix::CertificateName& subject,
		const sslpkix::CertificateName& issuer,
		const sslpkix::Key& public_key
	) {
		auto cert = std::make_unique<sslpkix::Certificate>();

		REQUIRE_NOTHROW(cert->set_version(sslpkix::Certificate::Version::v3));
		REQUIRE_NOTHROW(cert->set_pubkey(public_key));
		REQUIRE_NOTHROW(cert->set_serial(31337L)); // Hardcoded serial - Never do this in production!
		REQUIRE_NOTHROW(cert->set_issuer(issuer));
		REQUIRE_NOTHROW(cert->set_subject(subject));
		REQUIRE_NOTHROW(cert->set_valid_since(0));
		REQUIRE_NOTHROW(cert->set_valid_until(5)); // Valid for 5 days from now

		return cert;
	}

	void sign_certificate(sslpkix::Certificate& cert, const sslpkix::PrivateKey& private_key) {
		REQUIRE_NOTHROW(cert.sign(private_key));
	}
};

TEST_CASE_METHOD(TestFixture, "Certificate creation", "[certificate][creation]")
{
	auto test = make_test_objects();

	REQUIRE(test.cert->is_signed());
	REQUIRE(test.cert->has_required_fields());
	REQUIRE(test.cert->matches_private_key(*test.public_key));
	REQUIRE(test.cert->verify_signature(*test.public_key));
	REQUIRE(test.cert->subject() == *test.subject);
	REQUIRE(test.cert->issuer() == *test.issuer);

	// Test copy constructor
	sslpkix::Certificate certCopy1(*test.cert);
	REQUIRE(certCopy1 == *test.cert);

	// Test assignment operator
	sslpkix::Certificate certCopy2;
	certCopy2 = *test.cert;
	REQUIRE(certCopy2 == *test.cert);
}

TEST_CASE_METHOD(TestFixture, "Certificate self-signed", "[certificate][self-signed]")
{
	auto test = make_test_objects(true);
	REQUIRE(test.cert->subject() == test.cert->issuer());
	REQUIRE(test.cert->is_self_signed());
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
