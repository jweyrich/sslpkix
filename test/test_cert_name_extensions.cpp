#include <catch2/catch_test_macros.hpp>
#include <catch2/reporters/catch_reporter_event_listener.hpp>
#include <catch2/reporters/catch_reporter_registrars.hpp>
#include <catch2/catch_test_case_info.hpp>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include "sslpkix/sslpkix.h"

static const char * const SN_clientToken = "clientTokenIdentifier";
static const char * const LN_clientToken = "Client Token Identifier";
static const char * const OID_clientToken = "1.2.3.4.5.31.33.71";
static const char * const value_clientToken = "here-goes-a-hash";
static int nid_clientToken;

static const char * const SN_usersLimit = "usersLimit";
static const char * const LN_usersLimit = "Users Limit";
static const char * const OID_usersLimit = "1.2.3.4.5.31.33.72";
static const char * const value_usersLimit = "10";
static int nid_usersLimit;

// Runs before anu tests in this file
struct FileScopedListenerCertNameExtensions :  Catch::EventListenerBase {
    using EventListenerBase::EventListenerBase; // inherit constructor

    // Get rid of Weak-tables
    ~FileScopedListenerCertNameExtensions() override;

    void testRunStarting(Catch::TestRunInfo const& testRunInfo) override {
        std::cout << "Running once before tests in this file: " << testRunInfo.name << std::endl;

		// Add a custom extension
		REQUIRE(sslpkix::add_custom_object(OID_clientToken, SN_clientToken, LN_clientToken, &nid_clientToken));
		REQUIRE(sslpkix::add_custom_object(OID_usersLimit, SN_usersLimit, LN_usersLimit, &nid_usersLimit));
    }
};

CATCH_REGISTER_LISTENER(FileScopedListenerCertNameExtensions);

// Get rid of Weak-tables
FileScopedListenerCertNameExtensions::~FileScopedListenerCertNameExtensions() = default;

struct TestFixture {
	sslpkix::CertificateName name;

	TestFixture() {
		setup_name();
	}

private:
	void setup_name() {
		REQUIRE_NOTHROW(name.set_common_name("johndoe.example.com"));
		REQUIRE_NOTHROW(name.set_email("john.doe@example.com"));
		REQUIRE_NOTHROW(name.set_country("BR"));
		REQUIRE_NOTHROW(name.set_state("RS"));
		REQUIRE_NOTHROW(name.set_locality("Porto Alegre"));
		REQUIRE_NOTHROW(name.set_organization("John Doe's Company Pty."));

		// Add a custom extensions
		REQUIRE_NOTHROW(name.add_entry(SN_clientToken, value_clientToken));
		REQUIRE_NOTHROW(name.add_entry(SN_usersLimit, value_usersLimit));
		REQUIRE(name.entry_value(nid_clientToken) == value_clientToken);
		REQUIRE(name.entry_value(nid_usersLimit) == value_usersLimit);
	}
};

TEST_CASE("CertificateName extension", "[certificate_name][extensions]")
{
	sslpkix::CertificateName name;

	REQUIRE_NOTHROW(name.add_entry(SN_clientToken, value_clientToken));
	REQUIRE_NOTHROW(name.add_entry(SN_usersLimit, value_usersLimit));

	REQUIRE(name.entry_count() == 2);
	REQUIRE(name.entry_value(nid_clientToken) == value_clientToken);
	REQUIRE(name.entry_value(nid_usersLimit) == value_usersLimit);

	int index;
	REQUIRE((index = name.find_entry(nid_clientToken)) != -1);
	REQUIRE(name.entry(index) != nullptr);

	REQUIRE((index = name.find_entry(nid_usersLimit)) != -1);
	REQUIRE(name.entry(index) != nullptr);

	// Test copy constructor
	sslpkix::CertificateName nameCopy1(name);
	REQUIRE(nameCopy1 == name);

	// Test assignment operator
	sslpkix::CertificateName nameCopy2;
	REQUIRE_NOTHROW(nameCopy2 = name);
	REQUIRE(nameCopy2 == name);
}