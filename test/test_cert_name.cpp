#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_template_test_macros.hpp>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <unordered_set>
#include <unordered_map>
#include "sslpkix/x509/cert_name.h"

using namespace sslpkix;

struct CertificateNameTestFixture {
	CertificateNameTestFixture() = default;
	~CertificateNameTestFixture() = default;
	CertificateNameTestFixture(const CertificateNameTestFixture&) = delete;
	CertificateNameTestFixture& operator=(const CertificateNameTestFixture&) = delete;
	CertificateNameTestFixture(CertificateNameTestFixture&&) = delete;
	CertificateNameTestFixture& operator=(CertificateNameTestFixture&&) = delete;

	// Helper to create a populated certificate name
	CertificateName createTestName() {
		CertificateName name;
		REQUIRE_NOTHROW(name.set_common_name("Test User"));
		REQUIRE_NOTHROW(name.set_country("US"));
		REQUIRE_NOTHROW(name.set_state("California"));
		REQUIRE_NOTHROW(name.set_locality("San Francisco"));
		REQUIRE_NOTHROW(name.set_organization("Test Org"));
		REQUIRE_NOTHROW(name.set_organizational_unit("Test Unit"));
		REQUIRE_NOTHROW(name.set_email("test@example.com"));
		return name;
	}

	// Helper to create a minimal certificate name
	CertificateName createMinimalName() {
		CertificateName name;
		REQUIRE_NOTHROW(name.set_common_name("Minimal User"));
		return name;
	}
};

TEST_CASE_METHOD(CertificateNameTestFixture, "CertificateName default construction", "[CertificateName][constructor]") {
	CertificateName name;

	SECTION("Default constructed name is valid") {
		REQUIRE(name);
		REQUIRE(name.handle() != nullptr);
		REQUIRE(name.entry_count() == 0);
	}
}

TEST_CASE_METHOD(CertificateNameTestFixture, "CertificateName creation and basic operations", "[CertificateName][creation]") {
	CertificateName name;

	SECTION("Create new certificate name") {
		REQUIRE(name);
		REQUIRE(name.handle() != nullptr);
		REQUIRE(name.entry_count() == 0);
	}
}

TEST_CASE_METHOD(CertificateNameTestFixture, "CertificateName handle constructor", "[CertificateName][constructor]") {
	SECTION("Valid handle construction") {
		X509_NAME* raw_name = X509_NAME_new();
		REQUIRE(raw_name != nullptr);

		CertificateName name(raw_name);
		REQUIRE(name);
		REQUIRE(name.handle() == raw_name);

		// Cleanup the handle
		X509_NAME_free(raw_name);
	}

	SECTION("Null handle does not throw exception") {
		REQUIRE_NOTHROW(CertificateName(nullptr));
	}

	SECTION("Constructing with null handle") {
		CertificateName null_name(nullptr);
		REQUIRE_FALSE(null_name);
		REQUIRE(null_name.handle() == nullptr);
		REQUIRE_FALSE(null_name.is_valid());
		REQUIRE(null_name.entry_count() == 0);
	}
}

TEST_CASE_METHOD(CertificateNameTestFixture, "CertificateName copy operations", "[CertificateName][copy]") {
	auto original = createTestName();

	SECTION("Copy constructor") {
		CertificateName copy(original);

		REQUIRE(copy);
		REQUIRE(copy.handle() != original.handle()); // Different handles
		REQUIRE(copy == original); // But equal content
		REQUIRE(copy.common_name() == original.common_name());
		REQUIRE(copy.country() == original.country());
	}

	SECTION("Copy assignment") {
		CertificateName copy;
		copy = original;

		REQUIRE(copy);
		REQUIRE(copy.handle() != original.handle());
		REQUIRE(copy == original);
		REQUIRE(copy.common_name() == original.common_name());
	}

	SECTION("Self assignment") {
		auto& self_ref = original;
		original = self_ref;

		REQUIRE(original);
		REQUIRE(original.common_name() == "Test User");
	}

	SECTION("Copy from empty name") {
		CertificateName empty;
		CertificateName copy(empty);

		REQUIRE(copy);
		REQUIRE(copy.handle() != nullptr);
	}
}

TEST_CASE_METHOD(CertificateNameTestFixture, "CertificateName move operations", "[CertificateName][move]") {
	SECTION("Move constructor") {
		auto original = createTestName();
		X509_NAME* original_handle = original.handle();

		CertificateName moved(std::move(original));

		REQUIRE(moved);
		REQUIRE(moved.handle() == original_handle);
		REQUIRE(moved.common_name() == "Test User");

		// Original should be in valid but unspecified state
		// We can't guarantee what state it's in after move
	}

	SECTION("Move assignment") {
		auto original = createTestName();
		X509_NAME* original_handle = original.handle();

		CertificateName moved;
		moved = std::move(original);

		REQUIRE(moved);
		REQUIRE(moved.handle() == original_handle);
		REQUIRE(moved.common_name() == "Test User");
	}
}

TEST_CASE_METHOD(CertificateNameTestFixture, "CertificateName field operations", "[CertificateName][fields]") {
	CertificateName name;

	SECTION("Add entries by NID") {
		REQUIRE_NOTHROW(name.add_entry_by_nid(NID_commonName, "John Doe"));
		REQUIRE_NOTHROW(name.add_entry_by_nid(NID_countryName, "US"));

		REQUIRE(name.entry_count() == 2);
		REQUIRE(name.get_entry_value(NID_commonName) == "John Doe");
		REQUIRE(name.get_entry_value(NID_countryName) == "US");
	}

	SECTION("Add entries by text") {
		REQUIRE_NOTHROW(name.add_entry_by_txt("CN", "Jane Doe"));
		REQUIRE_NOTHROW(name.add_entry_by_txt("C", "CA"));

		REQUIRE(name.entry_count() == 2);
		REQUIRE(name.get_entry_value(NID_commonName) == "Jane Doe");
		REQUIRE(name.get_entry_value(NID_countryName) == "CA");
	}

	SECTION("Legacy add_entry methods") {
		REQUIRE_NOTHROW(name.add_entry(NID_commonName, "Legacy User"));
		REQUIRE_NOTHROW(name.add_entry("C", "DE"));

		REQUIRE(name.entry_count() == 2);
		REQUIRE(name.entry_value(NID_commonName) == "Legacy User");
		REQUIRE(name.get_entry_value(NID_countryName) == "DE");
	}
}

TEST_CASE_METHOD(CertificateNameTestFixture, "CertificateName field accessors", "[CertificateName][accessors]") {
	auto name = createTestName();

	SECTION("Field getters") {
		REQUIRE(name.common_name() == "Test User");
		REQUIRE(name.country() == "US");
		REQUIRE(name.state() == "California");
		REQUIRE(name.locality() == "San Francisco");
		REQUIRE(name.organization() == "Test Org");
		REQUIRE(name.organizational_unit() == "Test Unit");
		REQUIRE(name.email() == "test@example.com");
	}

	SECTION("Empty fields return empty strings") {
		CertificateName empty_name;
		REQUIRE(empty_name.common_name().empty());
		REQUIRE(empty_name.country().empty());
		REQUIRE(empty_name.state().empty());
		REQUIRE(empty_name.locality().empty());
		REQUIRE(empty_name.organization().empty());
		REQUIRE(empty_name.organizational_unit().empty());
		REQUIRE(empty_name.email().empty());
	}

	SECTION("Field setters") {
		CertificateName name;
		REQUIRE_NOTHROW(name.set_common_name("New User"));
		REQUIRE_NOTHROW(name.set_country("GB"));
		REQUIRE_NOTHROW(name.set_state("England"));
		REQUIRE_NOTHROW(name.set_locality("London"));
		REQUIRE_NOTHROW(name.set_organization("New Org"));
		REQUIRE_NOTHROW(name.set_organizational_unit("New Unit"));
		REQUIRE_NOTHROW(name.set_email("new@example.com"));

		REQUIRE(name.common_name() == "New User");
		REQUIRE(name.country() == "GB");
		REQUIRE(name.state() == "England");
		REQUIRE(name.locality() == "London");
		REQUIRE(name.organization() == "New Org");
		REQUIRE(name.organizational_unit() == "New Unit");
		REQUIRE(name.email() == "new@example.com");
	}
}

TEST_CASE_METHOD(CertificateNameTestFixture, "CertificateName entry operations", "[CertificateName][entries]") {
	auto name = createTestName();

	SECTION("Entry count") {
		REQUIRE(name.entry_count() == 7); // All fields we set
	}

	SECTION("Find entry by NID") {
		int cn_index = name.find_entry_by_nid(NID_commonName);
		REQUIRE(cn_index >= 0);

		int nonexistent_index = name.find_entry_by_nid(NID_serialNumber);
		REQUIRE(nonexistent_index == -1);
	}

	SECTION("Legacy find_entry method") {
		int cn_index = name.find_entry(NID_commonName);
		REQUIRE(cn_index >= 0);
	}

	SECTION("Get entry by index") {
		int cn_index = name.find_entry_by_nid(NID_commonName);
		X509_NAME_ENTRY* entry = name.get_entry(cn_index);
		REQUIRE(entry != nullptr);

		// Legacy method
		X509_NAME_ENTRY* entry2 = name.entry(cn_index);
		REQUIRE(entry2 == entry);
	}

	SECTION("Get entry value with buffer") {
		char buffer[256];
		int result = name.get_entry_value(NID_commonName, buffer, sizeof(buffer));
		REQUIRE(result > 0);
		REQUIRE(std::string(buffer) == "Test User");

		// Legacy method
		int result2 = name.entry_value(NID_commonName, buffer, sizeof(buffer));
		REQUIRE(result2 > 0);
		REQUIRE(std::string(buffer) == "Test User");
	}
}

TEST_CASE_METHOD(CertificateNameTestFixture, "CertificateName string representation", "[CertificateName][string]") {
	auto name = createTestName();

	SECTION("to_string method") {
		std::string str = name.to_string();
		REQUIRE_FALSE(str.empty());
		REQUIRE(str.find("Test User") != std::string::npos);
	}

	SECTION("Legacy one_line method") {
		std::string str = name.one_line();
		REQUIRE_FALSE(str.empty());
		REQUIRE(str == name.to_string());
	}

	SECTION("Empty name string representation") {
		CertificateName empty;
		REQUIRE(empty.to_string().empty());
	}
}

TEST_CASE_METHOD(CertificateNameTestFixture, "CertificateName BIO operations", "[CertificateName][bio]") {
	auto name = createTestName();

	SECTION("Print to BIO") {
		BIO* bio = BIO_new(BIO_s_mem());
		REQUIRE(bio != nullptr);

		REQUIRE(name.print_ex(bio));

		char* data;
		long length = BIO_get_mem_data(bio, &data);
		REQUIRE(length > 0);

		std::string output(data, length);
		REQUIRE(output.find("Test User") != std::string::npos);

		BIO_free(bio);
	}

	SECTION("Legacy one_line_print method") {
		BIO* bio = BIO_new(BIO_s_mem());
		REQUIRE(bio != nullptr);

		REQUIRE(name.one_line_print(bio, 4)); // With indent

		BIO_free(bio);
	}

	SECTION("Print with null BIO fails") {
		REQUIRE_FALSE(name.print_ex(nullptr));
	}
}

TEST_CASE_METHOD(CertificateNameTestFixture, "CertificateName comparison operators", "[CertificateName][comparison]") {
	auto name1 = createTestName();
	auto name2 = createTestName();
	auto different_name = createMinimalName();

	SECTION("Equality comparison") {
		REQUIRE(name1 == name2);
		REQUIRE_FALSE(name1 == different_name);
		REQUIRE_FALSE(name1 != name2);
		REQUIRE(name1 != different_name);
	}

	SECTION("Less than comparison") {
		// This depends on OpenSSL's X509_NAME_cmp implementation
		// We just verify the operation doesn't crash and is consistent
		bool less1 = name1 < different_name;
		bool less2 = different_name < name1;
		bool both_are_less = less1 && less2;

		// At least one should be false (they can't both be less than each other)
		REQUIRE_FALSE(both_are_less);
	}

	SECTION("Empty name comparisons") {
		CertificateName empty1, empty2;

		REQUIRE(empty1 == empty2);
		REQUIRE_FALSE(empty1 != empty2);
		REQUIRE_FALSE(empty1 < empty2);

		REQUIRE_FALSE(empty1 == name1);
		REQUIRE(empty1 != name1);
		REQUIRE(empty1 < name1);
		REQUIRE_FALSE(name1 < empty1);
	}
}

TEST_CASE_METHOD(CertificateNameTestFixture, "CertificateName hash functionality", "[CertificateName][hash]") {
	auto name1 = createTestName();
	auto name2 = createTestName();
	auto different_name = createMinimalName();

	SECTION("CertificateNameHash") {
		CertificateNameHash hasher;

		auto hash1 = hasher(name1);
		auto hash2 = hasher(name2);
		auto hash_diff = hasher(different_name);

		REQUIRE(hash1 == hash2); // Same content should have same hash
		REQUIRE(hash1 != hash_diff); // Different content should have different hash
	}

	SECTION("std::hash specialization") {
		std::hash<CertificateName> hasher;

		auto hash1 = hasher(name1);
		auto hash2 = hasher(name2);

		REQUIRE(hash1 == hash2);
	}

	SECTION("Hash of empty name") {
		CertificateNameHash hasher;
		CertificateName empty_name;

		REQUIRE(hasher(empty_name) != 0);
	}

	SECTION("Use in unordered containers") {
		std::unordered_set<CertificateName> name_set;
		name_set.insert(name1);
		name_set.insert(name2); // Should not increase size (same content)
		name_set.insert(different_name);

		REQUIRE(name_set.size() == 2);
		REQUIRE(name_set.count(name1) == 1);
		REQUIRE(name_set.count(different_name) == 1);

		std::unordered_map<CertificateName, std::string> name_map;
		name_map[name1] = "first";
		name_map[different_name] = "second";

		REQUIRE(name_map.size() == 2);
		REQUIRE(name_map[name2] == "first"); // Same content as name1
	}
}

TEST_CASE_METHOD(CertificateNameTestFixture, "CertificateName error handling", "[CertificateName][errors]") {
	SECTION("Operations on empty name") {
		CertificateName empty_name;

		REQUIRE(empty_name.entry_count() == 0);
		REQUIRE(empty_name.find_entry_by_nid(NID_commonName) == -1);
		REQUIRE(empty_name.get_entry(0) == nullptr);
		REQUIRE(empty_name.get_entry_value(NID_commonName).empty());
		REQUIRE(empty_name.get_entry_value(NID_commonName, nullptr, 0) == -1);
		REQUIRE(empty_name.to_string().empty());
		REQUIRE(empty_name.print_ex(BIO_new(BIO_s_mem())));
	}

	SECTION("Invalid entry operations") {
		auto name = createTestName();

		// Invalid index
		REQUIRE(name.get_entry(-1) == nullptr);
		REQUIRE(name.get_entry(1000) == nullptr);

		// Non-existent NID
		REQUIRE(name.get_entry_value(NID_serialNumber).empty());
	}

	SECTION("Buffer operations with invalid parameters") {
		auto name = createTestName();

		// Null buffer
		REQUIRE(name.get_entry_value(NID_commonName, nullptr, 100) == 9);

		// Zero buffer size
		char buffer[1];
		int result = name.get_entry_value(NID_commonName, buffer, 0);
		REQUIRE(result <= 0);
	}
}

TEST_CASE_METHOD(CertificateNameTestFixture, "CertificateName edge cases", "[CertificateName][edge]") {
	SECTION("Empty string values") {
		CertificateName name;

		REQUIRE_THROWS_AS(name.set_common_name(""), std::invalid_argument);
		REQUIRE(name.common_name().empty());
		REQUIRE(name.entry_count() == 0);
	}

	SECTION("Unicode/special characters") {
		CertificateName name;

		// Test with some special characters (results may vary based on OpenSSL config)
		std::string special_name = "Test-User_123";
		REQUIRE_NOTHROW(name.set_common_name(special_name));
		REQUIRE(name.common_name() == special_name);
	}

	SECTION("Multiple entries with same NID") {
		CertificateName name;

		// Some fields can have multiple entries
		REQUIRE_NOTHROW(name.add_entry_by_nid(NID_organizationalUnitName, "Unit1"));
		REQUIRE_NOTHROW(name.add_entry_by_nid(NID_organizationalUnitName, "Unit2"));

		REQUIRE(name.entry_count() == 2);

		// find_entry should find the first one
		int index = name.find_entry_by_nid(NID_organizationalUnitName);
		REQUIRE(index >= 0);

		// Find the second one starting after the first
		int index2 = name.find_entry_by_nid(NID_organizationalUnitName, index);
		REQUIRE(index2 > index);
	}

	SECTION("Very long field values") {
		CertificateName name;

		std::string long_value(500, 'A'); // 500 character string
		REQUIRE_THROWS_AS(name.set_common_name(long_value), std::runtime_error);
		REQUIRE_FALSE(name.common_name() == long_value);
	}
}