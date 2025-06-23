#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <memory>
#include <stdexcept>

#include "sslpkix/x509/cert.h"
#include "sslpkix/x509/key.h"
#include "sslpkix/x509/cert_name.h"
#include "sslpkix/x509/digest.h"
#include "sslpkix/iosink.h"

using namespace sslpkix;

// Test fixture for Certificate tests
class CertificateTestFixture {
public:
    CertificateTestFixture() {
        // Create a test RSA key pair
        createTestKeyPair();

        // Create a test certificate name
        createTestCertificateName();
    }

    ~CertificateTestFixture() = default;
    CertificateTestFixture(const CertificateTestFixture&) = delete;
    CertificateTestFixture& operator=(const CertificateTestFixture&) = delete;
    CertificateTestFixture(CertificateTestFixture&&) = delete;
    CertificateTestFixture& operator=(CertificateTestFixture&&) = delete;

protected:
    std::unique_ptr<PrivateKey> test_private_key;
    std::unique_ptr<Key> test_public_key;
    std::unique_ptr<CertificateName> test_subject;
    std::unique_ptr<CertificateName> test_issuer;

private:

    void createTestKeyPair() {
        EVP_PKEY* private_pkey = factory::generate_key_rsa(512);
        test_private_key = std::make_unique<PrivateKey>(private_pkey);
        test_public_key = test_private_key->extract_public_key();
    }

    void createTestCertificateName() {
        test_subject = std::make_unique<CertificateName>();
        test_subject->set_country("US");
        test_subject->set_state("California");
        test_subject->set_locality("San Francisco");
        test_subject->set_organization("Test Organization");
        test_subject->set_organizational_unit("Test Unit");
        test_subject->set_common_name("test.example.com");
        test_subject->set_email("test@example.com");

        test_issuer = std::make_unique<CertificateName>();
        test_issuer->set_country("US");
        test_issuer->set_state("California");
        test_issuer->set_locality("San Francisco");
        test_issuer->set_organization("Test CA Organization");
        test_issuer->set_organizational_unit("Test CA Unit");
        test_issuer->set_common_name("ca.example.com");
        test_issuer->set_email("ca@example.com");
    }
};

// Basic Construction Tests
TEST_CASE_METHOD(CertificateTestFixture, "Certificate Construction", "[certificate][construction]") {

    SECTION("Default constructor creates valid certificate") {
        Certificate cert;
        REQUIRE(cert.is_valid());
        REQUIRE(cert.handle() != nullptr);
        REQUIRE(static_cast<bool>(cert));
    }

    SECTION("Constructor with X509 handle") {
        X509* x509 = X509_new();
        REQUIRE(x509 != nullptr);

        Certificate cert(x509);
        REQUIRE(cert.is_valid());
        REQUIRE(cert.handle() == x509);
    }

    SECTION("Constructor with null handle throws") {
        REQUIRE_THROWS_AS(Certificate(nullptr), std::invalid_argument);
    }
}

// Copy and Move Semantics Tests
TEST_CASE_METHOD(CertificateTestFixture, "Certificate Copy and Move Semantics", "[certificate][semantics]") {

    SECTION("Copy constructor throws when certificate is missing required fields") {
        Certificate original;
        REQUIRE_THROWS_AS(Certificate(original), std::runtime_error);
    }

    SECTION("Copy constructor creates independent copy") {
        Certificate original;
        original.set_version(Certificate::Version::v3);
        original.set_serial(12345);
        original.set_valid_since(0);
        original.set_valid_until(365);
        original.set_subject(*test_subject);
        original.set_issuer(*test_issuer);
        original.set_pubkey(*test_public_key);
        original.sign(*test_private_key, Digest::TYPE_SHA256);

        Certificate copy(original);
        REQUIRE(copy.is_valid());
        REQUIRE(copy.handle() != original.handle()); // Different handles
        REQUIRE(copy.version() == original.version());
        REQUIRE(copy.serial() == original.serial());
    }

    SECTION("Copy assignment works correctly") {
        Certificate original;
        original.set_version(Certificate::Version::v3);
        original.set_serial(54321);
        original.set_valid_since(0);
        original.set_valid_until(365);
        original.set_subject(*test_subject);
        original.set_issuer(*test_issuer);
        original.set_pubkey(*test_public_key);
        original.sign(*test_private_key, Digest::TYPE_SHA256);

        Certificate copy;
        copy = original;

        REQUIRE(copy.is_valid());
        REQUIRE(copy.version() == original.version());
        REQUIRE(copy.serial() == original.serial());
    }

    SECTION("Self-assignment is safe") {
        Certificate cert;
        cert.set_version(Certificate::Version::v3);
        cert.set_serial(99999);
        cert.set_valid_since(0);
        cert.set_valid_until(365);
        cert.set_subject(*test_subject);
        cert.set_issuer(*test_issuer);
        cert.set_pubkey(*test_public_key);
        cert.sign(*test_private_key, Digest::TYPE_SHA256);

        cert = cert; // Self-assignment

        REQUIRE(cert.is_valid());
        REQUIRE(cert.version() == Certificate::Version::v3);
        REQUIRE(cert.serial() == 99999);
    }

    SECTION("Move constructor") {
        Certificate original;
        original.set_version(Certificate::Version::v3);
        X509* original_handle = original.handle();

        Certificate moved(std::move(original));
        REQUIRE(moved.is_valid());
        REQUIRE(moved.handle() == original_handle);
        REQUIRE(moved.version() == Certificate::Version::v3);
    }

    SECTION("Move assignment") {
        Certificate original;
        original.set_version(Certificate::Version::v3);
        X509* original_handle = original.handle();

        Certificate moved;
        moved = std::move(original);

        REQUIRE(moved.is_valid());
        REQUIRE(moved.handle() == original_handle);
        REQUIRE(moved.version() == Certificate::Version::v3);
    }
}

// Version Tests
TEST_CASE_METHOD(CertificateTestFixture, "Certificate Version", "[certificate][version]") {

    SECTION("Set and get version v1") {
        Certificate cert;
        cert.set_version(Certificate::Version::v1);
        REQUIRE(cert.version() == Certificate::Version::v1);
    }

    SECTION("Set and get version v2") {
        Certificate cert;
        cert.set_version(Certificate::Version::v2);
        REQUIRE(cert.version() == Certificate::Version::v2);
    }

    SECTION("Set and get version v3") {
        Certificate cert;
        cert.set_version(Certificate::Version::v3);
        REQUIRE(cert.version() == Certificate::Version::v3);
    }

    SECTION("Setting invalid version throws") {
        Certificate cert;
        REQUIRE_THROWS_AS(cert.set_version(Certificate::Version::invalid), std::invalid_argument);
    }
}

// Serial Number Tests
TEST_CASE_METHOD(CertificateTestFixture, "Certificate Serial Number", "[certificate][serial]") {

    SECTION("Set and get serial number") {
        Certificate cert;
        cert.set_serial(123456789L);
        REQUIRE(cert.serial() == 123456789L);
    }

    SECTION("Set serial number to zero") {
        Certificate cert;
        cert.set_serial(0);
        REQUIRE(cert.serial() == 0);
    }

    SECTION("Set large serial number") {
        Certificate cert;
        long large_serial = 0x7FFFFFFFL;
        cert.set_serial(large_serial);
        REQUIRE(cert.serial() == large_serial);
    }
}

// Validity Period Tests
TEST_CASE_METHOD(CertificateTestFixture, "Certificate Validity Period", "[certificate][validity]") {

    SECTION("Set valid since (past)") {
        Certificate cert;
        REQUIRE_NOTHROW(cert.set_valid_since(-1)); // 1 day ago
    }

    SECTION("Set valid since (present)") {
        Certificate cert;
        REQUIRE_NOTHROW(cert.set_valid_since(0)); // Today
    }

    SECTION("Set valid until (future)") {
        Certificate cert;
        REQUIRE_NOTHROW(cert.set_valid_until(365)); // 1 year from now
    }

    SECTION("Set validity period together") {
        Certificate cert;
        REQUIRE_NOTHROW(cert.set_valid_since(0));
        REQUIRE_NOTHROW(cert.set_valid_until(365));
    }
}

// Public Key Tests
TEST_CASE_METHOD(CertificateTestFixture, "Certificate Public Key", "[certificate][pubkey]") {

    SECTION("Set and get public key") {
        Certificate cert;
        REQUIRE_NOTHROW(cert.set_pubkey(*test_public_key));

        auto retrieved_key = cert.pubkey();
        REQUIRE(retrieved_key.is_valid());
        REQUIRE(retrieved_key.algorithm() == test_public_key->algorithm());
    }

    SECTION("Set public key with invalid key throws") {
        Certificate cert;
        Key invalid_key; // Default constructed but doesn't containg a generated key
        REQUIRE_THROWS_AS(cert.set_pubkey(invalid_key), std::runtime_error);
    }

    SECTION("Get public key from certificate without key") {
        Certificate cert;
        // A new certificate doesn't have a public key set
        REQUIRE_THROWS_AS(cert.pubkey(), std::runtime_error);
    }
}

// Subject and Issuer Tests
TEST_CASE_METHOD(CertificateTestFixture, "Certificate Subject and Issuer", "[certificate][names]") {

    SECTION("Set and get subject") {
        Certificate cert;
        cert.set_subject(*test_subject);

        auto retrieved_subject = cert.subject();
        REQUIRE(retrieved_subject.is_valid());
        REQUIRE(retrieved_subject == *test_subject);
        REQUIRE(retrieved_subject.common_name() == "test.example.com");
    }

    SECTION("Set and get issuer") {
        Certificate cert;
        cert.set_issuer(*test_issuer);

        auto retrieved_issuer = cert.issuer();
        REQUIRE(retrieved_issuer.is_valid());
        REQUIRE(retrieved_issuer == *test_issuer);
        REQUIRE(retrieved_issuer.common_name() == "ca.example.com");
    }

    SECTION("Set an empty subject") {
        Certificate cert;
        CertificateName empty_name; // Empty name
        REQUIRE_NOTHROW(cert.set_subject(empty_name));
    }

    SECTION("Set an empty issuer") {
        Certificate cert;
        CertificateName empty_name; // Empty name
        REQUIRE_NOTHROW(cert.set_issuer(empty_name));
    }
}

// Extension Tests
TEST_CASE_METHOD(CertificateTestFixture, "Certificate Extensions", "[certificate][extensions]") {

    SECTION("Add basic constraint extension") {
        Certificate cert;
        REQUIRE_NOTHROW(cert.add_extension(NID_basic_constraints, "critical,CA:FALSE"));
    }

    SECTION("Add key usage extension") {
        Certificate cert;
        REQUIRE_NOTHROW(cert.add_extension(NID_key_usage, "critical,digitalSignature,keyEncipherment"));
    }

    SECTION("Add subject alternative name extension") {
        Certificate cert;
        REQUIRE_NOTHROW(cert.add_extension(NID_subject_alt_name, "DNS:test.example.com,DNS:www.test.example.com"));
    }

    SECTION("Add extension with null value throws") {
        Certificate cert;
        REQUIRE_THROWS_AS(cert.add_extension(NID_basic_constraints, nullptr), std::invalid_argument);
    }

    SECTION("Add extension with invalid NID") {
        Certificate cert;
        // Using an invalid NID should cause an error
        REQUIRE_THROWS_AS(cert.add_extension(-1, "somevalue"), std::runtime_error);
    }
}

// Signing Tests
TEST_CASE_METHOD(CertificateTestFixture, "Certificate Signing", "[certificate][signing]") {

    SECTION("Sign certificate with private key") {
        Certificate cert;
        cert.set_version(Certificate::Version::v3);
        cert.set_serial(12345);
        cert.set_valid_since(0);
        cert.set_valid_until(365);
        cert.set_pubkey(*test_public_key);
        cert.set_subject(*test_subject);
        cert.set_issuer(*test_issuer);

        REQUIRE(test_private_key->can_sign());
        REQUIRE_NOTHROW(cert.sign(*test_private_key, Digest::TYPE_SHA256));
    }

    SECTION("Sign with invalid key throws") {
        Certificate cert;
        cert.set_version(Certificate::Version::v3);
        cert.set_serial(12345);
        cert.set_valid_since(0);
        cert.set_valid_until(365);
        cert.set_subject(*test_subject);
        cert.set_issuer(*test_issuer);
        cert.set_pubkey(*test_public_key);

        PrivateKey invalid_key; // Not properly initialized
        REQUIRE_FALSE(invalid_key.has_public_key());
        REQUIRE_FALSE(invalid_key.has_private_key());
        REQUIRE_FALSE(invalid_key.can_sign());
        REQUIRE_THROWS_AS(cert.sign(invalid_key), std::invalid_argument);
    }

    SECTION("Sign certificate with different digest algorithms") {
        Certificate cert;
        cert.set_version(Certificate::Version::v3);
        cert.set_serial(12345);
        cert.set_valid_since(0);
        cert.set_valid_until(365);
        cert.set_pubkey(*test_public_key);
        cert.set_subject(*test_subject);
        cert.set_issuer(*test_issuer);

        REQUIRE(test_private_key->has_public_key());
        REQUIRE(test_private_key->has_private_key());
        REQUIRE(test_private_key->can_sign());
        REQUIRE_NOTHROW(cert.sign(*test_private_key, Digest::TYPE_SHA1));
        REQUIRE_NOTHROW(cert.sign(*test_private_key, Digest::TYPE_SHA256));
    }
}

// Verification Tests
TEST_CASE_METHOD(CertificateTestFixture, "Certificate Verification", "[certificate][verification]") {

    SECTION("Verify signature with correct key") {
        Certificate cert;
        cert.set_version(Certificate::Version::v3);
        cert.set_serial(12345);
        cert.set_valid_since(0);
        cert.set_valid_until(365);
        cert.set_pubkey(*test_public_key);
        cert.set_subject(*test_subject);
        cert.set_issuer(*test_issuer);
        cert.sign(*test_private_key);

        REQUIRE(cert.verify_signature(*test_public_key));
    }

    SECTION("Check private key matches certificate") {
        Certificate cert;
        cert.set_pubkey(*test_public_key);

        REQUIRE(cert.matches_private_key(*test_public_key));
    }

    SECTION("Verify with wrong key returns false") {
        Certificate cert;
        cert.set_version(Certificate::Version::v3);
        cert.set_serial(12345);
        cert.set_valid_since(0);
        cert.set_valid_until(365);
        cert.set_pubkey(*test_public_key);
        cert.set_subject(*test_subject);
        cert.set_issuer(*test_issuer);
        cert.sign(*test_private_key);

        // Create a different key for verification
        Key different_key;
        REQUIRE_FALSE(cert.verify_signature(different_key));
    }
}

// Equality and Comparison Tests
TEST_CASE_METHOD(CertificateTestFixture, "Certificate Equality and Comparison", "[certificate][equality]") {

    SECTION("Equal certificates compare equal") {
        Certificate cert1;
        cert1.set_version(Certificate::Version::v3);
        cert1.set_serial(12345);
        cert1.set_valid_since(0);
        cert1.set_valid_until(365);
        cert1.set_subject(*test_subject);
        cert1.set_issuer(*test_issuer);
        cert1.set_pubkey(*test_public_key);
        cert1.sign(*test_private_key, Digest::TYPE_SHA256);

        Certificate cert2(cert1); // Copy constructor

        REQUIRE(cert1 == cert2);
        REQUIRE_FALSE(cert1 != cert2);
    }

    SECTION("Different certificates compare unequal") {
        Certificate cert1;
        cert1.set_version(Certificate::Version::v3);
        cert1.set_serial(12345);
        cert1.set_valid_since(0);
        cert1.set_valid_until(365);
        cert1.set_subject(*test_subject);
        cert1.set_issuer(*test_issuer);
        cert1.set_pubkey(*test_public_key);
        cert1.sign(*test_private_key, Digest::TYPE_SHA256);

        Certificate cert2;
        cert2.set_version(Certificate::Version::v3);
        cert2.set_serial(54321); // Different serial
        cert2.set_valid_since(0);
        cert2.set_valid_until(365);
        cert2.set_subject(*test_subject);
        cert2.set_issuer(*test_issuer);
        cert2.set_pubkey(*test_public_key);
        cert2.sign(*test_private_key, Digest::TYPE_SHA256);

        REQUIRE_FALSE(cert1 == cert2);
        REQUIRE(cert1 != cert2);
    }

    SECTION("Empty certificates compare equal") {
        Certificate cert1;
        Certificate cert2;
        REQUIRE(cert1 == cert2);
        REQUIRE_FALSE(cert1 != cert2);
    }
}

// Complete Certificate Creation Test
TEST_CASE_METHOD(CertificateTestFixture, "Complete Certificate Creation", "[certificate][integration]") {

    SECTION("Create a complete self-signed certificate") {
        Certificate cert;

        // Set basic certificate information
        cert.set_version(Certificate::Version::v3);
        cert.set_serial(1);
        cert.set_valid_since(0);
        cert.set_valid_until(365);

        // Set subject and issuer (self-signed)
        cert.set_subject(*test_subject);
        cert.set_issuer(*test_subject); // Self-signed

        // Set public key
        cert.set_pubkey(*test_public_key);

        // Add extensions
        cert.add_extension(NID_basic_constraints, "critical,CA:TRUE");
        cert.add_extension(NID_key_usage, "critical,keyCertSign,cRLSign");
        cert.add_extension(NID_subject_key_identifier, "hash");

        // Sign the certificate
        cert.sign(*test_private_key, Digest::TYPE_SHA256);

        // Verify the certificate
        REQUIRE(cert.is_valid());
        REQUIRE(cert.version() == Certificate::Version::v3);
        REQUIRE(cert.serial() == 1);
        REQUIRE(cert.verify_signature(*test_public_key));
        REQUIRE(cert.matches_private_key(*test_public_key));

        auto subject = cert.subject();
        REQUIRE(subject.common_name() == "test.example.com");

        auto issuer = cert.issuer();
        REQUIRE(issuer.common_name() == "test.example.com"); // Self-signed
    }
}

// Error Handling Tests
TEST_CASE_METHOD(CertificateTestFixture, "Certificate Error Handling", "[certificate][errors]") {

    SECTION("Invalid operations throw appropriate exceptions") {
        Certificate cert;

        // These should throw runtime_error or invalid_argument
        REQUIRE_THROWS_AS(cert.set_version(Certificate::Version::invalid), std::invalid_argument);
        REQUIRE_THROWS_AS(cert.add_extension(NID_basic_constraints, nullptr), std::invalid_argument);
    }
}

// Swap Function Test
TEST_CASE_METHOD(CertificateTestFixture, "Certificate Swap", "[certificate][swap]") {

    SECTION("Swap function works correctly") {
        Certificate cert1;
        cert1.set_version(Certificate::Version::v3);
        cert1.set_serial(111);
        cert1.set_valid_since(0);
        cert1.set_valid_until(365);
        cert1.set_subject(*test_subject);
        cert1.set_issuer(*test_issuer);
        cert1.set_pubkey(*test_public_key);
        cert1.sign(*test_private_key, Digest::TYPE_SHA256);

        Certificate cert2;
        cert2.set_version(Certificate::Version::v2);
        cert2.set_serial(222);
        cert2.set_valid_since(0);
        cert2.set_valid_until(365);
        cert2.set_subject(*test_subject);
        cert2.set_issuer(*test_issuer);
        cert2.set_pubkey(*test_public_key);
        cert2.sign(*test_private_key, Digest::TYPE_SHA256);

        swap(cert1, cert2);

        REQUIRE(cert1.version() == Certificate::Version::v2);
        REQUIRE(cert1.serial() == 222);
        REQUIRE(cert2.version() == Certificate::Version::v3);
        REQUIRE(cert2.serial() == 111);
    }
}