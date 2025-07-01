#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <sstream>
#include <memory>

#include "sslpkix/x509/cert_req.h"
#include "sslpkix/x509/key.h"
#include "sslpkix/x509/cert_name.h"
#include "sslpkix/x509/digest.h"
#include "sslpkix/iosink.h"

using namespace sslpkix;

struct CertificateRequestTestFixture {
    CertificateRequestTestFixture() = default;
    ~CertificateRequestTestFixture() = default;
    CertificateRequestTestFixture(const CertificateRequestTestFixture&) = delete;
    CertificateRequestTestFixture& operator=(const CertificateRequestTestFixture&) = delete;
    CertificateRequestTestFixture(CertificateRequestTestFixture&&) = delete;
    CertificateRequestTestFixture& operator=(CertificateRequestTestFixture&&) = delete;

    EVP_PKEY* create_keypair(int bits = 512) {
        return factory::generate_key_rsa(bits);
    }

    CertificateName create_certificate_name() {
        CertificateName name;
        REQUIRE_NOTHROW(name.add_entry("C", "US"));
        REQUIRE_NOTHROW(name.add_entry("ST", "California"));
        REQUIRE_NOTHROW(name.add_entry("L", "San Francisco"));
        REQUIRE_NOTHROW(name.add_entry("O", "Test Organization"));
        REQUIRE_NOTHROW(name.add_entry("CN", "test.example.com"));
        return name;
    }
};

TEST_CASE("CertificateRequest Default Constructor", "[certificate_request][constructor]") {
    CertificateRequest req;

    SECTION("Default constructed request should be valid") {
        REQUIRE(req);
        REQUIRE(req.handle() != nullptr);
        REQUIRE(req.version() == CertificateRequest::Version::invalid);
    }
}

TEST_CASE("CertificateRequest Creation", "[certificate_request][creation]") {
    CertificateRequest req;

    SECTION("Create new certificate request") {
        REQUIRE(req);
        REQUIRE(req.handle() != nullptr);
    }

    SECTION("Set version after creation") {
        REQUIRE(req.set_version(CertificateRequest::Version::v1));
        REQUIRE(req.version() == CertificateRequest::Version::v1);
    }

    SECTION("Cannot set invalid version") {
        REQUIRE_THROWS_AS(req.set_version(CertificateRequest::Version::invalid), std::invalid_argument);
    }
}

TEST_CASE_METHOD(CertificateRequestTestFixture, "CertificateRequest Copy Operations", "[certificate_request][copy]") {
    CertificateRequest original;
    CertificateName subject = create_certificate_name();

    EVP_PKEY* keypair = create_keypair();
    std::unique_ptr<PrivateKey> private_key = std::make_unique<PrivateKey>(keypair);
    std::unique_ptr<Key> public_key = private_key->pubkey();

    REQUIRE(original.set_version(CertificateRequest::Version::v1));
    REQUIRE_NOTHROW(original.set_subject(subject));
    REQUIRE_NOTHROW(original.set_pubkey(*public_key));
    REQUIRE_NOTHROW(original.sign(*private_key, Digest::TYPE_SHA256));

    SECTION("Copy constructor") {
        CertificateRequest copy(original);

        REQUIRE(copy);
        REQUIRE(copy.handle() != nullptr);
        REQUIRE(copy.handle() != original.handle()); // Should be different handles
        REQUIRE(copy.version() == original.version());
    }

    SECTION("Copy assignment operator") {
        CertificateRequest copy;
        copy = original;

        REQUIRE(copy);
        REQUIRE(copy.handle() != nullptr);
        REQUIRE(copy.handle() != original.handle()); // Should be different handles
        REQUIRE(copy.version() == original.version());
    }

    SECTION("Self-assignment") {
        CertificateRequest req;

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wself-assign-overloaded"
#endif

        req = req; // Self-assignment should be safe

#ifdef __clang__
#pragma clang diagnostic pop
#endif

        REQUIRE(req);
        REQUIRE(req.handle() != nullptr);
    }
}

TEST_CASE("CertificateRequest Move Operations", "[certificate_request][move]") {
    CertificateRequest original;
    REQUIRE(original.set_version(CertificateRequest::Version::v1));

    auto* original_handle = original.handle();
    auto original_version = original.version();

    SECTION("Move constructor") {
        CertificateRequest moved(std::move(original));

        REQUIRE(moved);
        REQUIRE(moved.handle() == original_handle);
        REQUIRE(moved.version() == original_version);
        REQUIRE_FALSE(original); // Original should be empty after move
    }

    SECTION("Move assignment operator") {
        CertificateRequest moved;
        moved = std::move(original);

        REQUIRE(moved);
        REQUIRE(moved.handle() == original_handle);
        REQUIRE(moved.version() == original_version);
        REQUIRE_FALSE(original); // Original should be empty after move
    }
}

TEST_CASE_METHOD(CertificateRequestTestFixture, "CertificateRequest Public Key Operations", "[certificate_request][pubkey]") {
    CertificateRequest req;

    // Test data members
    EVP_PKEY* keypair = create_keypair();
    std::unique_ptr<PrivateKey> private_key = std::make_unique<PrivateKey>(keypair);
    std::unique_ptr<Key> public_key = private_key->pubkey();

    SECTION("Set and get public key") {
        REQUIRE_NOTHROW(req.set_pubkey(*public_key));
        REQUIRE_NOTHROW(req.pubkey());

        const Key dup_pubkey = req.pubkey();
        REQUIRE(dup_pubkey.handle() != nullptr);

        Key mutable_pubkey = req.pubkey();
        REQUIRE(mutable_pubkey.handle() != nullptr);
        REQUIRE(mutable_pubkey.handle() == dup_pubkey.handle());
    }
}

TEST_CASE_METHOD(CertificateRequestTestFixture, "CertificateRequest Subject Operations", "[certificate_request][subject]") {
    SECTION("Set and get subject") {
        CertificateName subject = create_certificate_name();

        CertificateRequest req;
        REQUIRE_NOTHROW(req.set_subject(subject));

        const CertificateName& subject_copy = req.subject();
        REQUIRE(subject_copy.handle() != nullptr);

        // Test non-const access
        // CertificateName& mutable_subject = req.subject();
        // REQUIRE(mutable_subject.handle() != nullptr);
        CertificateName mutable_subject = req.subject();
        REQUIRE(mutable_subject.handle() != subject_copy.handle());
    }
}

TEST_CASE_METHOD(CertificateRequestTestFixture, "CertificateRequest Signing Operations", "[certificate_request][signing]") {
    CertificateRequest req;
    CertificateName subject = create_certificate_name();

    EVP_PKEY* keypair = create_keypair();
    std::unique_ptr<PrivateKey> private_key = std::make_unique<PrivateKey>(keypair);
    std::unique_ptr<Key> public_key = private_key->pubkey();

    REQUIRE(req.set_version(CertificateRequest::Version::v1));
    REQUIRE_NOTHROW(req.set_pubkey(*public_key));
    REQUIRE_NOTHROW(req.set_subject(subject));

    SECTION("Sign certificate request with default digest") {
        REQUIRE_NOTHROW(req.sign(*private_key));
    }

    SECTION("Sign certificate request with specific digest") {
        REQUIRE_NOTHROW(req.sign(*private_key, Digest::TYPE_SHA256));
    }

    SECTION("Cannot sign invalid request") {
        CertificateRequest invalid_req;
        REQUIRE_THROWS_AS(invalid_req.sign(*private_key), std::runtime_error);
    }

    SECTION("Verify signature after signing") {
        REQUIRE_NOTHROW(req.sign(*private_key));
        REQUIRE(req.verify_signature(*public_key));
    }

    SECTION("Check private key correspondence") {
        REQUIRE_NOTHROW(req.sign(*private_key));
        REQUIRE(req.matches_private_key(*public_key));
    }
}

TEST_CASE("CertificateRequest Extensions", "[certificate_request][extensions]") {
    CertificateRequest req;

    SECTION("Add extensions") {
        // Create a simple extension stack for testing
        STACK_OF(X509_EXTENSION)* exts = sk_X509_EXTENSION_new_null();

        // Add a basic constraint extension
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_basic_constraints, "CA:FALSE");
        if (ext) {
            sk_X509_EXTENSION_push(exts, ext);
            REQUIRE_NOTHROW(req.add_extensions(exts));
        }

        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }

    SECTION("Can add extensions to default constructed request") {
        CertificateRequest invalid_req;
        STACK_OF(X509_EXTENSION)* exts = sk_X509_EXTENSION_new_null();

        REQUIRE_NOTHROW(invalid_req.add_extensions(exts));

        sk_X509_EXTENSION_free(exts);
    }
}

TEST_CASE_METHOD(CertificateRequestTestFixture, "CertificateRequest Verification Operations", "[certificate_request][verification]") {
    EVP_PKEY* keypair = create_keypair();
    std::unique_ptr<PrivateKey> private_key = std::make_unique<PrivateKey>(keypair);
    std::unique_ptr<Key> public_key = private_key->pubkey();

    CertificateName subject = create_certificate_name();
    CertificateRequest req;
    REQUIRE_NOTHROW(req.set_version(CertificateRequest::Version::v1));
    REQUIRE_NOTHROW(req.set_pubkey(*public_key));
    REQUIRE_NOTHROW(req.set_subject(subject));
    REQUIRE_NOTHROW(req.sign(*private_key));

    SECTION("Verify signature with correct key") {
        REQUIRE(req.verify_signature(*public_key));
    }

    SECTION("Check private key with correct key") {
        REQUIRE(req.matches_private_key(*public_key));
    }

    SECTION("Verification fails on default constructed request") {
        CertificateRequest default_req;
        REQUIRE_FALSE(default_req.verify_signature(*public_key));
        REQUIRE_FALSE(default_req.matches_private_key(*private_key));
    }
}

TEST_CASE_METHOD(CertificateRequestTestFixture, "CertificateRequest IO Operations", "[certificate_request][io]") {
    CertificateRequest req;
    CertificateName subject = create_certificate_name();

    EVP_PKEY* keypair = create_keypair();
    std::unique_ptr<PrivateKey> private_key = std::make_unique<PrivateKey>(keypair);
    std::unique_ptr<Key> public_key = private_key->pubkey();

    REQUIRE_NOTHROW(req.set_version(CertificateRequest::Version::v1));
    REQUIRE_NOTHROW(req.set_pubkey(*public_key));
    REQUIRE_NOTHROW(req.set_subject(subject));
    REQUIRE_NOTHROW(req.sign(*private_key));

    SECTION("Save certificate request") {
        MemorySink sink;
        sink.open_rw();

        REQUIRE_NOTHROW(req.save(sink));

        // Verify that data was written
        char* data;
        long len = BIO_get_mem_data(sink.handle(), &data);
        REQUIRE(len > 0);
    }

    SECTION("Cannot save invalid request") {
        CertificateRequest invalid_req;
        MemorySink sink;
        sink.open_rw();

        REQUIRE_THROWS_AS(invalid_req.save(sink), std::runtime_error);
    }

    SECTION("Load and save round trip") {
        // First save the request
        MemorySink save_sink;
        save_sink.open_rw();
        REQUIRE_NOTHROW(req.save(save_sink));

        // Get the saved data
        char* data;
        long len = BIO_get_mem_data(save_sink.handle(), &data);

        // Create a new BIO with the saved data for loading
        MemorySink load_sink;
        load_sink.open_ro(data, static_cast<int>(len));

        // Load into a new certificate request
        CertificateRequest loaded_req;
        REQUIRE_NOTHROW(loaded_req.load(load_sink));

        // Verify the loaded request
        REQUIRE(loaded_req);
        REQUIRE(loaded_req.version() == req.version());
    }
}

TEST_CASE_METHOD(CertificateRequestTestFixture, "CertificateRequest Complete Workflow", "[certificate_request][workflow]") {
    SECTION("Complete certificate request creation workflow") {
        CertificateRequest req;
        CertificateName subject = create_certificate_name();

        EVP_PKEY* keypair = create_keypair();
        std::unique_ptr<PrivateKey> private_key = std::make_unique<PrivateKey>(keypair);
        std::unique_ptr<Key> public_key = private_key->pubkey();

        // Step 1: Set version
        REQUIRE_NOTHROW(req.set_version(CertificateRequest::Version::v1));
        REQUIRE(req.version() == CertificateRequest::Version::v1);

        // Step 2: Set subject
        REQUIRE_NOTHROW(req.set_subject(subject));

        // Step 3: Set public key
        REQUIRE_NOTHROW(req.set_pubkey(*public_key));

        // Step 4: Sign the request
        REQUIRE_NOTHROW(req.sign(*private_key, Digest::TYPE_SHA256));

        // Step 5: Verify the request
        REQUIRE(req.verify_signature(*public_key));
        REQUIRE(req.matches_private_key(*private_key));

        // Step 6: Save the request
        MemorySink sink;
        sink.open_rw();
        REQUIRE_NOTHROW(req.save(sink));
    }
}

TEST_CASE_METHOD(CertificateRequestTestFixture, "CertificateRequest Error Handling", "[certificate_request][error_handling]") {
    SECTION("Operations on uninitialized request should fail gracefully") {
        CertificateRequest req{nullptr};
        CertificateName subject = create_certificate_name();

        EVP_PKEY* keypair = create_keypair();
        std::unique_ptr<PrivateKey> private_key = std::make_unique<PrivateKey>(keypair);
        std::unique_ptr<Key> public_key = private_key->pubkey();

        REQUIRE_FALSE(req);
        REQUIRE(req.handle() == nullptr);
        REQUIRE_THROWS_AS(req.set_version(CertificateRequest::Version::v1), std::logic_error);
        REQUIRE_THROWS_AS(req.set_pubkey(*public_key), std::logic_error);
        REQUIRE_THROWS_AS(req.set_subject(subject), std::logic_error);
        REQUIRE_THROWS_AS(req.sign(*private_key), std::logic_error);
        REQUIRE_THROWS_AS(req.verify_signature(*public_key), std::logic_error);
        REQUIRE_THROWS_AS(req.matches_private_key(*private_key), std::logic_error);
    }
}