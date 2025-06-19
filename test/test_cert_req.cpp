#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <openssl/evp.h>
#include <openssl/rsa.h>
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
    CertificateRequestTestFixture() {
        // Create a test RSA key pair for testing
        createTestKeyPair();

        // Create a test certificate name
        createTestCertificateName();
    }

    ~CertificateRequestTestFixture() {
        // Cleanup is handled by RAII
    }

    void createTestKeyPair() {
        // Create RSA key pair
        EVP_PKEY* pkey = EVP_PKEY_new();
        RSA* rsa = RSA_new();
        BIGNUM* bn = BN_new();

        REQUIRE(BN_set_word(bn, RSA_F4) == 1);
        REQUIRE(RSA_generate_key_ex(rsa, 512, bn, nullptr) == 1);
        // Ownership of rsa is transferred to pkey
        REQUIRE(EVP_PKEY_assign_RSA(pkey, rsa) == 1);

        // Wrap in our Key classes
        testPublicKey.set_external_handle(pkey);
        testPrivateKey.set_external_handle(pkey);

        BN_free(bn);
        // pkey and rsa are now owned by the Key objects
    }

    void createTestCertificateName() {
        // Create a test subject name
        REQUIRE_NOTHROW(testSubject.add_entry("C", "US"));
        REQUIRE_NOTHROW(testSubject.add_entry("ST", "California"));
        REQUIRE_NOTHROW(testSubject.add_entry("L", "San Francisco"));
        REQUIRE_NOTHROW(testSubject.add_entry("O", "Test Organization"));
        REQUIRE_NOTHROW(testSubject.add_entry("CN", "test.example.com"));
    }

    // Test data members
    Key testPublicKey;
    PrivateKey testPrivateKey;
    CertificateName testSubject;
};

TEST_CASE_METHOD(CertificateRequestTestFixture, "CertificateRequest Default Constructor", "[certificate_request][constructor]") {
    CertificateRequest req;

    SECTION("Default constructed request should be invalid") {
        REQUIRE_FALSE(req);
        REQUIRE(req.handle() == nullptr);
        REQUIRE(req.version() == CertificateRequest::Version::invalid);
    }
}

TEST_CASE_METHOD(CertificateRequestTestFixture, "CertificateRequest Creation", "[certificate_request][creation]") {
    CertificateRequest req;

    SECTION("Create new certificate request") {
        REQUIRE(req.create());
        REQUIRE(req);
        REQUIRE(req.handle() != nullptr);
    }

    SECTION("Set version after creation") {
        REQUIRE(req.create());
        REQUIRE(req.set_version(CertificateRequest::Version::v1));
        REQUIRE(req.version() == CertificateRequest::Version::v1);
    }

    SECTION("Cannot set version on invalid request") {
        REQUIRE_FALSE(req.set_version(CertificateRequest::Version::v1));
        REQUIRE(req.version() == CertificateRequest::Version::invalid);
    }
}

TEST_CASE_METHOD(CertificateRequestTestFixture, "CertificateRequest Copy Operations", "[certificate_request][copy]") {
    CertificateRequest original;
    REQUIRE(original.create());
    REQUIRE(original.set_version(CertificateRequest::Version::v1));
    REQUIRE(original.set_subject(testSubject));
    REQUIRE(original.set_pubkey(testPublicKey));
    REQUIRE(original.sign(testPublicKey, Digest::TYPE_SHA256));

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
        REQUIRE(req.create());

        req = req; // Self-assignment should be safe
        REQUIRE(req);
        REQUIRE(req.handle() != nullptr);
    }
}

TEST_CASE_METHOD(CertificateRequestTestFixture, "CertificateRequest Move Operations", "[certificate_request][move]") {
    CertificateRequest original;
    REQUIRE(original.create());
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
    REQUIRE(req.create());

    SECTION("Set and get public key") {
        REQUIRE(req.set_pubkey(testPublicKey));

        const Key& pubkey = req.pubkey();
        REQUIRE(pubkey.handle() != nullptr);

        // Test non-const access
        Key& mutable_pubkey = req.pubkey();
        REQUIRE(mutable_pubkey.handle() != nullptr);
    }

    SECTION("Cannot set public key on invalid request") {
        CertificateRequest invalid_req;
        REQUIRE_FALSE(invalid_req.set_pubkey(testPublicKey));
    }
}

TEST_CASE_METHOD(CertificateRequestTestFixture, "CertificateRequest Subject Operations", "[certificate_request][subject]") {
    CertificateRequest req;
    REQUIRE(req.create());

    SECTION("Set and get subject") {
        REQUIRE(req.set_subject(testSubject));

        const CertificateName& subject = req.subject();
        REQUIRE(subject.handle() != nullptr);

        // Test non-const access
        CertificateName& mutable_subject = req.subject();
        REQUIRE(mutable_subject.handle() != nullptr);
    }

    SECTION("Cannot set subject on invalid request") {
        CertificateRequest invalid_req;
        REQUIRE_FALSE(invalid_req.set_subject(testSubject));
    }
}

TEST_CASE_METHOD(CertificateRequestTestFixture, "CertificateRequest Signing Operations", "[certificate_request][signing]") {
    CertificateRequest req;
    REQUIRE(req.create());
    REQUIRE(req.set_version(CertificateRequest::Version::v1));
    REQUIRE(req.set_pubkey(testPublicKey));
    REQUIRE(req.set_subject(testSubject));

    SECTION("Sign certificate request with default digest") {
        REQUIRE(req.sign(testPrivateKey));
    }

    SECTION("Sign certificate request with specific digest") {
        REQUIRE(req.sign(testPrivateKey, Digest::TYPE_SHA256));
    }

    SECTION("Cannot sign invalid request") {
        CertificateRequest invalid_req;
        REQUIRE_FALSE(invalid_req.sign(testPrivateKey));
    }

    SECTION("Verify signature after signing") {
        REQUIRE(req.sign(testPrivateKey));
        REQUIRE(req.verify_signature(testPublicKey));
    }

    SECTION("Check private key correspondence") {
        REQUIRE(req.sign(testPrivateKey));
        REQUIRE(req.check_private_key(testPrivateKey));
    }
}

TEST_CASE_METHOD(CertificateRequestTestFixture, "CertificateRequest Extensions", "[certificate_request][extensions]") {
    CertificateRequest req;
    REQUIRE(req.create());

    SECTION("Add extensions") {
        // Create a simple extension stack for testing
        STACK_OF(X509_EXTENSION)* exts = sk_X509_EXTENSION_new_null();

        // Add a basic constraint extension
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_basic_constraints, "CA:FALSE");
        if (ext) {
            sk_X509_EXTENSION_push(exts, ext);
            REQUIRE(req.add_extensions(exts));
        }

        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }

    SECTION("Cannot add extensions to invalid request") {
        CertificateRequest invalid_req;
        STACK_OF(X509_EXTENSION)* exts = sk_X509_EXTENSION_new_null();

        REQUIRE_FALSE(invalid_req.add_extensions(exts));

        sk_X509_EXTENSION_free(exts);
    }
}

TEST_CASE_METHOD(CertificateRequestTestFixture, "CertificateRequest Verification Operations", "[certificate_request][verification]") {
    CertificateRequest req;
    REQUIRE(req.create());
    REQUIRE(req.set_version(CertificateRequest::Version::v1));
    REQUIRE(req.set_pubkey(testPublicKey));
    REQUIRE(req.set_subject(testSubject));
    REQUIRE(req.sign(testPrivateKey));

    SECTION("Verify signature with correct key") {
        REQUIRE(req.verify_signature(testPublicKey));
    }

    SECTION("Check private key with correct key") {
        REQUIRE(req.check_private_key(testPrivateKey));
    }

    SECTION("Verification fails on invalid request") {
        CertificateRequest invalid_req;
        REQUIRE_FALSE(invalid_req.verify_signature(testPublicKey));
        REQUIRE_FALSE(invalid_req.check_private_key(testPrivateKey));
    }
}

TEST_CASE_METHOD(CertificateRequestTestFixture, "CertificateRequest IO Operations", "[certificate_request][io]") {
    CertificateRequest req;
    REQUIRE(req.create());
    REQUIRE(req.set_version(CertificateRequest::Version::v1));
    REQUIRE(req.set_pubkey(testPublicKey));
    REQUIRE(req.set_subject(testSubject));
    REQUIRE(req.sign(testPrivateKey));

    SECTION("Save certificate request") {
        MemorySink sink;
        sink.open_rw();

        REQUIRE(req.save(sink));

        // Verify that data was written
        char* data;
        long len = BIO_get_mem_data(sink.handle(), &data);
        REQUIRE(len > 0);
    }

    SECTION("Cannot save invalid request") {
        CertificateRequest invalid_req;
        MemorySink sink;
        sink.open_rw();

        REQUIRE_FALSE(invalid_req.save(sink));
    }

    SECTION("Load and save round trip") {
        // First save the request
        MemorySink save_sink;
        save_sink.open_rw();
        REQUIRE(req.save(save_sink));

        // Get the saved data
        char* data;
        long len = BIO_get_mem_data(save_sink.handle(), &data);

        // Create a new BIO with the saved data for loading
        MemorySink load_sink;
        load_sink.open_ro(data, static_cast<int>(len));

        // Load into a new certificate request
        CertificateRequest loaded_req;
        REQUIRE(loaded_req.load(load_sink));

        // Verify the loaded request
        REQUIRE(loaded_req);
        REQUIRE(loaded_req.version() == req.version());
    }
}

TEST_CASE_METHOD(CertificateRequestTestFixture, "CertificateRequest Complete Workflow", "[certificate_request][workflow]") {
    SECTION("Complete certificate request creation workflow") {
        CertificateRequest req;

        // Step 1: Create the request
        REQUIRE(req.create());

        // Step 2: Set version
        REQUIRE(req.set_version(CertificateRequest::Version::v1));
        REQUIRE(req.version() == CertificateRequest::Version::v1);

        // Step 3: Set subject
        REQUIRE(req.set_subject(testSubject));

        // Step 4: Set public key
        REQUIRE(req.set_pubkey(testPublicKey));

        // Step 5: Sign the request
        REQUIRE(req.sign(testPrivateKey, Digest::TYPE_SHA256));

        // Step 6: Verify the request
        REQUIRE(req.verify_signature(testPublicKey));
        REQUIRE(req.check_private_key(testPrivateKey));

        // Step 7: Save the request
        MemorySink sink;
        sink.open_rw();
        REQUIRE(req.save(sink));
    }
}

TEST_CASE_METHOD(CertificateRequestTestFixture, "CertificateRequest Error Handling", "[certificate_request][error_handling]") {
    SECTION("Operations on uninitialized request should fail gracefully") {
        CertificateRequest req;

        REQUIRE_FALSE(req);
        REQUIRE(req.handle() == nullptr);
        REQUIRE_FALSE(req.set_version(CertificateRequest::Version::v1));
        REQUIRE_FALSE(req.set_pubkey(testPublicKey));
        REQUIRE_FALSE(req.set_subject(testSubject));
        REQUIRE_FALSE(req.sign(testPrivateKey));
        REQUIRE_FALSE(req.verify_signature(testPublicKey));
        REQUIRE_FALSE(req.check_private_key(testPrivateKey));
    }
}