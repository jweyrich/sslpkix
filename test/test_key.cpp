#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <sstream>
#include <memory>

#include "sslpkix/x509/key.h"

using namespace sslpkix;

struct KeyTestFixture {
    KeyTestFixture() = default;
    ~KeyTestFixture() = default;

    KeyTestFixture(const KeyTestFixture&) = delete;
    KeyTestFixture& operator=(const KeyTestFixture&) = delete;
    KeyTestFixture(KeyTestFixture&&) = delete;
    KeyTestFixture& operator=(KeyTestFixture&&) = delete;

    // Helper to create test PEM data
    std::string create_test_private_key_pem() {
        auto keypair = factory::generate_key_rsa(512);
        PrivateKey private_key(keypair);

        MemorySink memory_sink;
        REQUIRE_NOTHROW(memory_sink.open_rw());
        private_key.save(memory_sink);
        return memory_sink.read_all();
    }
};

// Test Key class basic functionality
TEST_CASE_METHOD(KeyTestFixture, "Key default constructor", "[Key][constructor]") {
    Key key;
    REQUIRE(key.is_valid());
    REQUIRE(key.handle() != nullptr);
    REQUIRE(key.algorithm() == KeyType::UNKNOWN);
}

TEST_CASE_METHOD(KeyTestFixture, "Key create method", "[Key][create]") {
    Key key;
    REQUIRE(key.is_valid());
    REQUIRE(key.handle() != nullptr);
    REQUIRE(key.algorithm() == KeyType::UNKNOWN); // Key is not generated yet
}

TEST_CASE_METHOD(KeyTestFixture, "Key move constructor", "[Key][move]") {
    Key original;
    EVP_PKEY* original_handle = original.handle();

    Key moved(std::move(original));
    REQUIRE(moved.is_valid());
    REQUIRE(moved.handle() == original_handle);
    // Original should be invalid after move (shared_ptr was moved)
    REQUIRE_FALSE(original.is_valid());
    REQUIRE(original.handle() == nullptr);
}

TEST_CASE_METHOD(KeyTestFixture, "Key assignment operators", "[Key][assignment]") {
    Key key1, key2;

    key2 = std::move(key1); // Move assignment
    REQUIRE(key1.handle() == nullptr);
    REQUIRE_FALSE(key1.is_valid());
    REQUIRE(key2.handle() != nullptr);
    REQUIRE(key2.is_valid());
    REQUIRE(key2 != key1);
}

TEST_CASE_METHOD(KeyTestFixture, "Key assignment", "[Key][assignment]") {
    auto keypair = factory::generate_key_rsa(512);
    REQUIRE(keypair != nullptr);

    PrivateKey private_key(keypair);
    Key new_key;

    REQUIRE_NOTHROW(new_key.assign(keypair));
    REQUIRE(new_key.algorithm() == KeyType::RSA);
    REQUIRE(new_key == private_key);
    REQUIRE(new_key.has_public_key());
    REQUIRE(new_key.has_private_key());
}

#ifndef OPENSSL_NO_RSA
TEST_CASE_METHOD(KeyTestFixture, "Key RSA operations", "[Key][RSA]") {
    auto keypair = factory::generate_key_rsa(512);
    REQUIRE(keypair != nullptr);

    PrivateKey private_key(keypair);
    auto pubkey_only = private_key.pubkey();
    Key *public_key = pubkey_only.get();

    SECTION("Assign RSA keypair") {
        Key new_key;
        REQUIRE_NOTHROW(new_key.assign(keypair));
        REQUIRE(new_key.algorithm() == KeyType::RSA);
        REQUIRE(new_key == *public_key);
        REQUIRE(new_key == private_key);
        REQUIRE(new_key.has_public_key());
        REQUIRE(new_key.has_private_key());
    }

    SECTION("Copy RSA keypair") {
        Key new_key;
        REQUIRE_NOTHROW(new_key.copy(keypair));
        REQUIRE(new_key.algorithm() == KeyType::RSA);
        REQUIRE(new_key == *public_key);
        REQUIRE(new_key == private_key);
        REQUIRE(new_key.has_public_key());
        REQUIRE(new_key.has_private_key());
    }

    SECTION("Assign RSA public key") {
        Key new_key;
        REQUIRE_NOTHROW(new_key.assign(public_key->handle()));
        REQUIRE(new_key.algorithm() == KeyType::RSA);
        REQUIRE(new_key == *public_key);
        REQUIRE(new_key == private_key);
        REQUIRE(new_key.has_public_key());
        REQUIRE_FALSE(new_key.has_private_key());
    }

    SECTION("Copy RSA public key") {
        Key new_key;
        REQUIRE_NOTHROW(new_key.copy(public_key->handle()));
        REQUIRE(new_key.algorithm() == KeyType::RSA);
        REQUIRE(new_key == *public_key);
        REQUIRE(new_key == private_key);
        REQUIRE(new_key.has_public_key());
        REQUIRE_FALSE(new_key.has_private_key());
    }
}
#endif

// #ifndef OPENSSL_NO_DSA
// TEST_CASE_METHOD(KeyTestFixture, "Key DSA operations", "[Key][DSA]") {
//     auto keypair = factory::generate_key_dsa(2048, 256);
//     REQUIRE(keypair != nullptr);
//
//     Key key;
//     REQUIRE_NOTHROW(key.assign(keypair));
//     REQUIRE(key.algorithm() == KeyType::DSA);
// }
// #endif

#ifndef OPENSSL_NO_EC
TEST_CASE_METHOD(KeyTestFixture, "Key EC operations", "[Key][EC]") {
    auto keypair = factory::generate_key_ec(traits::EC::KeyGroup::P256);
    REQUIRE(keypair != nullptr);

    Key key;
    REQUIRE_NOTHROW(key.assign(keypair));
    REQUIRE(key.algorithm() == KeyType::EC);
}
#endif

TEST_CASE_METHOD(KeyTestFixture, "Key bit_length method", "[Key][bit_length]") {
    Key key;

    SECTION("Invalid key bit length") {
        REQUIRE(key.bit_length() == 0); // EVP_PKEY_bits returns 0 for null key
    }

    #ifndef OPENSSL_NO_RSA
    SECTION("RSA key bit length") {
        auto keypair = factory::generate_key_rsa(512);
        REQUIRE(keypair != nullptr);
        REQUIRE_NOTHROW(key.assign(keypair));
        REQUIRE(key.bit_length() == 512);
    }
    #endif

    // #ifndef OPENSSL_NO_DSA
    // SECTION("DSA key bit length") {
    //     auto keypair = factory::generate_key_dsa(2048, 256);
    //     REQUIRE(keypair != nullptr);
    //
    //     REQUIRE_NOTHROW(key.assign(keypair));
    //     REQUIRE(key.bit_length() == 512);
    // }
    // #endif

    #ifndef OPENSSL_NO_EC
    SECTION("EC key bit length") {
        auto keypair = factory::generate_key_ec(traits::EC::KeyGroup::P256);
        REQUIRE(keypair != nullptr);
        REQUIRE_NOTHROW(key.assign(keypair));
        REQUIRE(key.bit_length() == 256);
    }
    #endif
}

TEST_CASE_METHOD(KeyTestFixture, "Key comparison operators", "[Key][comparison]") {
    Key key1, key2, key3;

    SECTION("Default keys comparison") {
        // Comparting invalid keys should throw an error
        REQUIRE_THROWS_AS(key1 != key2, error::key::RuntimeError);
        REQUIRE_THROWS_AS(key1 == key2, error::key::RuntimeError);
    }

    SECTION("Different keys comparison") {
        // Copying a key should result in an equal key
        // So comparing the copied key with the original should not throw an error
        Key copied_key1(key1.handle());
        REQUIRE(copied_key1 == key1);
        REQUIRE_FALSE(copied_key1 != key1);

        Key copied_key2(key2.handle());
        REQUIRE(copied_key2 == key2);
        REQUIRE_FALSE(copied_key2 != key2);

        // Moving a key invalidates the original key
        // So comparing the new key with the original should return false
        Key new_key3(std::move(key1));
        REQUIRE(new_key3 != key1);
        REQUIRE_FALSE(new_key3 == key1);
        // While the new key is valid, the original key is invalid
        REQUIRE(new_key3.is_valid());
        REQUIRE_FALSE(key1.is_valid());
        // The new key should have a handle, the original key should not
        REQUIRE(new_key3.handle() != nullptr);
        REQUIRE(key1.handle() == nullptr);
    }
}

TEST_CASE_METHOD(KeyTestFixture, "Key external handle operations", "[Key][external]") {
    Key key;

    SECTION("Assign a null external handle") {
        EVP_PKEY* external_key = nullptr;

        Key new_key(external_key);
        REQUIRE_FALSE(new_key.is_valid());
        REQUIRE(new_key.handle() == external_key);
    }

    SECTION("Assign a valid external handle") {
        EVP_PKEY* external_key = EVP_PKEY_new();
        REQUIRE(external_key != nullptr);

        Key new_key(external_key);
        REQUIRE(new_key.is_valid());
        REQUIRE(new_key.handle() == external_key);

        EVP_PKEY_free(external_key);
    }
}

// Test PrivateKey class
TEST_CASE_METHOD(KeyTestFixture, "PrivateKey default constructor", "[PrivateKey][constructor]") {
    PrivateKey private_key;
    REQUIRE(private_key.is_valid());
    REQUIRE(private_key.handle() != nullptr);
}

TEST_CASE_METHOD(KeyTestFixture, "PrivateKey load from PEM", "[PrivateKey][load]") {
    std::string pem_data = create_test_private_key_pem();
    REQUIRE_FALSE(pem_data.empty());

    PrivateKey private_key;
    MemorySink sink;

    REQUIRE_NOTHROW(sink.open_ro(pem_data.c_str(), pem_data.length()));
    REQUIRE_NOTHROW(private_key.load(sink));
    REQUIRE(private_key.is_valid());
    REQUIRE(private_key.algorithm() == KeyType::RSA);
}

TEST_CASE_METHOD(KeyTestFixture, "PrivateKey save to PEM", "[PrivateKey][save]") {
    // First create and load a private key
    std::string pem_data = create_test_private_key_pem();
    REQUIRE_FALSE(pem_data.empty());

    PrivateKey private_key;
    MemorySink load_sink;

    REQUIRE_NOTHROW(load_sink.open_ro(pem_data.c_str(), pem_data.length()));
    REQUIRE_NOTHROW(private_key.load(load_sink));
    REQUIRE(private_key.is_valid());
    REQUIRE(private_key.algorithm() == KeyType::RSA);

    // Now save it
    MemorySink save_sink;
    REQUIRE_NOTHROW(save_sink.open_rw());
    REQUIRE_NOTHROW(private_key.save(save_sink));

    // Test that the saved key is the same as the loaded key
    REQUIRE(save_sink.read_all() == pem_data);
}

#ifndef OPENSSL_NO_RSA
TEST_CASE_METHOD(KeyTestFixture, "PrivateKey constructor for external handle", "[PrivateKey][contructor_for_external_handle]") {
    auto keypair = factory::generate_key_rsa(512);
    REQUIRE(keypair != nullptr);

    PrivateKey private_key(keypair);
    REQUIRE(private_key.handle() != nullptr);
    REQUIRE(private_key.is_valid());
    REQUIRE(private_key.algorithm() == KeyType::RSA);
}
#endif

// Test factory functions
TEST_CASE_METHOD(KeyTestFixture, "Factory make_key", "[factory][make_key]") {
    auto key = factory::make_key();
    REQUIRE(key != nullptr);
    REQUIRE(key->is_valid());
}

TEST_CASE_METHOD(KeyTestFixture, "Factory make_private_key", "[factory][make_private_key]") {
    auto private_key = factory::make_private_key();
    REQUIRE(private_key != nullptr);
    REQUIRE(private_key->is_valid());
}

// Test error conditions
TEST_CASE_METHOD(KeyTestFixture, "Key error conditions", "[Key][error]") {
    Key key;

    SECTION("Operations on default constructed key") {
        REQUIRE(key.is_valid());
        REQUIRE(key.algorithm() == KeyType::UNKNOWN);
    }

    SECTION("Assign null key") {
        REQUIRE_THROWS_AS(key.assign(nullptr), error::key::InvalidArgumentError);
    }

    SECTION("Copy null key") {
        REQUIRE_THROWS_AS(key.copy(nullptr), error::key::InvalidArgumentError);
    }
}

TEST_CASE_METHOD(KeyTestFixture, "PrivateKey error conditions", "[PrivateKey][error]") {
    PrivateKey private_key;

    SECTION("Save default constructed key") {
        std::string empty_pem;
        MemorySink sink;
        // This should throw a std::logic_error because the buffer is empty
        REQUIRE_THROWS_AS(sink.open_ro(empty_pem.c_str(), empty_pem.length()), std::invalid_argument);
        REQUIRE_THROWS_AS(private_key.save(sink), std::runtime_error);
    }

    SECTION("Load invalid PEM") {
        std::string invalid_pem = "invalid pem data";
        MemorySink sink;
        REQUIRE_NOTHROW(sink.open_ro(invalid_pem.c_str(), invalid_pem.length()));
        REQUIRE_THROWS_AS(private_key.load(sink), error::key::RuntimeError);
    }
}

TEST_CASE_METHOD(KeyTestFixture, "Key pubkey", "[Key][pubkey]") {
    auto keypair = sslpkix::factory::generate_key_rsa(512);
    auto private_key = std::make_unique<sslpkix::PrivateKey>(keypair);
    // Create a public key from the private key
    auto public_key = std::make_unique<sslpkix::Key>(private_key->handle());
    // Extract the public key from the private key
    auto extracted_public_key = private_key->pubkey();

    // Print the public keys to memory sinks
    MemorySink sink1, sink2;
    sink1.open_rw();
    sink2.open_rw();

    // Print the public keys to the memory sinks
    public_key->print_ex(sink1.handle());
    extracted_public_key->print_ex(sink2.handle());

    // Compare the printed public keys
    REQUIRE(sink1.read_all() == sink2.read_all());
}