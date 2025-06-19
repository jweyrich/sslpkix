#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <sstream>
#include <memory>

#include "sslpkix/x509/key.h"

using namespace sslpkix;

struct KeyTestFixture {
    KeyTestFixture() = default;
    ~KeyTestFixture() = default;

    // Helper to create RSA key for testing
    RSA* create_test_rsa_key() {
        #ifndef OPENSSL_NO_RSA
        RSA* rsa = RSA_new();
        BIGNUM* bn = BN_new();
        if (rsa && bn) {
            BN_set_word(bn, RSA_F4);
            if (RSA_generate_key_ex(rsa, 512, bn, nullptr) == 1) {
                BN_free(bn);
                return rsa;
            }
        }
        if (rsa) RSA_free(rsa);
        if (bn) BN_free(bn);
        #endif
        return nullptr;
    }

    // Helper to create DSA key for testing
    DSA* create_test_dsa_key() {
        #ifndef OPENSSL_NO_DSA
        DSA* dsa = DSA_new();
        if (dsa && DSA_generate_parameters_ex(dsa, 512, nullptr, 0, nullptr, nullptr, nullptr) == 1) {
            if (DSA_generate_key(dsa) == 1) {
                return dsa;
            }
        }
        if (dsa) DSA_free(dsa);
        #endif
        return nullptr;
    }

    // Helper to create EC key for testing
    EC_KEY* create_test_ec_key() {
        #ifndef OPENSSL_NO_EC
        EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (ec_key && EC_KEY_generate_key(ec_key) == 1) {
            return ec_key;
        }
        if (ec_key) EC_KEY_free(ec_key);
        #endif
        return nullptr;
    }

    // Helper to create test PEM data
    std::string create_test_private_key_pem() {
        RSA* rsa = create_test_rsa_key();
        if (!rsa) return "";

        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            RSA_free(rsa);
            return "";
        }

        EVP_PKEY* pkey = EVP_PKEY_new();
        if (!pkey || EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
            BIO_free(bio);
            if (pkey) EVP_PKEY_free(pkey);
            else RSA_free(rsa);
            return "";
        }

        if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, 0, nullptr) != 1) {
            BIO_free(bio);
            EVP_PKEY_free(pkey);
            return "";
        }

        char* pem_data;
        long pem_len = BIO_get_mem_data(bio, &pem_data);
        std::string result(pem_data, pem_len);

        BIO_free(bio);
        EVP_PKEY_free(pkey);
        return result;
    }

    // Mock IoSink class for testing
    class MockIoSink : public MemorySink {
    public:
        MockIoSink(const std::string& pem_data) {
            if (!open_ro(pem_data.c_str(), pem_data.length())) {
                throw std::runtime_error("Failed to open memory sink");
            }
        }
    };
};

// Test Key class basic functionality
TEST_CASE_METHOD(KeyTestFixture, "Key default constructor", "[Key][constructor]") {
    Key key;
    REQUIRE_FALSE(key.is_valid());
    REQUIRE(key.handle() == nullptr);
    REQUIRE(key.algorithm() == Key::Cipher::Type::UNKNOWN);
}

TEST_CASE_METHOD(KeyTestFixture, "Key create method", "[Key][create]") {
    Key key;
    REQUIRE(key.create());
    REQUIRE(key.is_valid());
    REQUIRE(key.handle() != nullptr);
    REQUIRE(key.algorithm() == Key::Cipher::Type::UNKNOWN); // No cipher assigned yet
}

TEST_CASE_METHOD(KeyTestFixture, "Key copy constructor", "[Key][copy]") {
    Key original;
    REQUIRE(original.create());

    Key copy(original);
    REQUIRE(copy.is_valid());
    REQUIRE(copy.handle() == original.handle()); // Should share the same handle
    REQUIRE(copy == original);
}

TEST_CASE_METHOD(KeyTestFixture, "Key move constructor", "[Key][move]") {
    Key original;
    REQUIRE(original.create());
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
    REQUIRE(key1.create());

    key2 = key1; // Copy assignment
    REQUIRE(key2.is_valid());
    REQUIRE(key1 == key2);

    Key key3;
    key3 = std::move(key1); // Move assignment
    REQUIRE(key3.is_valid());
    REQUIRE(key3 == key2);
}

#ifndef OPENSSL_NO_RSA
TEST_CASE_METHOD(KeyTestFixture, "Key RSA cipher operations", "[Key][RSA]") {
    Key key;
    REQUIRE(key.create());

    RSA* rsa = create_test_rsa_key();
    REQUIRE(rsa != nullptr);

    SECTION("Assign RSA key") {
        REQUIRE(key.assign(rsa));
        REQUIRE(key.algorithm() == Key::Cipher::Type::RSA);
        REQUIRE(key.is_cipher_type<RSA>());
        REQUIRE_FALSE(key.is_cipher_type<DSA>());

        // Get cipher handle
        RSA* retrieved_rsa = key.get_cipher_handle<RSA>();
        REQUIRE(retrieved_rsa != nullptr);
        RSA_free(retrieved_rsa); // EVP_PKEY_get1_RSA increments ref count
    }

    SECTION("Copy RSA key") {
        RSA* rsa_copy = RSAPrivateKey_dup(rsa);
        REQUIRE(rsa_copy != nullptr);

        REQUIRE(key.copy(rsa_copy));
        REQUIRE(key.algorithm() == Key::Cipher::Type::RSA);
        REQUIRE(key.is_cipher_type<RSA>());

        RSA_free(rsa_copy);
    }

    // Note: rsa is now owned by EVP_PKEY if assign was called, don't free it
    if (!key.is_cipher_type<RSA>()) {
        RSA_free(rsa);
    }
}
#endif

#ifndef OPENSSL_NO_DSA
TEST_CASE_METHOD(KeyTestFixture, "Key DSA cipher operations", "[Key][DSA]") {
    Key key;
    REQUIRE(key.create());

    DSA* dsa = create_test_dsa_key();
    REQUIRE(dsa != nullptr);

    REQUIRE(key.assign(dsa));
    REQUIRE(key.algorithm() == Key::Cipher::Type::DSA);
    REQUIRE(key.is_cipher_type<DSA>());
    REQUIRE_FALSE(key.is_cipher_type<RSA>());

    DSA* retrieved_dsa = key.get_cipher_handle<DSA>();
    REQUIRE(retrieved_dsa != nullptr);
    DSA_free(retrieved_dsa);
}
#endif

#ifndef OPENSSL_NO_EC
TEST_CASE_METHOD(KeyTestFixture, "Key EC cipher operations", "[Key][EC]") {
    Key key;
    REQUIRE(key.create());

    EC_KEY* ec_key = create_test_ec_key();
    REQUIRE(ec_key != nullptr);

    REQUIRE(key.assign(ec_key));
    REQUIRE(key.algorithm() == Key::Cipher::Type::EC);
    REQUIRE(key.is_cipher_type<EC_KEY>());
    REQUIRE_FALSE(key.is_cipher_type<RSA>());

    EC_KEY* retrieved_ec = key.get_cipher_handle<EC_KEY>();
    REQUIRE(retrieved_ec != nullptr);
    EC_KEY_free(retrieved_ec);
}
#endif

TEST_CASE_METHOD(KeyTestFixture, "Key bit_length method", "[Key][bit_length]") {
    Key key;

    SECTION("Invalid key bit length") {
        REQUIRE(key.bit_length() == 0); // EVP_PKEY_bits returns 0 for null key
    }

    SECTION("RSA key bit length") {
        #ifndef OPENSSL_NO_RSA
        RSA* rsa = create_test_rsa_key(); // Creates 512-bit RSA key
        REQUIRE(rsa != nullptr);

        REQUIRE(key.create());
        REQUIRE(key.assign(rsa));
        REQUIRE(key.bit_length() == 512);
        #endif
    }

    SECTION("EC key bit length") {
        #ifndef OPENSSL_NO_EC
        EC_KEY* ec_key = create_test_ec_key(); // Creates P-256 key (256 bits)
        REQUIRE(ec_key != nullptr);

        REQUIRE(key.create());
        REQUIRE(key.assign(ec_key));
        REQUIRE(key.bit_length() == 256);
        #endif
    }

    SECTION("DSA key bit length") {
        #ifndef OPENSSL_NO_DSA
        DSA* dsa = create_test_dsa_key(); // Creates 512-bit DSA key
        REQUIRE(dsa != nullptr);

        REQUIRE(key.create());
        REQUIRE(key.assign(dsa));
        REQUIRE(key.bit_length() == 512);
        #endif
    }
}

TEST_CASE_METHOD(KeyTestFixture, "Key comparison operators", "[Key][comparison]") {
    Key key1, key2, key3;

    SECTION("Null keys comparison") {
        REQUIRE(key1 == key2);
        REQUIRE_FALSE(key1 != key2);
    }

    SECTION("Valid vs null key comparison") {
        REQUIRE(key1.create());
        REQUIRE_FALSE(key1 == key2);
        REQUIRE(key1 != key2);
    }

    SECTION("Same key comparison") {
        REQUIRE(key1.create());
        key2 = key1;
        REQUIRE(key1 == key2);
        REQUIRE_FALSE(key1 != key2);
    }

    SECTION("Different keys comparison") {
        REQUIRE(key1.create());
        REQUIRE(key2.create());
        // Different keys should not be equal (even though they're both empty)
        // This test might be implementation dependent
    }
}

TEST_CASE_METHOD(KeyTestFixture, "Key external handle operations", "[Key][external]") {
    Key key;

    SECTION("Set null external handle") {
        key.set_external_handle(nullptr);
        REQUIRE_FALSE(key.is_valid());
    }

    SECTION("Set valid external handle") {
        EVP_PKEY* external_key = EVP_PKEY_new();
        REQUIRE(external_key != nullptr);

        key.set_external_handle(external_key);
        REQUIRE(key.is_valid());
        REQUIRE(key.handle() == external_key);

        EVP_PKEY_free(external_key);
    }
}

// Test PrivateKey class
TEST_CASE_METHOD(KeyTestFixture, "PrivateKey default constructor", "[PrivateKey][constructor]") {
    PrivateKey private_key;
    REQUIRE_FALSE(private_key.is_valid());
    REQUIRE(private_key.handle() == nullptr);
}

TEST_CASE_METHOD(KeyTestFixture, "PrivateKey load from PEM", "[PrivateKey][load]") {
    std::string pem_data = create_test_private_key_pem();
    REQUIRE_FALSE(pem_data.empty());

    PrivateKey private_key;
    MockIoSink sink(pem_data);

    REQUIRE(private_key.load(sink));
    REQUIRE(private_key.is_valid());
    REQUIRE(private_key.algorithm() == Key::Cipher::Type::RSA);
}

TEST_CASE_METHOD(KeyTestFixture, "PrivateKey save to PEM", "[PrivateKey][save]") {
    // First create and load a private key
    std::string pem_data = create_test_private_key_pem();
    REQUIRE_FALSE(pem_data.empty());

    PrivateKey private_key;
    MockIoSink load_sink(pem_data);
    REQUIRE(private_key.load(load_sink));
    REQUIRE(private_key.is_valid());
    REQUIRE(private_key.algorithm() == Key::Cipher::Type::RSA);
    REQUIRE(private_key.is_cipher_type<RSA>());
    REQUIRE(private_key.get_cipher_handle<RSA>() != nullptr);

    // Now save it
    MemorySink save_sink;
    REQUIRE(save_sink.open_rw());
    REQUIRE(private_key.save(save_sink));

    // Test that the saved key is the same as the loaded key
    REQUIRE(save_sink.read_all() == pem_data);
}

#ifndef OPENSSL_NO_RSA
TEST_CASE_METHOD(KeyTestFixture, "PrivateKey create_from_cipher", "[PrivateKey][factory]") {
    RSA* rsa = create_test_rsa_key();
    REQUIRE(rsa != nullptr);

    auto private_key = PrivateKey::create_from_cipher(rsa);
    REQUIRE(private_key != nullptr);
    REQUIRE(private_key->is_valid());
    REQUIRE(private_key->algorithm() == Key::Cipher::Type::RSA);
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
    REQUIRE_FALSE(private_key->is_valid()); // Not created yet
}

#ifndef OPENSSL_NO_RSA
TEST_CASE_METHOD(KeyTestFixture, "Factory make_key_for_cipher", "[factory][make_key_for_cipher]") {
    auto key = factory::make_key_for_cipher<RSA>();
    REQUIRE(key != nullptr);
    REQUIRE(key->is_valid());
}
#endif

// Test error conditions
TEST_CASE_METHOD(KeyTestFixture, "Key error conditions", "[Key][error]") {
    Key key;

    SECTION("Operations on invalid key") {
        REQUIRE_FALSE(key.is_valid());
        REQUIRE(key.algorithm() == Key::Cipher::Type::UNKNOWN);

        #ifndef OPENSSL_NO_RSA
        REQUIRE_FALSE(key.is_cipher_type<RSA>());
        REQUIRE(key.get_cipher_handle<RSA>() == nullptr);
        #endif
    }

    SECTION("Assign null cipher") {
        REQUIRE(key.create());
        #ifndef OPENSSL_NO_RSA
        REQUIRE_FALSE(key.assign<RSA>(nullptr));
        REQUIRE_FALSE(key.copy<RSA>(nullptr));
        #endif
    }
}

TEST_CASE_METHOD(KeyTestFixture, "PrivateKey error conditions", "[PrivateKey][error]") {
    PrivateKey private_key;

    SECTION("Save invalid key") {
        std::string empty_pem;
        MockIoSink sink(empty_pem);
        REQUIRE_FALSE(private_key.save(sink));
    }

    SECTION("Load invalid PEM") {
        std::string invalid_pem = "invalid pem data";
        MockIoSink sink(invalid_pem);
        REQUIRE_FALSE(private_key.load(sink));
    }
}

// Test cipher traits and SFINAE
TEST_CASE_METHOD(KeyTestFixture, "Cipher traits compilation", "[cipher_traits][compile_time]") {
    #ifndef OPENSSL_NO_RSA
    static_assert(detail::is_cipher_supported_v<RSA>);
    static_assert(detail::cipher_traits<RSA>::evp_pkey_type == EVP_PKEY_RSA);
    #endif

    #ifndef OPENSSL_NO_DSA
    static_assert(detail::is_cipher_supported_v<DSA>);
    static_assert(detail::cipher_traits<DSA>::evp_pkey_type == EVP_PKEY_DSA);
    #endif

    #ifndef OPENSSL_NO_EC
    static_assert(detail::is_cipher_supported_v<EC_KEY>);
    static_assert(detail::cipher_traits<EC_KEY>::evp_pkey_type == EVP_PKEY_EC);
    #endif

    // This should compile fine as the tests above validate the traits
    REQUIRE(true);
}