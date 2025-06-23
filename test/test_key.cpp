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

    KeyTestFixture(const KeyTestFixture&) = delete;
    KeyTestFixture& operator=(const KeyTestFixture&) = delete;
    KeyTestFixture(KeyTestFixture&&) = delete;
    KeyTestFixture& operator=(KeyTestFixture&&) = delete;

    // Helper to create RSA key for testing
    RSA* create_test_rsa_key() {
        #ifndef OPENSSL_NO_RSA
        std::unique_ptr<RSA, decltype(&RSA_free)> rsa(RSA_new(), RSA_free);
        std::unique_ptr<BIGNUM, decltype(&BN_free)> bn(BN_new(), BN_free);
        if (rsa.get() && bn.get()) {
            BN_set_word(bn.get(), RSA_F4);
            if (RSA_generate_key_ex(rsa.get(), 512, bn.get(), nullptr) == 1) {
                return rsa.release(); // Transfer ownership to caller
            }
        }
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
};

// Test Key class basic functionality
TEST_CASE_METHOD(KeyTestFixture, "Key default constructor", "[Key][constructor]") {
    Key key;
    REQUIRE(key.is_valid());
    REQUIRE(key.handle() != nullptr);
    REQUIRE(key.algorithm() == Key::Cipher::Type::UNKNOWN);
}

TEST_CASE_METHOD(KeyTestFixture, "Key create method", "[Key][create]") {
    Key key;
    REQUIRE(key.is_valid());
    REQUIRE(key.handle() != nullptr);
    REQUIRE(key.algorithm() == Key::Cipher::Type::UNKNOWN); // No cipher assigned yet
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

#ifndef OPENSSL_NO_RSA
TEST_CASE_METHOD(KeyTestFixture, "Key RSA cipher operations", "[Key][RSA]") {
    RSA* rsa = create_test_rsa_key();
    REQUIRE(rsa != nullptr);

    Key key;

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
    DSA* dsa = create_test_dsa_key();
    REQUIRE(dsa != nullptr);

    Key key;
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
    EC_KEY* ec_key = create_test_ec_key();
    REQUIRE(ec_key != nullptr);

    Key key;
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

        REQUIRE(key.assign(rsa));
        REQUIRE(key.bit_length() == 512);
        #endif
    }

    SECTION("EC key bit length") {
        #ifndef OPENSSL_NO_EC
        EC_KEY* ec_key = create_test_ec_key(); // Creates P-256 key (256 bits)
        REQUIRE(ec_key != nullptr);

        REQUIRE(key.assign(ec_key));
        REQUIRE(key.bit_length() == 256);
        #endif
    }

    SECTION("DSA key bit length") {
        #ifndef OPENSSL_NO_DSA
        DSA* dsa = create_test_dsa_key(); // Creates 512-bit DSA key
        REQUIRE(dsa != nullptr);

        REQUIRE(key.assign(dsa));
        REQUIRE(key.bit_length() == 512);
        #endif
    }
}

TEST_CASE_METHOD(KeyTestFixture, "Key comparison operators", "[Key][comparison]") {
    Key key1, key2, key3;

    SECTION("Default keys comparison") {
        // Different keys should not be equal (even though they're both default constructed)
        REQUIRE(key1 != key2);
        REQUIRE_FALSE(key1 == key2);
    }

    SECTION("Different keys comparison") {
        Key copied_key1(key1.handle());
        REQUIRE(copied_key1 == key1);
        REQUIRE_FALSE(copied_key1 != key1);

        Key copied_key2(key2.handle());
        REQUIRE(copied_key2 == key2);
        REQUIRE_FALSE(copied_key2 != key2);

        Key new_key3(std::move(key1));
        REQUIRE(new_key3 != key1);
        REQUIRE_FALSE(new_key3 == key1);
        REQUIRE(new_key3.is_valid());
        REQUIRE_FALSE(key1.is_valid());
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

        // EVP_PKEY_free(external_key);
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
    REQUIRE(private_key.algorithm() == Key::Cipher::Type::RSA);
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
    REQUIRE(private_key.algorithm() == Key::Cipher::Type::RSA);
    REQUIRE(private_key.is_cipher_type<RSA>());
    REQUIRE(private_key.get_cipher_handle<RSA>() != nullptr);

    // Now save it
    MemorySink save_sink;
    REQUIRE_NOTHROW(save_sink.open_rw());
    REQUIRE_NOTHROW(private_key.save(save_sink));

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
    REQUIRE(private_key->is_valid());
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

    SECTION("Operations on default constructed key") {
        REQUIRE(key.is_valid());
        REQUIRE(key.algorithm() == Key::Cipher::Type::UNKNOWN);

        #ifndef OPENSSL_NO_RSA
        REQUIRE_FALSE(key.is_cipher_type<RSA>());
        REQUIRE(key.get_cipher_handle<RSA>() == nullptr);
        #endif
    }

    SECTION("Assign null cipher") {
        #ifndef OPENSSL_NO_RSA
        REQUIRE_FALSE(key.assign<RSA>(nullptr));
        REQUIRE_FALSE(key.copy<RSA>(nullptr));
        #endif
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
        REQUIRE_THROWS_AS(private_key.load(sink), KeyException);
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