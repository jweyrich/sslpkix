#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_template_test_macros.hpp>
#include <fstream>
#include <filesystem>
#include <cstring>
#include <sstream>
#include "sslpkix/iosink.h"

using namespace sslpkix;

// Test fixture for creating temporary files
class TempFileFixture {
public:
    TempFileFixture() : temp_filename("test_temp_file.txt") {}

    ~TempFileFixture() {
        cleanup();
    }

    TempFileFixture(const TempFileFixture&) = delete;
    TempFileFixture& operator=(const TempFileFixture&) = delete;
    TempFileFixture(TempFileFixture&&) = delete;
    TempFileFixture& operator=(TempFileFixture&&) = delete;

    void create_test_file(const std::string& content) {
        std::ofstream file(temp_filename);
        file << content;
        file.close();
    }

    void cleanup() {
        if (std::filesystem::exists(temp_filename)) {
            std::filesystem::remove(temp_filename);
        }
    }

    const std::string temp_filename;
};

TEST_CASE("IoSink Base Class", "[IoSink]") {
    class TestableIoSink : public IoSink {
    public:
        void set_test_handle(BIO* bio) {
            reset_handle(bio);
        }
    };

    SECTION("Default constructor") {
        TestableIoSink sink;
        REQUIRE(sink.handle() == nullptr);
        REQUIRE_FALSE(sink.is_open());
        REQUIRE(sink.source() == "<IoSink>");
        REQUIRE(sink.read_all() == "");
    }

    SECTION("Handle management") {
        TestableIoSink sink;

        // Create a memory BIO for testing
        BIO* test_bio = BIO_new(BIO_s_mem());
        REQUIRE(test_bio != nullptr);

        sink.set_test_handle(test_bio);
        REQUIRE(sink.handle() == test_bio);
        REQUIRE(sink.is_open());

        sink.close();
        REQUIRE(sink.handle() == nullptr);
        REQUIRE_FALSE(sink.is_open());
    }

    SECTION("Copy/move operations are deleted") {
        // This test ensures the class is not copyable/movable
        STATIC_REQUIRE_FALSE(std::is_copy_constructible_v<IoSink>);
        STATIC_REQUIRE_FALSE(std::is_copy_assignable_v<IoSink>);
        STATIC_REQUIRE_FALSE(std::is_move_constructible_v<IoSink>);
        STATIC_REQUIRE_FALSE(std::is_move_assignable_v<IoSink>);
    }
}

TEST_CASE("FileSink", "[FileSink]") {
    TempFileFixture fixture;

    SECTION("Default constructor") {
        FileSink sink;
        REQUIRE(sink.handle() == nullptr);
        REQUIRE_FALSE(sink.is_open());
        REQUIRE(sink.source().empty());
    }

    SECTION("Open and read file - std::string version") {
        const std::string test_content = "Hello, World!\nThis is a test file.";
        fixture.create_test_file(test_content);

        FileSink sink;
        REQUIRE_NOTHROW(sink.open(fixture.temp_filename, "r"));
        REQUIRE(sink.is_open());
        REQUIRE(sink.source() == fixture.temp_filename);

        std::string content = sink.read_all();
        REQUIRE(content == test_content);

        sink.close();
        REQUIRE_FALSE(sink.is_open());
    }

    SECTION("Open and read file - C-string version") {
        const std::string test_content = "C-string test content";
        fixture.create_test_file(test_content);

        FileSink sink;
        REQUIRE_NOTHROW(sink.open(fixture.temp_filename.c_str(), "r"));
        REQUIRE(sink.is_open());
        REQUIRE(sink.source() == fixture.temp_filename);

        std::string content = sink.read_all();
        REQUIRE(content == test_content);
    }

    SECTION("Open non-existent file throws exception") {
        FileSink sink;
        REQUIRE_THROWS_AS(sink.open("non_existent_file.txt", "r"), std::runtime_error);
        REQUIRE_FALSE(sink.is_open());
    }

    SECTION("Read from closed file throws exception") {
        FileSink sink;
        REQUIRE_THROWS_AS(sink.read_all(), std::runtime_error);
    }

    SECTION("File positioning - seek and tell") {
        const std::string test_content = "0123456789ABCDEF";
        fixture.create_test_file(test_content);

        FileSink sink;
        sink.open(fixture.temp_filename, "r");

        // Test initial position
        REQUIRE(sink.tell() == 0);

        // Test seeking
        REQUIRE_NOTHROW(sink.seek(5));
        REQUIRE(sink.tell() == 5);

        // Test rewind
        REQUIRE_NOTHROW(sink.rewind());
        REQUIRE(sink.tell() == 0);

        // Test seeking to end
        REQUIRE_NOTHROW(sink.seek(test_content.length()));
        REQUIRE(sink.tell() == static_cast<int>(test_content.length()));
    }

    SECTION("Seek on closed file throws exception") {
        FileSink sink;
        REQUIRE_THROWS_AS(sink.seek(0), std::logic_error);
    }

    SECTION("Tell on closed file throws exception") {
        FileSink sink;
        REQUIRE_THROWS_AS(sink.tell(), std::logic_error);
    }

    SECTION("Large file reading") {
        // Create a file larger than the buffer size (4KB)
        std::string large_content;
        for (int i = 0; i < 5000; ++i) {
            large_content += "A";
        }
        fixture.create_test_file(large_content);

        FileSink sink;
        sink.open(fixture.temp_filename, "r");

        std::string content = sink.read_all();
        REQUIRE(content.length() == 5000);
        REQUIRE(content == large_content);
    }

    SECTION("Write mode") {
        FileSink sink;
        REQUIRE_NOTHROW(sink.open(fixture.temp_filename, "w"));
        REQUIRE(sink.is_open());

        // Note: We can't easily test writing through the BIO interface
        // without additional wrapper methods, but we can verify the file opens
        sink.close();
        REQUIRE(std::filesystem::exists(fixture.temp_filename));
    }
}

TEST_CASE("MemorySink", "[MemorySink]") {

    SECTION("Default constructor") {
        MemorySink sink;
        REQUIRE(sink.handle() == nullptr);
        REQUIRE_FALSE(sink.is_open());
        REQUIRE(sink.source() == "<MemorySink>");
        REQUIRE(sink.buffer() == nullptr);
        REQUIRE(sink.size() == 0);
    }

    SECTION("Read-only memory sink with explicit size") {
        const char* test_data = "Hello, Memory!";
        const int test_size = std::strlen(test_data);

        MemorySink sink;
        REQUIRE_NOTHROW(sink.open_ro(test_data, test_size));
        REQUIRE(sink.is_open());
        REQUIRE(sink.buffer() == test_data);
        REQUIRE(sink.size() == test_size);

        std::string content = sink.read_all();
        REQUIRE(content == std::string(test_data));

        sink.close();
        REQUIRE_FALSE(sink.is_open());
    }

    SECTION("Read-only memory sink with automatic size calculation") {
        const char* test_data = "Auto-sized string";

        MemorySink sink;
        REQUIRE_NOTHROW(sink.open_ro(test_data));
        REQUIRE(sink.is_open());
        REQUIRE(sink.buffer() == test_data);
        REQUIRE(sink.size() == static_cast<int>(std::strlen(test_data)));

        std::string content = sink.read_all();
        REQUIRE(content == std::string(test_data));
    }

    SECTION("Read-only memory sink with binary data") {
        const char binary_data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
        const int binary_size = sizeof(binary_data);

        MemorySink sink;
        REQUIRE_NOTHROW(sink.open_ro(binary_data, binary_size));
        REQUIRE(sink.is_open());
        REQUIRE(sink.size() == binary_size);

        std::string content = sink.read_all();
        REQUIRE(content.length() == binary_size);
        REQUIRE(std::memcmp(content.data(), binary_data, binary_size) == 0);
    }

    SECTION("Read-only memory sink with null buffer throws") {
        MemorySink sink;
        REQUIRE_THROWS_AS(sink.open_ro(nullptr), std::invalid_argument);
        REQUIRE_FALSE(sink.is_open());

        // Also test with explicit size - should still throw due to null buffer
        REQUIRE_THROWS_AS(sink.open_ro(nullptr, 10), std::invalid_argument);
        REQUIRE_FALSE(sink.is_open());
    }

    SECTION("Read-only memory sink with zero size throws") {
        const char* test_data = "some data";
        MemorySink sink;
        REQUIRE_THROWS_AS(sink.open_ro(test_data, 0), std::invalid_argument);
        REQUIRE_FALSE(sink.is_open());
    }

    SECTION("Read-write memory sink") {
        MemorySink sink;
        REQUIRE_NOTHROW(sink.open_rw());
        REQUIRE(sink.is_open());
        REQUIRE(sink.buffer() == nullptr);
        REQUIRE(sink.size() == 0);

        // Initially empty
        std::string content = sink.read_all();
        REQUIRE(content.empty());

        sink.close();
        REQUIRE_FALSE(sink.is_open());
    }

    SECTION("Read from closed memory sink throws exception") {
        MemorySink sink;
        REQUIRE_THROWS_AS(sink.read_all(), std::logic_error);
    }

    SECTION("Empty string handling") {
        const char* empty_string = "";

        MemorySink sink;
        // Empty string should now throw due to zero size check
        REQUIRE_THROWS_AS(sink.open_ro(empty_string), std::logic_error);
        REQUIRE_FALSE(sink.is_open());
    }

    SECTION("Large memory buffer") {
        std::string large_data(10000, 'X');

        MemorySink sink;
        REQUIRE_NOTHROW(sink.open_ro(large_data.c_str(), large_data.length()));
        REQUIRE(sink.is_open());
        REQUIRE(sink.size() == static_cast<int>(large_data.length()));

        std::string content = sink.read_all();
        REQUIRE(content == large_data);
    }

    SECTION("Multiple opens on same sink") {
        const char* first_data = "First data";
        const char* second_data = "Second data set";

        MemorySink sink;

        // First open
        sink.open_ro(first_data);
        REQUIRE(sink.read_all() == std::string(first_data));

        // Second open should replace the first
        sink.open_ro(second_data);
        REQUIRE(sink.read_all() == std::string(second_data));
        REQUIRE(sink.size() == static_cast<int>(std::strlen(second_data)));
    }
}

TEST_CASE("Polymorphic behavior", "[Polymorphism]") {

    SECTION("FileSink through IoSink pointer") {
        TempFileFixture fixture;
        const std::string test_content = "Polymorphic test";
        fixture.create_test_file(test_content);

        auto sink = std::make_unique<FileSink>();
        sink->open(fixture.temp_filename, "r");

        IoSink* base_ptr = sink.get();
        REQUIRE(base_ptr->is_open());
        REQUIRE(base_ptr->read_all() == test_content);
        REQUIRE(base_ptr->source() == fixture.temp_filename);

        base_ptr->close();
        REQUIRE_FALSE(base_ptr->is_open());
    }

    SECTION("MemorySink through IoSink pointer") {
        const char* test_data = "Memory polymorphic test";

        auto sink = std::make_unique<MemorySink>();
        sink->open_ro(test_data);

        IoSink* base_ptr = sink.get();
        REQUIRE(base_ptr->is_open());
        REQUIRE(base_ptr->read_all() == std::string(test_data));
        REQUIRE(base_ptr->source() == "<MemorySink>");

        base_ptr->close();
        REQUIRE_FALSE(base_ptr->is_open());
    }
}

TEST_CASE("Error handling and edge cases", "[ErrorHandling]") {

    // SECTION("BIO allocation failure simulation") {
    //     // Note: It's difficult to simulate BIO allocation failure without
    //     // modifying the OpenSSL library or using dependency injection.
    //     // This section would typically require mocking or fault injection.
    //     INFO("BIO allocation failure tests would require mocking infrastructure");
    // }

    SECTION("File operations on invalid handles") {
        FileSink sink;
        // Attempting operations on unopened sink
        REQUIRE_THROWS(sink.read_all());
        REQUIRE_THROWS(sink.seek(0));
        REQUIRE_THROWS(sink.tell());
    }

    SECTION("Memory operations on invalid handles") {
        MemorySink sink;
        // Attempting operations on unopened sink
        REQUIRE_THROWS(sink.read_all());
    }

    SECTION("Resource cleanup on exception") {
        TempFileFixture fixture;
        fixture.create_test_file("test");

        FileSink sink;
        sink.open(fixture.temp_filename, "r");
        REQUIRE(sink.is_open());

        // Destructor should clean up properly even if exception occurs
        // This is automatically tested by RAII
    }
}

TEST_CASE("Stream operators", "[StreamOperators]") {
    SECTION("operator<<(IoSink&, const std::string&)") {
        MemorySink sink;
        sink.open_rw();

        const std::string test_string = "Hello, stream!";
        REQUIRE_NOTHROW(sink << test_string);

        std::string content = sink.read_all();
        REQUIRE(content == test_string);
    }

    SECTION("operator>>(IoSink&, std::string&)") {
        const std::string test_string = "Stream into string";
        MemorySink sink;
        sink.open_ro(test_string.c_str());

        std::string result;
        REQUIRE_NOTHROW(sink >> result);
        REQUIRE(result == test_string);
    }

    SECTION("operator<<(std::ostream&, IoSink&)") {
        const std::string test_string = "IoSink to ostream";
        MemorySink sink;
        sink.open_ro(test_string.c_str());

        std::stringstream ss;
        REQUIRE_NOTHROW(ss << sink);
        REQUIRE(ss.str() == test_string);
    }

    SECTION("operator>>(std::istream&, IoSink&)") {
        const std::string test_string = "istream to IoSink";
        std::stringstream ss(test_string);

        MemorySink sink;
        sink.open_rw();

        REQUIRE_NOTHROW(ss >> sink);

        std::string content = sink.read_all();
        REQUIRE(content == test_string);
    }
}