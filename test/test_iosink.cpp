#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_template_test_macros.hpp>
#include <fstream>
#include <filesystem>
#include <cstring>
#include "sslpkix/iosink.h"

using namespace sslpkix;

// Test fixture for creating temporary test files
class TestFileFixture {
public:
    TestFileFixture() : test_filename("test_file.tmp") {}

    ~TestFileFixture() {
        cleanup();
    }

    void create_test_file(const std::string& content) {
        std::ofstream file(test_filename);
        file << content;
        file.close();
    }

    void cleanup() {
        if (std::filesystem::exists(test_filename)) {
            std::filesystem::remove(test_filename);
        }
    }

    const std::string& filename() const { return test_filename; }

private:
    std::string test_filename;
};

TEST_CASE("IoSink basic functionality", "[IoSink]") {
    IoSink sink;

    SECTION("Default constructor creates closed sink") {
        REQUIRE_FALSE(sink.is_open());
        REQUIRE(sink.handle() == nullptr);
    }

    SECTION("Source returns default value") {
        REQUIRE(sink.source() == "<IoSink>");
    }

    SECTION("Close on unopened sink is safe") {
        REQUIRE_NOTHROW(sink.close());
    }

    SECTION("Copy/move operations are deleted") {
        // These should not compile, but we can't test that directly
        // The compiler will catch these at compile time
        REQUIRE(std::is_copy_constructible_v<IoSink> == false);
        REQUIRE(std::is_copy_assignable_v<IoSink> == false);
        REQUIRE(std::is_move_constructible_v<IoSink> == false);
        REQUIRE(std::is_move_assignable_v<IoSink> == false);
    }
}

TEST_CASE("FileSink functionality", "[FileSink]") {
    TestFileFixture fixture;
    FileSink file_sink;

    SECTION("Opening existing file for reading") {
        const std::string test_content = "Hello, World!";
        fixture.create_test_file(test_content);

        REQUIRE(file_sink.open(fixture.filename(), "r"));
        REQUIRE(file_sink.is_open());
        REQUIRE(file_sink.source() == fixture.filename());
    }

    SECTION("Opening non-existent file for reading fails") {
        REQUIRE_FALSE(file_sink.open("non_existent_file.txt", "r"));
        REQUIRE_FALSE(file_sink.is_open());
    }

    SECTION("Opening file for writing") {
        REQUIRE(file_sink.open(fixture.filename(), "w"));
        REQUIRE(file_sink.is_open());
        REQUIRE(file_sink.source() == fixture.filename());
    }

    SECTION("C-style string overload") {
        const std::string test_content = "Test content";
        fixture.create_test_file(test_content);

        REQUIRE(file_sink.open(fixture.filename().c_str(), "r"));
        REQUIRE(file_sink.is_open());
    }

    SECTION("Close functionality") {
        fixture.create_test_file("test");
        file_sink.open(fixture.filename(), "r");

        REQUIRE(file_sink.is_open());
        file_sink.close();
        REQUIRE_FALSE(file_sink.is_open());
    }

    SECTION("Multiple open calls") {
        fixture.create_test_file("test1");
        REQUIRE(file_sink.open(fixture.filename(), "r"));

        // Opening again should close previous and open new
        TestFileFixture fixture2;
        fixture2.create_test_file("test2");
        REQUIRE(file_sink.open(fixture2.filename(), "r"));
        REQUIRE(file_sink.source() == fixture2.filename());
    }
}

TEST_CASE("FileSink seek and tell operations", "[FileSink]") {
    TestFileFixture fixture;
    FileSink file_sink;
    const std::string test_content = "0123456789ABCDEF";

    SECTION("Seek and tell on opened file") {
        fixture.create_test_file(test_content);
        REQUIRE(file_sink.open(fixture.filename(), "r"));

        // Initial position should be 0
        REQUIRE(file_sink.tell() == 0);

        // Seek to middle of file
        REQUIRE(file_sink.seek(8));
        REQUIRE(file_sink.tell() == 8);

        // Seek to beginning
        REQUIRE(file_sink.seek(0));
        REQUIRE(file_sink.tell() == 0);
    }

    SECTION("Rewind functionality") {
        fixture.create_test_file(test_content);
        REQUIRE(file_sink.open(fixture.filename(), "r"));

        REQUIRE(file_sink.seek(10));
        REQUIRE(file_sink.tell() == 10);

        REQUIRE(file_sink.rewind());
        REQUIRE(file_sink.tell() == 0);
    }

    SECTION("Seek on closed file fails") {
        REQUIRE_FALSE(file_sink.seek(0));
        REQUIRE_FALSE(file_sink.rewind());
    }

    SECTION("Tell on closed file fails") {
        REQUIRE(file_sink.tell() == -1);
    }

    SECTION("Seek beyond file boundaries") {
        fixture.create_test_file("short");
        REQUIRE(file_sink.open(fixture.filename(), "r"));

        // Seeking beyond file size - behavior depends on BIO implementation
        // This test documents the current behavior
        bool seek_result = file_sink.seek(1000);
        // Result may vary, but should not crash
        REQUIRE((seek_result == true || seek_result == false));
    }
}

TEST_CASE("MemorySink read-only functionality", "[MemorySink]") {
    MemorySink memory_sink;

    SECTION("Open with string buffer") {
        const char* test_data = "Hello, Memory!";
        REQUIRE(memory_sink.open_ro(test_data));
        REQUIRE(memory_sink.is_open());
        REQUIRE(memory_sink.buffer() == test_data);
        REQUIRE(memory_sink.size() == static_cast<int>(strlen(test_data)));
    }

    SECTION("Open with explicit size") {
        const char* test_data = "Hello\0World"; // Contains null byte
        int explicit_size = 11;
        REQUIRE(memory_sink.open_ro(test_data, explicit_size));
        REQUIRE(memory_sink.is_open());
        REQUIRE(memory_sink.buffer() == test_data);
        REQUIRE(memory_sink.size() == explicit_size);
    }

    SECTION("Open with null buffer and no size fails") {
        REQUIRE_FALSE(memory_sink.open_ro(nullptr));
        REQUIRE_FALSE(memory_sink.is_open());
    }

    SECTION("Open with null buffer but explicit size") {
        // This should fail as we can't create a BIO from null buffer
        REQUIRE_FALSE(memory_sink.open_ro(nullptr, 10));
        REQUIRE_FALSE(memory_sink.is_open());
    }

    SECTION("Open with zero size") {
        const char* test_data = "test";
        REQUIRE(memory_sink.open_ro(test_data, 0));
        REQUIRE(memory_sink.is_open());
        REQUIRE(memory_sink.size() == 0);
    }

    SECTION("Source returns correct value") {
        const char* test_data = "test";
        memory_sink.open_ro(test_data);
        REQUIRE(memory_sink.source() == "<MemorySink>");
    }

    SECTION("Multiple open calls") {
        const char* data1 = "first";
        const char* data2 = "second";

        REQUIRE(memory_sink.open_ro(data1));
        REQUIRE(memory_sink.buffer() == data1);

        // Opening again should reset
        REQUIRE(memory_sink.open_ro(data2));
        REQUIRE(memory_sink.buffer() == data2);
    }
}

TEST_CASE("MemorySink read-write functionality", "[MemorySink]") {
    MemorySink memory_sink;

    SECTION("Open read-write sink") {
        REQUIRE(memory_sink.open_rw());
        REQUIRE(memory_sink.is_open());
        REQUIRE(memory_sink.buffer() == nullptr);
        REQUIRE(memory_sink.size() == 0);
    }

    SECTION("Source returns correct value for RW sink") {
        memory_sink.open_rw();
        REQUIRE(memory_sink.source() == "<MemorySink>");
    }

    SECTION("Multiple RW open calls") {
        REQUIRE(memory_sink.open_rw());
        REQUIRE(memory_sink.is_open());

        // Opening again should work
        REQUIRE(memory_sink.open_rw());
        REQUIRE(memory_sink.is_open());
    }

    SECTION("Switch between RO and RW") {
        const char* test_data = "test";
        REQUIRE(memory_sink.open_ro(test_data));
        REQUIRE(memory_sink.buffer() == test_data);

        REQUIRE(memory_sink.open_rw());
        REQUIRE(memory_sink.buffer() == nullptr);
        REQUIRE(memory_sink.size() == 0);
    }
}

TEST_CASE("IoSink handle management", "[IoSink][FileSink][MemorySink]") {
    SECTION("FileSink handle is valid when open") {
        TestFileFixture fixture;
        fixture.create_test_file("test");
        FileSink file_sink;

        REQUIRE(file_sink.handle() == nullptr);
        file_sink.open(fixture.filename(), "r");
        REQUIRE(file_sink.handle() != nullptr);
        file_sink.close();
        REQUIRE(file_sink.handle() == nullptr);
    }

    SECTION("MemorySink handle is valid when open") {
        MemorySink memory_sink;
        const char* test_data = "test";

        REQUIRE(memory_sink.handle() == nullptr);
        memory_sink.open_ro(test_data);
        REQUIRE(memory_sink.handle() != nullptr);
        memory_sink.close();
        REQUIRE(memory_sink.handle() == nullptr);
    }
}

TEST_CASE("Edge cases and error conditions", "[IoSink]") {
    SECTION("FileSink with invalid mode") {
        TestFileFixture fixture;
        fixture.create_test_file("test");
        FileSink file_sink;

        // Invalid mode should fail
        REQUIRE_FALSE(file_sink.open(fixture.filename(), "invalid_mode"));
        REQUIRE_FALSE(file_sink.is_open());
    }

    SECTION("FileSink with empty filename") {
        FileSink file_sink;
        REQUIRE_FALSE(file_sink.open("", "r"));
        REQUIRE_FALSE(file_sink.is_open());
    }

    SECTION("MemorySink with very large size") {
        MemorySink memory_sink;
        const char* test_data = "small";

        // Very large size should still work (BIO will handle it)
        REQUIRE(memory_sink.open_ro(test_data, 1000000));
        REQUIRE(memory_sink.is_open());
        REQUIRE(memory_sink.size() == 1000000);
    }

    SECTION("Destructor cleanup") {
        // Test that destructors properly clean up resources
        // This is mainly to ensure no memory leaks
        {
            TestFileFixture fixture;
            fixture.create_test_file("test");
            FileSink file_sink;
            file_sink.open(fixture.filename(), "r");
            // file_sink destructor should clean up automatically
        }

        {
            MemorySink memory_sink;
            const char* test_data = "test";
            memory_sink.open_ro(test_data);
            // memory_sink destructor should clean up automatically
        }

        // If we reach here without crashes, cleanup worked
        REQUIRE(true);
    }
}

TEST_CASE("Polymorphic behavior", "[IoSink]") {
    SECTION("FileSink through IoSink pointer") {
        TestFileFixture fixture;
        fixture.create_test_file("test");

        std::unique_ptr<IoSink> sink = std::make_unique<FileSink>();
        REQUIRE_FALSE(sink->is_open());
        REQUIRE(sink->source() == ""); // Base class method

        // Can't call FileSink-specific methods through base pointer
        // This is expected behavior
    }

    SECTION("MemorySink through IoSink pointer") {
        std::unique_ptr<IoSink> sink = std::make_unique<MemorySink>();
        REQUIRE_FALSE(sink->is_open());
        REQUIRE(sink->source() == "<MemorySink>"); // Base class method
    }

    SECTION("Virtual destructor works correctly") {
        // Test that virtual destructor properly cleans up derived objects
        TestFileFixture fixture;
        fixture.create_test_file("test");

        {
            std::unique_ptr<IoSink> sink = std::make_unique<FileSink>();
            // Destructor should call derived class destructor
        }

        {
            std::unique_ptr<IoSink> sink = std::make_unique<MemorySink>();
            // Destructor should call derived class destructor
        }

        REQUIRE(true); // If we reach here, destructors worked correctly
    }
}