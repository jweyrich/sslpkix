#pragma once

#include <cstring>
#include <iostream>
#include <string>
#include <memory>
#include <functional>
#include <openssl/bio.h>
#include "sslpkix/exception.h"

namespace sslpkix {

namespace error {
    namespace iosink {
        using BadAllocError = BadAllocError;
        using RuntimeError = RuntimeError;
        using InvalidArgumentError = InvalidArgumentError;
        using LogicError = LogicError;
        using IosBaseFailure = std::ios_base::failure;
    } // iosink
} // namespace error

class IoSink {
public:
    using handle_type = BIO;

	// Custom deleter for BIO handles
	struct Deleter {
		void operator()(BIO* bio) const noexcept {
			if (bio) {
				BIO_free(bio);
			}
		}
	};

	using handle_ptr = std::unique_ptr<BIO, Deleter>;

    IoSink() = default;
    virtual ~IoSink() = default;

    // Explicitly deleted copy/move operations
    IoSink(const IoSink&) = delete;
    IoSink& operator=(const IoSink&) = delete;
    IoSink(IoSink&&) = delete;
    IoSink& operator=(IoSink&&) = delete;

    handle_type* handle() const noexcept {
        return handle_.get();
    }

    virtual void close() noexcept {
        handle_.reset();
    }

    bool is_open() const noexcept {
        return static_cast<bool>(handle_);
    }

    virtual std::string read_all() const {
        return "";
    }

    virtual std::string source() const noexcept {
        return "<IoSink>";
    }

protected:
    void reset_handle(BIO* new_handle = nullptr) {
        handle_.reset(new_handle);
    }

private:
    handle_ptr handle_;
};

class FileSink : public IoSink {
public:
    FileSink() = default;

    virtual void open(const std::string& filename, const std::string& mode) {
        BIO* bio = BIO_new_file(filename.c_str(), mode.c_str());
        if (!bio) {
            throw error::iosink::RuntimeError("Failed to open file: " + filename);
        }

        reset_handle(bio);
        filename_ = filename;
    }

    // Overloaded version for C-style strings (for backward compatibility)
    virtual void open(const char* filename, const char* mode) {
        open(std::string(filename), std::string(mode));
    }

    virtual std::string read_all() const override {
        if (!is_open()) {
            throw error::iosink::RuntimeError("Cannot read from closed file: " + source());
        }

        BIO *bio = handle();
        std::string result;
        char buffer[4096];  // 4KB buffer

        while (true) {
            int bytesRead = BIO_read(bio, buffer, sizeof(buffer));
            if (bytesRead > 0) {
                result.append(buffer, bytesRead);
            } else if (bytesRead == 0) {
                break;  // EOF
            } else {
                if (!BIO_should_retry(bio)) {
                    // BIO_read failed and it's not a retryable error
                    throw error::iosink::RuntimeError("BIO_should_retry failed on " + source());
                }
                // If it's retryable, you might want to add sleep/retry logic
            }
        }

        return result;
    }

    std::string source() const noexcept override {
        return filename_;
    }

    void rewind() {
        seek(0);
    }

    void seek(long offset) {
        if (!is_open()) {
            throw error::iosink::LogicError("Cannot seek on closed file: " + source());
        }

        int ret = BIO_seek(handle(), offset);
        if (ret == -1) {
            throw error::iosink::RuntimeError("Failed to seek to file offset " + std::to_string(offset) + " on " + source());
        }
    }

    int tell() const {
        if (!is_open()) {
            throw error::iosink::LogicError("Cannot tell on closed file: " + source());
        }

        int ret = BIO_tell(handle());
        if (ret == -1) {
            throw error::iosink::RuntimeError("Failed to tell on file: " + source());
        }
        return ret;
    }

private:
    std::string filename_;
};

class MemorySink : public IoSink {
public:
    MemorySink() = default;

    virtual void open_ro(const void* buffer, int size = -1) {
        if (!buffer) {
            throw error::iosink::InvalidArgumentError("Buffer cannot be null on " + source());
        }
        if (size == 0) {
            throw error::iosink::InvalidArgumentError("Size cannot be zero on " + source());
        }

        // Calculate size if not provided
        int actual_size = size;
        if (size == -1) {
            actual_size = static_cast<int>(std::strlen(static_cast<const char*>(buffer)));
            if (actual_size == 0) {
                throw error::iosink::InvalidArgumentError("Buffer cannot be empty (calculated size is zero) on " + source());
            }
        }

        // BIO_new_mem_buf expects non-const void*, but it's used read-only
        BIO* bio = BIO_new_mem_buf(buffer, actual_size);
        if (!bio) {
            throw error::iosink::BadAllocError("Failed to create read-only memory BIO on " + source());
        }

        reset_handle(bio);
        buffer_ = buffer;
        size_ = actual_size;
    }

    virtual void open_rw() {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            throw error::iosink::BadAllocError("Failed to create read-write memory BIO on " + source());
        }

        reset_handle(bio);
        buffer_ = nullptr;
        size_ = 0;
    }

    virtual std::string read_all() const override {
        if (!is_open()) {
            throw error::iosink::LogicError("Cannot read from closed memory sink: " + source());
        }

        char* data = nullptr;
        int len = BIO_get_mem_data(handle(), &data);
        return std::string(data, len);
    }

    std::string source() const noexcept override {
        return "<MemorySink>";
    }

    // Getter methods for buffer info
    const void* buffer() const noexcept { return buffer_; }
    int size() const noexcept { return size_; }

private:
    const void* buffer_ = nullptr;
    int size_ = 0;
};

// Stream operators
IoSink& operator<<(IoSink& sink, const std::string& str);
IoSink& operator>>(IoSink& sink, std::string& str);
std::ostream& operator<<(std::ostream& stream, IoSink& sink);
std::istream& operator>>(std::istream& stream, IoSink& sink);

} // namespace sslpkix