#pragma once

#include <cstring>
#include <iostream>
#include <string>
#include <memory>
#include <functional>
#include <openssl/bio.h>

namespace sslpkix {

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
            throw std::runtime_error("Failed to open file: " + filename);
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
            throw std::runtime_error("Cannot read from closed file: " + source());
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
                    throw std::runtime_error("BIO_read failed");
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
            throw std::logic_error("Cannot seek on closed file");
        }

        int ret = BIO_seek(handle(), offset);
        if (ret == -1) {
            throw std::runtime_error("Failed to seek to file offset: " + std::to_string(offset));
        }
    }

    int tell() const {
        if (!is_open()) {
            throw std::logic_error("Cannot tell on closed file");
        }

        int ret = BIO_tell(handle());
        if (ret == -1) {
            throw std::runtime_error("Failed to tell on file");
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
            throw std::invalid_argument("Buffer cannot be null");
        }
        if (size == 0) {
            throw std::invalid_argument("Size cannot be zero");
        }

        // Calculate size if not provided
        int actual_size = size;
        if (size == -1) {
            actual_size = static_cast<int>(std::strlen(static_cast<const char*>(buffer)));
            if (actual_size == 0) {
                throw std::invalid_argument("Buffer cannot be empty (calculated size is zero)");
            }
        }

        // BIO_new_mem_buf expects non-const void*, but it's used read-only
        BIO* bio = BIO_new_mem_buf(buffer, actual_size);
        if (!bio) {
            throw std::runtime_error("Failed to create read-only memory BIO");
        }

        reset_handle(bio);
        buffer_ = buffer;
        size_ = actual_size;
    }

    virtual void open_rw() {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            throw std::bad_alloc();
        }

        reset_handle(bio);
        buffer_ = nullptr;
        size_ = 0;
    }

    virtual std::string read_all() const override {
        if (!is_open()) {
            throw std::logic_error("Cannot read from closed memory sink");
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