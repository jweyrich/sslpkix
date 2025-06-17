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

    virtual void close() {
        handle_.reset();
    }

    bool is_open() const noexcept {
        return static_cast<bool>(handle_);
    }

    virtual std::string source() const {
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

    virtual bool open(const std::string& filename, const std::string& mode) {
        reset_handle();

        BIO* bio = BIO_new_file(filename.c_str(), mode.c_str());
        if (!bio) {
            std::cerr << "Failed to open file: " << filename << std::endl;
            return false;
        }

        reset_handle(bio);
        filename_ = filename;
        return true;
    }

    // Overloaded version for C-style strings (for backward compatibility)
    virtual bool open(const char* filename, const char* mode) {
        return open(std::string(filename), std::string(mode));
    }

    std::string source() const override {
        return filename_;
    }

    bool rewind() {
        return seek(0);
    }

    bool seek(long offset) {
        if (!is_open()) {
            std::cerr << "Cannot seek on closed file" << std::endl;
            return false;
        }

        int ret = BIO_seek(handle(), offset);
        if (ret == -1) {
            std::cerr << "Failed to seek to file offset: " << offset << std::endl;
            return false;
        }
        return true;
    }

    int tell() const {
        if (!is_open()) {
            std::cerr << "Cannot tell on closed file" << std::endl;
            return -1;
        }

        int ret = BIO_tell(handle());
        if (ret == -1) {
            std::cerr << "Failed to tell on file" << std::endl;
            return -1;
        }
        return ret;
    }

private:
    std::string filename_;
};

class MemorySink : public IoSink {
public:
    MemorySink() = default;

    virtual bool open_ro(const void* buffer, int size = -1) {
        reset_handle();

        // Calculate size if not provided
        int actual_size = size;
        if (size == -1) {
            if (!buffer) {
                std::cerr << "Cannot determine size of null buffer" << std::endl;
                return false;
            }
            actual_size = static_cast<int>(std::strlen(static_cast<const char*>(buffer)));
        }

        // BIO_new_mem_buf expects non-const void*, but it's used read-only
        BIO* bio = BIO_new_mem_buf(const_cast<void*>(buffer), actual_size);
        if (!bio) {
            std::cerr << "Failed to create readonly memory BIO" << std::endl;
            return false;
        }

        reset_handle(bio);
        buffer_ = buffer;
        size_ = actual_size;
        return true;
    }

    virtual bool open_rw() {
        reset_handle();

        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            std::cerr << "Failed to create read-write memory BIO" << std::endl;
            return false;
        }

        reset_handle(bio);
        buffer_ = nullptr;
        size_ = 0;
        return true;
    }

    std::string source() const override {
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