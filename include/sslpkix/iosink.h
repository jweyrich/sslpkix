#pragma once

//#include <cassert>
#include <iostream>
#include <string>
#include <openssl/bio.h>

namespace sslpkix {

class IoSink {
public:
	IoSink() : _bio(NULL) {
	}
	virtual ~IoSink() {
		release();
	}
	BIO *handle() {
		//assert(_bio != NULL);
		return _bio;
	}
	virtual void close() {
		release();
	}
	bool is_open() {
		return _bio != NULL;
	}
	virtual const std::string source() const {
		return "<IoSink>";
	}
protected:
	void release() {
		if (_bio != NULL) {
			BIO_free(_bio);
			_bio = NULL;
		}
	}
	BIO *_bio;
};

class FileSink : public IoSink {
public:
	FileSink() {
	}
	~FileSink() {
	}
	virtual bool open(const char *filename, const char *mode) {
		release();
		_bio = BIO_new_file(filename, mode);
		if (_bio == NULL)
			std::cerr << "Failed to open file: " << filename << std::endl;
		_filename = filename;
		return _bio != NULL;
	}
	virtual const std::string source() const {
		return _filename;
	}
protected:
	std::string _filename;
};

class MemorySink : public IoSink {
public:
	MemorySink() {
	}
	~MemorySink() {
	}
	virtual bool open(void *buffer, int size) {
		release();
		_bio = BIO_new_mem_buf(buffer, size);
		if (_bio == NULL)
			std::cerr << "Couldn't open memory BIO: " << buffer << std::endl;
		_buffer = buffer;
		_size = size;
		return _bio != NULL;
	}
	virtual const std::string source() const {
		return "<MemorySink>";
	}
protected:
	void *_buffer;
	int _size;
};

} // namespace sslpkix
