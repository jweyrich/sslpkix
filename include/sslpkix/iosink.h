#pragma once

//#include <cassert>
#include <iostream>
#include <string>
#include <openssl/bio.h>

namespace sslpkix {

class IoSink {
public:
	typedef BIO handle_type;
public:
	IoSink() : _handle(NULL) {
	}
	virtual ~IoSink() {
		release();
	}
	handle_type *handle() {
		//assert(_handle != NULL);
		return _handle;
	}
	virtual void close() {
		release();
	}
	bool is_open() {
		return _handle != NULL;
	}
	virtual const std::string source() const {
		return "<IoSink>";
	}
protected:
	void release() {
		if (_handle != NULL) {
			BIO_free(_handle);
			_handle = NULL;
		}
	}
protected:
	handle_type *_handle;
};

class FileSink : public IoSink {
public:
	FileSink() {
	}
	~FileSink() {
	}
	virtual bool open(const char *filename, const char *mode) {
		release();
		_handle = BIO_new_file(filename, mode);
		if (_handle == NULL)
			std::cerr << "Failed to open file: " << filename << std::endl;
		_filename = filename;
		return _handle != NULL;
	}
	virtual const std::string source() const {
		return _filename;
	}
protected:
	std::string _filename;
};

class MemorySink : public IoSink {
public:
	MemorySink() : _buffer(NULL), _size(0) {
	}
	~MemorySink() {
	}
	virtual bool open(void *buffer, int size) {
		release();
		_handle = BIO_new_mem_buf(buffer, size);
		if (_handle == NULL)
			std::cerr << "Couldn't open memory BIO: " << buffer << std::endl;
		_buffer = buffer;
		_size = size;
		return _handle != NULL;
	}
	virtual const std::string source() const {
		return "<MemorySink>";
	}
protected:
	void *_buffer;
	int _size;
};

} // namespace sslpkix
