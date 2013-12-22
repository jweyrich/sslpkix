#pragma once

//#include <cassert>
#include <iostream>
#include <string>
#include <openssl/bio.h>
#include "sslpkix/non_copyable.h"

namespace sslpkix {

class IoSink : non_copyable {
public:
	typedef BIO handle_type;
public:
	IoSink()
		: _handle(NULL)
	{
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
	bool is_open() const {
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
	bool rewind() {
		return seek(0);
	}
	bool seek(long offset) {
		int ret = BIO_seek(_handle, offset);
		if (ret == -1) {
			std::cerr << "Failed to seek to file offset: " << offset << std::endl;
			return false;
		}
		return true;
	}
	int tell() {
		int ret = BIO_tell(_handle);
		if (ret == -1) {
			std::cerr << "Failed to tell on file." << std::endl;
			return -1;
		}
		return ret;
	}
protected:
	std::string _filename;
};

class MemorySink : public IoSink {
public:
	MemorySink()
		: _buffer(NULL)
		, _size(0)
	{
	}
	virtual bool open_ro(void *buffer, int size) {
		release();
		_handle = BIO_new_mem_buf(buffer, size);
		if (_handle == NULL)
			std::cerr << "Failed to create readonly memory BIO: " << buffer << std::endl;
		_buffer = buffer;
		_size = size == -1 ? strlen(static_cast<char *>(buffer)) : size;
		return _handle != NULL;
	}
	virtual bool open_rw() {
		release();
		_handle = BIO_new(BIO_s_mem());
		if (_handle == NULL)
			std::cerr << "Failed to create readwrite memory BIO." << std::endl;
		_buffer = NULL;
		_size = 0;
		return _handle != NULL;
	}

	virtual const std::string source() const {
		return "<MemorySink>";
	}
protected:
	void *_buffer;
	int _size;
};

IoSink& operator<<(IoSink& sink, const std::string& str);
IoSink& operator>>(IoSink& sink, std::string& str);
std::ostream& operator<<(std::ostream& stream, IoSink& sink);
std::istream& operator>>(std::istream& stream, IoSink& sink);

} // namespace sslpkix
