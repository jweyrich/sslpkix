#include "sslpkix/iosink.h"

namespace sslpkix {

IoSink& operator<<(IoSink& sink, const std::string& str) {
	const size_t total_size = str.length();
	const char *buf = str.data();
	const char *current = buf;
	size_t written_size = 0;
	int ret = 0;

	do {
		ret = BIO_write(sink.handle(), current, total_size - written_size);
		if (ret > 0) {
			current += ret;
			written_size += static_cast<size_t>(ret);
		}
	} while (ret > 0 && written_size < total_size);

	if (ret == 0 || ret == -1)
		throw error::iosink::IosBaseFailure("BIO_write failed");
	else if (ret == -2)
		throw error::iosink::IosBaseFailure("BIO_write is not implemented for this BIO");

	// TODO: Need to check result? 1=success, 0 or -1=failure
	ret = BIO_flush(sink.handle());

	return sink;
}

IoSink& operator>>(IoSink& sink, std::string& str) {
	char buf[1024];
	int ret = 0;

	do {
		ret = BIO_read(sink.handle(), buf, sizeof(buf));
		if (ret > 0)
			str.append(buf, ret);
	} while (ret > 0);

	// man BIO_read - http://www.manpagez.com/man/3/BIO_read/
	// NOTES
	// 		A 0 or -1 return is not necessarily an indication of an error. In
	// 		particular when the source/sink is non-blocking or of a certain type it
	// 		may merely be an indication that no data is currently available and
	// 		that the application should retry the operation later.

	if (ret == -1)
		; // EOF?
	else if (ret == -2)
		throw error::iosink::IosBaseFailure("BIO_read is not implemented for this BIO");

	return sink;
}

std::ostream& operator<<(std::ostream& stream, IoSink& sink) {
	char buf[1024];
	int ret = 0;

	do {
		ret = BIO_read(sink.handle(), buf, sizeof(buf)-1);
		if (ret > 0) {
			buf[ret] = '\0';
			stream << buf;
		}
	} while (ret > 0);

	if (ret == -1)
		; // EOF?
	else if (ret == -2)
		throw error::iosink::IosBaseFailure("BIO_read is not implemented for this BIO");

	return stream;
}

std::istream& operator>>(std::istream& stream, IoSink& sink) {
	char buf[1024];
	int ret = 0;

	while (!stream.eof()) {
		stream.read(buf, sizeof(buf));
		ret = BIO_write(sink.handle(), buf, stream.gcount());
		// BIO_write must succeed writing the exact amount of bytes we pass to it.
		if (ret == 0 || ret == -1)
			throw error::iosink::IosBaseFailure("BIO_write failed");
		else if (ret == -2)
			throw error::iosink::IosBaseFailure("BIO_write is not implemented for this BIO");
	}

	// TODO: Need to check result? 1=success, 0 or -1=failure
	ret = BIO_flush(sink.handle());

	return stream;
}

} // namespace sslpkix
