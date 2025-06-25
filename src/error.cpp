#include "sslpkix/error.h"
#include <openssl/err.h>
#include <string>

namespace sslpkix {

namespace error {

std::string get_error_string(void) noexcept {
    std::string result;
    unsigned long err;
    char buf[256];

    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, buf, sizeof(buf));
        result += std::string(buf) + "\n";
    }

    return result.empty() ? std::string() : result;
}

void print_errors(FILE *file) noexcept {
	ERR_print_errors_fp(file);
}

} // namespace error

} // namespace sslpkix