#include "sslpkix/error.h"
#include "sslpkix/bio_wrapper.h"
#include <openssl/err.h>
#include <openssl/bio.h>
#include <string>

namespace sslpkix {

std::string get_error_string() {
    BioWrapper bio(BIO_new(BIO_s_mem()));
    ERR_print_errors(bio.get());

    char* errorData;
    long errorLen = BIO_get_mem_data(bio.get(), &errorData);
    return std::string(errorData, errorLen);
}

void print_errors(FILE *file) {
	ERR_print_errors_fp(file);
}

} // namespace sslpkix