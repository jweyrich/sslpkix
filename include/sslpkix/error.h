#pragma once

#include <string>

namespace sslpkix {

std::string get_error_string(void);
void print_errors(FILE *file);

} // namespace sslpkix
