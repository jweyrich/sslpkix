#pragma once

#include <string>

namespace sslpkix {

namespace error {

std::string get_error_string(void) noexcept;
void print_errors(FILE *file) noexcept;

} // namespace error

} // namespace sslpkix
