#pragma once

namespace sslpkix {

#ifdef __GNUC__
#ifndef UNUSED
#define UNUSED __attribute__ ((unused))
#else
#error "UNUSED already defined"
#endif
#else
#define UNUSED
#endif

} // namespace sslpkix
