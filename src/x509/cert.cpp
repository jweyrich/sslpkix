#include "sslpkix/x509/cert.h"

namespace sslpkix {
namespace detail {

time_t asn1_time_to_time_t(const ASN1_TIME* time) {
    struct tm tm = {};
    // Requires OpenSSL 1.1.0 or later
    if (!ASN1_TIME_to_tm(time, &tm)) {
        // Conversion failed
        return static_cast<time_t>(-1);
    }

    // Convert tm (assumed UTC) to time_t
    // Use timegm() instead of mktime() to avoid local timezone shift
    // NOTE: timegm() is non-standard (POSIX/Unix)
    return timegm(&tm);  // POSIX; for portable alternative see below
}

} // namespace sslpkix::detail
} // namespace sslpkix