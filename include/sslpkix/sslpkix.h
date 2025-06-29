#pragma once

#include "sslpkix/error.h"
#include "sslpkix/iosink.h"
#include "sslpkix/x509/cert_name.h"
#include "sslpkix/x509/cert.h"
#include "sslpkix/x509/cert_req.h"
#include "sslpkix/x509/cert_store.h"
#include "sslpkix/x509/digest.h"
#include "sslpkix/x509/key.h"

namespace sslpkix {

/**
 * @brief Initialize the SSLPKIX library.
 * @note You MUST call this function before using any other functions in the SSLPKIX library.
 */
void initialize(void);

/**
 * @brief Seed the PRNG.
 */
void seed_prng(void);

/**
 * @brief Add a custom object to the SSLPKIX library.
 * @param oid The OID of the custom object.
 * @param sn The short name of the custom object.
 * @param ln The long name of the custom object.
 * @param alias_nid The NID of the alias for the custom object. If 0 (NID_undef), no alias is added.
 * @return The NID of the registered custom object.
 */
int add_custom_object(const char *oid, const char *sn, const char *ln, int alias_nid = NID_netscape_comment);

} // namespace sslpkix
