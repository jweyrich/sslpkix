#pragma once

#include "sslpkix/iosink.h"
#include "sslpkix/x509/key.h"
#include "sslpkix/x509/cert_name.h"
#include "sslpkix/x509/cert.h"
#include "sslpkix/x509/cert_req.h"
#include "sslpkix/x509/cert_store.h"

namespace sslpkix {

bool startup(void);
void shutdown(void);
bool seed_prng(void);
void print_errors(FILE *file);
bool add_custom_object(const char *oid, const char *sn, const char *ln);

} // namespace sslpkix
