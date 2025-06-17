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

bool startup(void);
void shutdown(void);
bool seed_prng(void);
bool add_custom_object(const char *oid, const char *sn, const char *ln, int *out_nid);

} // namespace sslpkix
