#pragma once

#include "sslpkix/iosink.h"
#include "sslpkix/x509/key.h"
#include "sslpkix/x509/cert_name.h"
#include "sslpkix/x509/cert.h"
#include "sslpkix/x509/cert_req.h"
#include "sslpkix/x509/cert_store.h"

bool sslpkix_startup(void);
void sslpkix_shutdown(void);
bool sslpkix_seed_prng(void);
void sslpkix_print_errors(FILE *file);
bool sslpkix_add_custom_object(const char *oid, const char *sn, const char *ln);
