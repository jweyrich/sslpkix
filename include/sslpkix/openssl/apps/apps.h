#pragma once

#include <openssl/bio.h>
#include <openssl/x509_vfy.h> // for X509_STORE_CTX

#ifdef  __cplusplus
extern "C" {
#endif

void policies_print(BIO *out, X509_STORE_CTX *ctx);

#ifdef  __cplusplus
}
#endif
