#pragma once

#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#ifdef  __cplusplus
extern "C" {
#endif

int verify_callback(int ok, X509_STORE_CTX *ctx);

#ifdef  __cplusplus
}
#endif
