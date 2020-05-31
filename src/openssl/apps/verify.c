/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

/*
 * The original code was adapted by Jardel Weyrich <jweyrich at gmail dot com>
 * to serve the purposes of the sslpkix library.
 */

#include "sslpkix/openssl/apps/verify.h"
#include "sslpkix/openssl/apps/apps.h"
#include <openssl/err.h>
#include <openssl/x509_vfy.h>

int verify_callback(int ok, X509_STORE_CTX *ctx) {
	static int v_verbose = 0;
	int cert_error = X509_STORE_CTX_get_error(ctx);

	if (!ok) {
		X509 *current_cert = X509_STORE_CTX_get_current_cert(ctx);
		if (current_cert) {
			char buf[256];
			X509_NAME_oneline(X509_get_subject_name(current_cert), buf, sizeof(buf));
			fprintf(stderr, "%s\n", buf);
		}
		{
			int error_depth = X509_STORE_CTX_get_error_depth(ctx);
			const char *error_msg = X509_verify_cert_error_string(cert_error); // FIXME(jweyrich): not thread-safe
			fprintf(stderr, "%sError %d at %d depth lookup: %s\n",
#if OPENSSL_VERSION_NUMBER >= 0x1000000f
				   X509_STORE_CTX_get0_parent_ctx(ctx) ? "[CRL path] " : "",
#else
					"",
#endif
				   cert_error, error_depth, error_msg);
		}
		switch (cert_error) {
			case X509_V_ERR_NO_EXPLICIT_POLICY:
				policies_print(NULL, ctx);
			case X509_V_ERR_CERT_HAS_EXPIRED:
			// Since we are just checking the certificates, it is
			// ok if they are self signed. But we should still warn
			// the user.
			case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
			// Continue after extension errors too
			case X509_V_ERR_INVALID_CA:
			case X509_V_ERR_INVALID_NON_CA:
			case X509_V_ERR_PATH_LENGTH_EXCEEDED:
			case X509_V_ERR_INVALID_PURPOSE:
			case X509_V_ERR_CRL_HAS_EXPIRED:
			case X509_V_ERR_CRL_NOT_YET_VALID:
			case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
				ok = 1;
		}
		return ok;
	}
	if (cert_error == X509_V_OK && ok == 2)
		policies_print(NULL, ctx);
	if (!v_verbose)
		ERR_clear_error();
	return ok;
}
