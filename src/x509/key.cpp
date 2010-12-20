#include "sslpkix/x509/key.h"

namespace sslpkix {

bool operator==(const Key& lhs, const Key& rhs) {
	// TODO(jweyrich): do we need EVP_PKEY_cmp_parameters() too?
	return EVP_PKEY_cmp(lhs._handle, rhs._handle) == 1;
}

bool operator!=(const Key& lhs, const Key& rhs) {
	return !(lhs == rhs);
}

} // sslpkix
