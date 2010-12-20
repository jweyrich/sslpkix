#include "sslpkix/x509/cert.h"

namespace sslpkix {

bool operator==(const Certificate& lhs, const Certificate& rhs) {
	return X509_cmp(lhs._handle, rhs._handle) == 0 &&
		lhs._subject == rhs._subject &&
		lhs._issuer == rhs._issuer;
}

bool operator!=(const Certificate& lhs, const Certificate& rhs) {
	return !(lhs == rhs);
}

} // sslpkix
