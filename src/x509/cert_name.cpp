#include "sslpkix/x509/cert_name.h"

namespace sslpkix {

bool operator==(const CertificateName& lhs, const CertificateName& rhs) {
	return X509_NAME_cmp(lhs._handle, rhs._handle) == 0;
}

bool operator!=(const CertificateName& lhs, const CertificateName& rhs) {
	return !(lhs == rhs);
}

} // sslpkix
