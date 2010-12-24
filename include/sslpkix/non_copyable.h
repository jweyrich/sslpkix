#pragma once

namespace sslpkix {

class non_copyable {
private:
	non_copyable(const non_copyable&);
	non_copyable& operator=(const non_copyable&);
protected:
	non_copyable();
};

} // namespace sslpkix
