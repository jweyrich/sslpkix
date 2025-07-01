#pragma once

namespace sslpkix {

/**
 * @brief ResourceOwnership enum class defines options for ownership management.
 * It can be used to control whether a resource should be freed or not when the object is destroyed.
 */
enum class ResourceOwnership : unsigned int {
    Default = 0, // Default behavior, does not take ownership. The resource will not be freed when the object is destroyed.
    Transfer = 1, // Takes ownership of the resource. The resource will be freed when the object is destroyed.
};

inline constexpr bool should_own_resource(ResourceOwnership value) noexcept {
    return value == ResourceOwnership::Transfer;
}

} // namespace sslpkix