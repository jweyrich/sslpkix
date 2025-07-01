#pragma once

namespace sslpkix {

/**
 * @brief key_capabilities enum class defines the capabilities of a key.
 * It can be used to control whether a key can be used for a specific purpose.
 */
enum class key_capabilities : unsigned int {
    Unknown = 0,
    KeyExchange = 1 << 0,
    Signature = 1 << 1,
    Encryption = 1 << 3,
};

inline constexpr key_capabilities operator&(key_capabilities lhs, key_capabilities rhs) noexcept {
    return static_cast<key_capabilities>(static_cast<unsigned int>(lhs) & static_cast<unsigned int>(rhs));
}

inline constexpr key_capabilities operator|(key_capabilities lhs, key_capabilities rhs) noexcept {
    return static_cast<key_capabilities>(static_cast<unsigned int>(lhs) | static_cast<unsigned int>(rhs));
}

inline constexpr bool can_sign(key_capabilities capabilities) noexcept {
    return (capabilities & key_capabilities::Signature) == key_capabilities::Signature;
}

inline constexpr bool can_key_exchange(key_capabilities capabilities) noexcept {
    return (capabilities & key_capabilities::KeyExchange) == key_capabilities::KeyExchange;
}

inline constexpr bool can_encrypt(key_capabilities capabilities) noexcept {
    return (capabilities & key_capabilities::Encryption) == key_capabilities::Encryption;
}

} // namespace sslpkix