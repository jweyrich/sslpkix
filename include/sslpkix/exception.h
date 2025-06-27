#pragma once

#include <string>
#include <stdexcept>
#include "sslpkix/error.h"

namespace sslpkix {

namespace error {

template <typename BaseType>
class BaseException : public BaseType {
public:
    explicit BaseException(const std::string& msg, const std::string& reason = get_error_string())
        : BaseType(msg)
        , _reason(reason) {}

    const char* what() const noexcept override {
        _what = std::string(BaseType::what()) + ". Reason: " + _reason;
        return _what.c_str();
    }

    std::string reason() const noexcept {
        return _reason;
    }

private:
    const std::string _reason;
    mutable std::string _what;
};

class BadAllocException : public std::bad_alloc {
public:
    BadAllocException(const std::string& msg)
        : std::bad_alloc()
        , _reason(msg) {}

    const char* what() const noexcept override {
        _what = std::string(std::bad_alloc::what()) + ". Reason: " + _reason;
        return _what.c_str();
    }

    std::string reason() const noexcept {
        return _reason;
    }

private:
    const std::string _reason;
    mutable std::string _what;
};

using BadAllocError = BadAllocException;
using DomainError = BaseException<std::domain_error>;
using InvalidArgumentError = BaseException<std::invalid_argument>;
using LengthError = BaseException<std::length_error>;
using LogicError = BaseException<std::logic_error>;
using OutOfRangeError = BaseException<std::out_of_range>;
using OverflowError = BaseException<std::overflow_error>;
using RangeError = BaseException<std::range_error>;
using RuntimeError = BaseException<std::runtime_error>;
using UnderflowError = BaseException<std::underflow_error>;

} // namespace error

} // namespace sslpkix