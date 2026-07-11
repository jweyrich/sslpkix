#pragma once

#include <string>
#include <stdexcept>
#include "sslpkix/error.h"

namespace sslpkix {

namespace error {

namespace detail {

class ExceptionReason {
public:
    explicit ExceptionReason(const std::string& reason)
        : _reason(reason) {}

    std::string reason() const noexcept {
        return _reason;
    }

protected:
    const char* compose_what(const char* base_what) const noexcept {
        _what = std::string(base_what) + ". Reason: " + _reason;
        return _what.c_str();
    }

private:
    const std::string _reason;
    mutable std::string _what;
};

} // namespace detail

template <typename BaseType>
class BaseException : public BaseType, private detail::ExceptionReason {
public:
    explicit BaseException(const std::string& msg, const std::string& reason = get_error_string())
        : BaseType(msg)
        , detail::ExceptionReason(reason) {}

    const char* what() const noexcept override {
        return compose_what(BaseType::what());
    }

    std::string reason() const noexcept {
        return detail::ExceptionReason::reason();
    }
};

template <>
class BaseException<std::bad_alloc> : public std::bad_alloc, private detail::ExceptionReason {
public:
    explicit BaseException(const std::string& reason = get_error_string())
        : std::bad_alloc()
        , detail::ExceptionReason(reason) {}

    const char* what() const noexcept override {
        return compose_what(std::bad_alloc::what());
    }

    std::string reason() const noexcept {
        return detail::ExceptionReason::reason();
    }
};

using BadAllocError = BaseException<std::bad_alloc>;
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