#pragma once

#include <bytes/bytes.h>
#include <iosfwd>

// This file declares operators on bytes separately from the bytes alias and
// functions, so that the global namespace is not polluted by default.
//
// Note that these operators will be shadowed by any other operator of the same
// type in the caller namespace.

bytes_ns::bytes&
operator+=(bytes_ns::bytes& lhs, const bytes_ns::bytes& rhs);

bytes_ns::bytes
operator+(const bytes_ns::bytes& lhs, const bytes_ns::bytes& rhs);

bytes_ns::bytes
operator^(const bytes_ns::bytes& lhs, const bytes_ns::bytes& rhs);

std::ostream&
operator<<(std::ostream& out, const bytes_ns::bytes& data);
