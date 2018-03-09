#pragma once

#include <array>
#include <experimental/optional>
#include <stdexcept>
#include <vector>

namespace mls {

///
/// Some abbreviations
///

template<typename T>
using optional = std::experimental::optional<T>;

typedef std::vector<uint8_t> bytes;

typedef std::array<uint64_t, 8> epoch_t;

///
/// Hash prefixes
///

static const uint8_t leaf_hash_prefix = 0x01;
static const uint8_t pair_hash_prefix = 0x02;
static const uint8_t dh_hash_prefix = 0x03;

///
/// Error types
///

// The `typedef X parent` / `using parent::parent` construction here
// imports the constructors of the parent.

class InvalidTLSSyntax : public std::invalid_argument
{
public:
  typedef std::invalid_argument parent;
  using parent::parent;
};

class IncompatibleNodesError : public std::invalid_argument
{
public:
  typedef std::invalid_argument parent;
  using parent::parent;
};

class InvalidParameterError : public std::invalid_argument
{
public:
  typedef std::invalid_argument parent;
  using parent::parent;
};

class InvalidPathError : public std::invalid_argument
{
public:
  typedef std::invalid_argument parent;
  using parent::parent;
};

class InvalidIndexError : public std::invalid_argument
{
public:
  typedef std::invalid_argument parent;
  using parent::parent;
};

class MissingNodeError : public std::out_of_range
{
public:
  typedef std::out_of_range parent;
  using parent::parent;
};

} // namespace mls
