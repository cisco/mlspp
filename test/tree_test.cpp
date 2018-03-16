#include "tree.h"
#include <catch.hpp>
#include <iostream>
#include <string>

using namespace mls;

struct StringNode
{
  std::string _value;

  StringNode() = default;

  StringNode(const std::string& value)
    : _value(value)
  {}

  bool public_equal(const StringNode& other) const
  {
    return other._value == _value;
  }
};

StringNode
operator+(const StringNode& lhs, const StringNode& rhs)
{
  return StringNode(lhs._value + rhs._value);
}

bool
operator==(const StringNode& lhs, const StringNode& rhs)
{
  return lhs._value == rhs._value;
}

bool
operator!=(const StringNode& lhs, const StringNode& rhs)
{
  return lhs._value != rhs._value;
}

std::ostream&
operator<<(std::ostream& out, const StringNode& node)
{
  out << node._value;
  return out;
}

tls::ostream&
operator<<(tls::ostream& out, const StringNode& node)
{
  tls::opaque<1> vec(node._value.begin(), node._value.end());
  return out << vec;
}

tls::istream&
operator>>(tls::istream& in, StringNode& node)
{
  tls::opaque<1> vec;
  in >> vec;
  node._value = std::string(vec.begin(), vec.end());
  return in;
}

TEST_CASE("Trees can be created and updated", "[tree]")
{
  StringNode a{ "a" }, b{ "b" }, c{ "c" }, d{ "d" }, e{ "e" }, ab{ "ab" },
    abcd{ "abcd" }, abcde{ "abcde" };
  size_t size = 5;

  Tree<StringNode> t_direct({ a, b, c, d, e });

  REQUIRE(t_direct.size() == size);
  REQUIRE(t_direct == t_direct);
  REQUIRE(t_direct.root() == abcde);

  SECTION("Creation from frontier")
  {
    Tree<StringNode> t_frontier(size, { abcd, e });
    REQUIRE(t_frontier == t_direct);
  }

  SECTION("Creation from copath")
  {
    Tree<StringNode> t_copath(size, 2, { e, ab, d });
    REQUIRE(t_copath == t_direct);
  }
}

TEST_CASE("Addition of a leaf to a tree", "[tree]")
{
  StringNode a{ "a" }, b{ "b" }, c{ "c" }, d{ "d" }, e{ "e" }, f{ "f" };

  Tree<StringNode> t_before({ a, b, c, d, e });
  Tree<StringNode> t_after({ a, b, c, d, e, f });

  t_before.add(f);
  REQUIRE(t_before == t_after);
}

TEST_CASE("Update of a leaf", "[tree]")
{
  StringNode a{ "a" }, b{ "b" }, c{ "c" }, d{ "d" }, e{ "e" }, x{ "x" };

  Tree<StringNode> t_before({ a, b, c, d, e });
  Tree<StringNode> t_after({ a, b, x, d, e });

  t_before.update(2, x);
  REQUIRE(t_before == t_after);
}

TEST_CASE("Update of a leaf with direct path", "[tree]")
{
  StringNode a{ "a" }, b{ "b" }, c{ "c" }, d{ "d" }, e{ "e" }, x{ "x" },
    cd{ "cd" };

  Tree<StringNode> t_full({ a, b, c, d, e });
  Tree<StringNode> t_copath(5, 0, { e, cd, b });
  REQUIRE(t_full == t_copath);

  auto path = t_full.update_path(2, x);
  t_full.update(2, x);
  t_copath.update(2, path);
  REQUIRE(t_full == t_copath);
}

TEST_CASE("TLS marshal / unmarshal", "[tree]")
{
  StringNode a{ "a" }, b{ "b" }, c{ "c" }, d{ "d" }, e{ "e" };
  Tree<StringNode> before({ a, b, c, d, e }), after;
  tls::unmarshal(tls::marshal(before), after);
  REQUIRE(before == after);
}
