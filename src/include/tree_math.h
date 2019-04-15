#pragma once

#include <algorithm>
#include <cstdint>
#include <vector>

// The below functions provide the index calculus for the tree
// structures used in MLS.  They are premised on a "flat"
// representation of a balanced binary tree.  Leaf nodes are
// even-numbered nodes, with the n-th leaf at 2*n.  Intermediate
// nodes are held in odd-numbered nodes.  For example, a 11-element
// tree has the following structure:
//
//                                              X
//                      X
//          X                       X                       X
//    X           X           X           X           X
// X     X     X     X     X     X     X     X     X     X     X
// 0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f 10 11 12 13 14
//
// This allows us to compute relationships between tree nodes simply
// by manipulating indices, rather than having to maintain
// complicated structures in memory, even for partial trees.  (The
// storage for a tree can just be a map[int]Node dictionary or an
// array.)  The basic rule is that the high-order bits of parent and
// child nodes have the following relation:
//
//    01x = <00x, 10x>

// Fordward declaration of TLS streams
namespace tls {
class istream;
class ostream;
}

namespace mls {

// Index types go in the overall namespace
struct UInt32
{
  uint32_t val;

  UInt32()
    : val(0)
  {}

  explicit UInt32(uint32_t val)
    : val(val)
  {}
};

tls::istream&
operator>>(tls::istream& in, UInt32& obj);
tls::ostream&
operator<<(tls::ostream& out, const UInt32& obj);

struct LeafCount : public UInt32
{
  using UInt32::UInt32;
};

struct NodeCount : public UInt32
{
  using UInt32::UInt32;
};

struct LeafIndex : public UInt32
{
  using UInt32::UInt32;

  bool operator==(const LeafIndex other) const { return val == other.val; }
  bool operator!=(const LeafIndex other) const { return val != other.val; }
};

struct NodeIndex : public UInt32
{
  using UInt32::UInt32;
  explicit NodeIndex(LeafIndex x)
    : UInt32(2 * x.val)
  {}

  bool operator==(const NodeIndex other) const { return val == other.val; }
  bool operator!=(const NodeIndex other) const { return val != other.val; }
};

// Internal namespace to keep these generic names clean
namespace tree_math {

uint32_t
level(NodeIndex x);

// Tree size properties
NodeCount
node_width(LeafCount n);

LeafCount
size_from_width(NodeCount w);

// Node relationships
NodeIndex
root(NodeCount w);

NodeIndex
left(NodeIndex x);

NodeIndex
right(NodeIndex x, NodeCount w);

NodeIndex
parent(NodeIndex x, NodeCount w);

NodeIndex
sibling(NodeIndex x, NodeCount w);

std::vector<NodeIndex>
dirpath(NodeIndex x, NodeCount w);

std::vector<NodeIndex>
copath(NodeIndex x, NodeCount w);

// XXX(rlb@ipv.sx): The templating here is looser than I would like.
// Really it should be something like vector<optional<T>>
template<typename T>
std::vector<NodeIndex>
resolve(const T& nodes, NodeIndex target)
{
  // Resolution of a populated node is the node itself
  if (nodes[target.val]) {
    return { target };
  }

  // Resolution of an empty leaf is the empty list
  if (level(target) == 0) {
    return {};
  }

  auto n = NodeCount{ uint32_t(nodes.size()) };
  auto l = resolve(nodes, left(target));
  auto r = resolve(nodes, right(target, n));
  l.insert(l.end(), r.begin(), r.end());
  return l;
}

} // namespace tree_math
} // namespace mls
