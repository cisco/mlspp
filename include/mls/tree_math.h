#pragma once

#include <cstdint>
#include <tls/tls_syntax.h>
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

namespace mls {

// Index types go in the overall namespace
// XXX(rlb@ipv.sx): Seems like this stuff can probably get
// simplified down a fair bit.
struct UInt32
{
  uint32_t val;

  UInt32()
    : val(0)
  {}

  explicit UInt32(uint32_t val_in)
    : val(val_in)
  {}

  TLS_SERIALIZABLE(val)
};

struct NodeCount;

struct LeafCount : public UInt32
{
  using UInt32::UInt32;
  explicit LeafCount(const NodeCount w);
};

struct NodeCount : public UInt32
{
  using UInt32::UInt32;
  explicit NodeCount(const LeafCount n);
};

struct LeafIndex : public UInt32
{
  using UInt32::UInt32;
  bool operator<(const LeafIndex other) const { return val < other.val; }
  bool operator<(const LeafCount other) const { return val < other.val; }
};

struct NodeIndex : public UInt32
{
  using UInt32::UInt32;
  explicit NodeIndex(const LeafIndex x)
    : UInt32(2 * x.val)
  {}

  bool operator<(const NodeIndex other) const { return val < other.val; }
};

// Internal namespace to keep these generic names clean
namespace tree_math {

uint32_t
level(NodeIndex x);

// Node relationships
NodeIndex
root(LeafCount n);

NodeIndex
left(NodeIndex x);

NodeIndex
right(NodeIndex x, LeafCount n);

NodeIndex
parent(NodeIndex x, LeafCount n);

NodeIndex
sibling(NodeIndex x, LeafCount n);

std::vector<NodeIndex>
dirpath(NodeIndex x, LeafCount n);

std::vector<NodeIndex>
copath(NodeIndex x, LeafCount n);

bool
in_path(NodeIndex x, NodeIndex y);

NodeIndex
ancestor(LeafIndex l, LeafIndex r);

} // namespace tree_math
} // namespace mls
