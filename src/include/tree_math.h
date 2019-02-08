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

namespace mls {

// Internal namespace to keep these generic names clean
namespace tree_math {

uint32_t
level(uint32_t x);

// Tree size properties
uint32_t
node_width(uint32_t n);

uint32_t
size_from_width(uint32_t w);

// Node relationships
uint32_t
root(uint32_t n);

uint32_t
left(uint32_t x);

uint32_t
right(uint32_t x, uint32_t n);

uint32_t
parent(uint32_t x, uint32_t n);

uint32_t
sibling(uint32_t x, uint32_t n);

std::vector<uint32_t>
dirpath(uint32_t x, uint32_t n);

std::vector<uint32_t>
copath(uint32_t x, uint32_t n);

// XXX(rlb@ipv.sx): The templating here is looser than I would like.
// Really it should be something like vector<optional<T>>
template<typename T>
std::vector<uint32_t>
resolve(const T& nodes, uint32_t target)
{
  // Resolution of a populated node is the node itself
  if (nodes[target]) {
    return { target };
  }

  // Resolution of an empty leaf is the empty list
  if (level(target) == 0) {
    return {};
  }

  auto n = size_from_width(nodes.size());
  auto l = resolve(nodes, left(target));
  auto r = resolve(nodes, right(target, n));
  l.insert(l.end(), r.begin(), r.end());
  return l;
}

} // namespace tree_math
} // namespace mls
