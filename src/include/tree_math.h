#pragma once

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

// Node relationships
size_t
root(size_t n);

size_t
left(size_t x);

size_t
right(size_t x, size_t n);

size_t
parent(size_t x, size_t n);

size_t
sibling(size_t x, size_t n);

// Slices through the tree
std::vector<size_t>
frontier(size_t n);

std::vector<size_t>
dirpath(size_t x, size_t n);

std::vector<size_t>
copath(size_t x, size_t n);

std::vector<size_t>
leaves(size_t n);

} // namespace tree_math
} // namespace mls
