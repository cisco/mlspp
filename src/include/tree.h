#pragma once

#include "common.h"
#include "tree_math.h"
#include <algorithm>
#include <iostream>
#include <map>
#include <set>
#include <vector>

namespace mls {

// XXX(rlb@ipv.sx) There's no easy way to express this in C++, but
// the template argument Node must satisfy a few requirements:
//   Node Node();
//   Node operator+(const Node& lhs, const Node& rhs);
//   bool operator==(const Node& lhs, const Node& rhs);
//   bool operator!=(const Node& lhs, const Node& rhs);
//   bool public_equal(const Node& other) const;
//   ostream& operator<<(ostream&, const Node&);
template<typename Node>
class Tree
{
public:
  // Construct an empty tree
  Tree()
    : _size(0)
  {}

  // Construct a (partial) tree from its leaves
  Tree(const std::vector<Node>& leaves)
    : _size(leaves.size())
  {
    std::vector<size_t> new_nodes(_size);
    for (size_t i = 0; i < _size; i += 1) {
      new_nodes[i] = 2 * i;
      set(2 * i, leaves[i]);
    }

    build(new_nodes);
  }

  // Construct a (partial) tree from a frontier
  Tree(size_t size, std::vector<Node> F)
    : _size(size)
  {
    auto f = tree_math::frontier(size);
    if (f.size() != F.size()) {
      throw InvalidPathError("Frontier has incorrect length for tree size");
    }

    for (int i = 0; i < f.size(); i += 1) {
      set(f[i], F[i]);
    }

    build(f);
  }

  // Construct a (partial) tree from a copath
  Tree(size_t size, size_t index, std::vector<Node> C)
    : _size(size)
  {
    if (index > size) {
      throw InvalidParameterError("Leaf index greater than tree size");
    }

    auto c = tree_math::copath(2 * index, size);
    if (c.size() != C.size()) {
      throw InvalidPathError(
        "Copath has incorrect length for tree size and leaf");
    }

    for (int i = 0; i < c.size(); i += 1) {
      set(c[i], C[i]);
    }

    build(c);
  }

  // Defaults for:
  // * destructor
  // * copy constructor
  // * copy assignment
  // * move constructor
  // * move assignment

  // Two trees are equal if they have the same node type and size,
  // and if the nodes they have in common are equal.
  bool operator==(const Tree& other) const
  {
    if (_size != other._size) {
      return false;
    }

    for (const auto& x : _nodes) {
      if (other._nodes.count(x.first) == 0) {
        continue;
      }

      if (!x.second.public_equal(other._nodes.at(x.first))) {
        return false;
      }
    }

    return true;
  }

  // Mutators
  void add(Node leaf)
  {
    _size += 1;
    update(_size - 1, leaf);
  }

  void add(const std::vector<Node>& path)
  {
    _size += 1;
    update(_size - 1, path);
  }

  void update(size_t index, Node leaf)
  {
    if (index > _size) {
      throw InvalidIndexError("Leaf index greater than tree size");
    }

    set(2 * index, leaf);
    build({ 2 * index });
  }

  void update(size_t index, std::vector<Node> path)
  {
    if (index > _size) {
      throw InvalidIndexError("Leaf index greater than tree size");
    }

    auto d = tree_math::dirpath(2 * index, _size);
    d.push_back(2 * index);
    if (path.size() != d.size()) {
      throw InvalidPathError(
        "Update path incorrect for tree size and leaf index");
    }

    for (int i = 0; i < d.size(); i += 1) {
      set(d[i], path[i]);
    }

    build(d);
  }

  // Extractors
  // NB: All of these can throw if there are missing nodes
  size_t size() const { return _size; }

  std::vector<Node> leaves() const { return extract(tree_math::leaves(_size)); }

  Node root() const { return _nodes.at(tree_math::root(_size)); }

  std::vector<Node> direct_path(size_t index) const
  {
    return extract(tree_math::dirpath(2 * index, _size));
  }

  std::vector<Node> copath(size_t index) const
  {
    return extract(tree_math::copath(2 * index, _size));
  }

  std::vector<Node> frontier() const
  {
    return extract(tree_math::frontier(_size));
  }

  std::vector<Node> update_path(size_t index, Node newValue) const
  {
    auto c = tree_math::copath(2 * index, _size);
    std::vector<Node> nodes;
    nodes.reserve(c.size());

    nodes.push_back(newValue);
    for (int i = c.size() - 1; i > 0; i -= 1) {
      auto copathNode = _nodes.at(c[i]);
      auto s = tree_math::sibling(c[i], _size);
      if (s < c[i]) {
        nodes.insert(nodes.begin(), nodes.front() + copathNode);
      } else {
        nodes.insert(nodes.begin(), copathNode + nodes.front());
      }
    }

    return nodes;
  }

private:
  uint32_t _size;
  std::map<size_t, Node> _nodes;

  // Compute intermediate nodes in the tree as much as possible
  void build(const std::vector<size_t>& new_nodes)
  {
    std::set<size_t> toUpdate;
    std::for_each(
      new_nodes.begin(), new_nodes.end(), [this, &toUpdate](const size_t& x) {
        toUpdate.insert(tree_math::parent(x, _size));
      });

    while (toUpdate.size() > 0) {
      std::set<size_t> nextToUpdate;

      for (const auto& p : toUpdate) {
        auto l = tree_math::left(p);
        auto r = tree_math::right(p, _size);

        if ((l == p) || (r == p)) {
          // Small tree edge case: p is both a "parent" and a
          // "leaf".  No need to update.
          continue;
        }

        auto okl = (_nodes.count(l) > 0);
        auto okr = (_nodes.count(r) > 0);
        if (!okl || !okr) {
          // Don't have both children
          continue;
        }

        try {
          Node node(_nodes.at(l) + _nodes.at(r));

          auto change = set(p, node);
          if (!change) {
            continue;
          }

          auto pp = tree_math::parent(p, _size);
          if (pp != p) {
            nextToUpdate.insert(pp);
          }
        } catch (IncompatibleNodesError) {
          // Ignore failures due to nodes being incompatible
        }
      }

      toUpdate = nextToUpdate;
    }
  }

  // Use of emplace to construct nodes and at to replace them avoids
  // the need for a default constructor in Node classes.
  //
  // Return value: Whether a change was made
  bool set(size_t i, Node n)
  {
    if (_nodes.count(i) == 0) {
      _nodes.emplace(i, n);
      return true;
    } else if (_nodes.at(i) != n) {
      _nodes.at(i) = n;
      return true;
    }

    return false;
  }

  std::vector<Node> extract(const std::vector<size_t>& indices) const
  {
    std::vector<Node> out;
    out.reserve(indices.size());
    for (const auto& i : indices) {
      out.push_back(_nodes.at(i));
    }
    return out;
  }

  friend std::ostream& operator<<(std::ostream& out, Tree t)
  {
    out << "Size: " << t._size << std::endl;
    out << "Nodes:" << std::endl;
    for (const auto& x : t._nodes) {
      out << "  [" << x.first << ": " << x.second << "]" << std::endl;
    }
    return out;
  }
};

} // namespace mls
