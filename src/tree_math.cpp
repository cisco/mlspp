#include "tree_math.h"
#include "common.h"
#include "tls_syntax.h"

#include <algorithm>

static uint32_t one = 0x01;

namespace mls {

LeafCount::LeafCount(const NodeCount w)
{
  if (w.val == 0) {
    val = 0;
    return;
  }

  if ((w.val & one) == 0) {
    throw InvalidParameterError("Only odd node counts describe trees");
  }

  val = (w.val >> one) + 1;
}

NodeCount::NodeCount(const LeafCount n)
  : UInt32(2 * (n.val - 1) + 1)
{}

tls::istream&
operator>>(tls::istream& in, UInt32& obj)
{
  return in >> obj.val;
}

tls::ostream&
operator<<(tls::ostream& out, const UInt32& obj)
{
  return out << obj.val;
}

namespace tree_math {

static uint32_t
log2(uint32_t x)
{
  if (x == 0) {
    return 0;
  }

  uint32_t k = 0;
  while ((x >> k) > 0) {
    k += 1;
  }
  return k - 1;
}

uint32_t
level(NodeIndex x)
{
  if ((x.val & one) == 0) {
    return 0;
  }

  uint32_t k = 0;
  while (((x.val >> k) & one) == 1) {
    k += 1;
  }
  return k;
}

NodeIndex
root(NodeCount w)
{
  return NodeIndex{ (one << log2(w.val)) - 1 };
}

NodeIndex
left(NodeIndex x)
{
  if (level(x) == 0) {
    return x;
  }

  return NodeIndex{ x.val ^ (one << (level(x) - 1)) };
}

NodeIndex
right(NodeIndex x, NodeCount w)
{
  if (level(x) == 0) {
    return x;
  }

  NodeIndex r{ x.val ^ (uint32_t(0x03) << (level(x) - 1)) };
  while (r.val >= w.val) {
    r = left(r);
  }
  return r;
}

static NodeIndex
parent_step(NodeIndex x)
{
  auto k = level(x);
  return NodeIndex{ (x.val | (one << k)) & ~(one << (k + 1)) };
}

NodeIndex
parent(NodeIndex x, NodeCount w)
{
  if (x == root(w)) {
    return x;
  }

  auto p = parent_step(x);
  while (p.val >= w.val) {
    p = parent_step(p);
  }
  return p;
}

NodeIndex
sibling(NodeIndex x, NodeCount w)
{
  auto p = parent(x, w);
  if (x.val < p.val) {
    return right(p, w);
  }

  if (x.val > p.val) {
    return left(p);
  }

  // root's sibling is itself
  return p;
}

std::vector<NodeIndex>
dirpath(NodeIndex x, NodeCount w)
{
  std::vector<NodeIndex> d;

  auto r = root(w);
  for (auto c = x; c.val != r.val; c = parent(c, w)) {
    d.push_back(c);
  }

  return d;
}

std::vector<NodeIndex>
copath(NodeIndex x, NodeCount w)
{
  auto d = dirpath(x, w);
  std::vector<NodeIndex> c(d.size());
  for (size_t i = 0; i < d.size(); ++i) {
    c[i] = sibling(d[i], w);
  }
  return c;
}

} // namespace tree_math
} // namespace mls
