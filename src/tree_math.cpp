#include "tree_math.h"
#include "tls_syntax.h"

#include <algorithm>

namespace mls {

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

static uint32_t one = 0x01;

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
  if ((x & one) == 0) {
    return 0;
  }

  uint32_t k = 0;
  while (((x >> k) & one) == 1) {
    k += 1;
  }
  return k;
}

NodeCount
node_width(LeafCount n)
{
  return NodeCount{ 2 * (n.val - 1) + 1 };
}

LeafCount
size_from_width(NodeCount w)
{
  if (w.val == 0) {
    return LeafCount{ 0 };
  }

  return LeafCount{ (w.val >> one) + 1 };
}

NodeIndex
root(NodeCount w)
{
  return (one << log2(w.val)) - 1;
}

NodeIndex
left(NodeIndex x)
{
  if (level(x) == 0) {
    return x;
  }

  return x ^ (one << (level(x) - 1));
}

NodeIndex
right(NodeIndex x, NodeCount w)
{
  if (level(x) == 0) {
    return x;
  }

  uint32_t r = x ^ (uint32_t(0x03) << (level(x) - 1));
  while (r >= w.val) {
    r = left(r);
  }
  return r;
}

static NodeIndex
parent_step(NodeIndex x)
{
  auto k = level(x);
  return (x | (one << k)) & ~(one << (k + 1));
}

NodeIndex
parent(NodeIndex x, NodeCount w)
{
  if (x == root(w)) {
    return x;
  }

  auto p = parent_step(x);
  while (p >= w.val) {
    p = parent_step(p);
  }
  return p;
}

NodeIndex
sibling(NodeIndex x, NodeCount w)
{
  auto p = parent(x, w);
  if (x < p) {
    return right(p, w);
  }

  if (x > p) {
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
  for (auto c = x; c != r; c = parent(c, w)) {
    d.push_back(c);
  }

  return d;
}

std::vector<NodeIndex>
copath(NodeIndex x, NodeCount w)
{
  auto d = dirpath(x, w);
  std::vector<uint32_t> c(d.size());
  for (size_t i = 0; i < d.size(); ++i) {
    c[i] = sibling(d[i], w);
  }
  return c;
}

} // namespace tree_math
} // namespace mls
