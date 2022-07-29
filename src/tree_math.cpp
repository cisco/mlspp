#include "mls/tree_math.h"
#include "mls/common.h"

#include <algorithm>

static const uint32_t one = 0x01;

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

LeafCount
LeafCount::full(const LeafCount n)
{
  auto k = log2(n.val);
  return LeafCount{ 1U << (k + 1) };
}

NodeCount::NodeCount(const LeafCount n)
  : UInt32(2 * (n.val - 1) + 1)
{
}

LeafIndex::LeafIndex(NodeIndex x)
  : UInt32(0)
{
  if (x.val % 2 == 1) {
    throw InvalidParameterError("Only even node indices describe leaves");
  }

  val = x.val >> 1; // NOLINT(hicpp-signed-bitwise)
}

NodeIndex::NodeIndex(LeafIndex x)
  : UInt32(2 * x.val)
{
}

tls::ostream&
operator<<(tls::ostream& str, const LeafIndex& obj)
{
  return str << NodeIndex(obj);
}

tls::istream&
operator>>(tls::istream& str, LeafIndex& obj)
{
  auto index = NodeIndex(0);
  str >> index;
  obj = LeafIndex(index);
  return str;
}

namespace tree_math {

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
root(LeafCount n)
{
  if (n.val == 0) {
    throw std::runtime_error("Root for zero-size tree is undefined");
  }

  auto w = NodeCount(n);
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
right(NodeIndex x)
{
  if (level(x) == 0) {
    return x;
  }

  return NodeIndex{ x.val ^ (uint32_t(0x03) << (level(x) - 1)) };
}

NodeIndex
parent(NodeIndex x)
{
  auto k = level(x);
  return NodeIndex{ (x.val | (one << k)) & ~(one << (k + 1)) };
}

NodeIndex
sibling(NodeIndex x)
{
  auto p = parent(x);
  auto l = left(p);
  auto r = right(p);

  if (x.val == l.val) {
    return r;
  }

  return l;
}

std::vector<NodeIndex>
dirpath(NodeIndex x, LeafCount n)
{
  std::vector<NodeIndex> d;

  auto r = root(n);
  if (x == r) {
    return d;
  }

  auto p = parent(x);
  while (p.val != r.val) {
    d.push_back(p);
    p = parent(p);
  }

  if (x.val != r.val) {
    d.push_back(p);
  }

  return d;
}

std::vector<NodeIndex>
copath(NodeIndex x, LeafCount n)
{
  auto d = dirpath(x, n);
  if (d.empty()) {
    return {};
  }

  std::vector<NodeIndex> path;
  path.push_back(x);
  // exclude root
  for (size_t i = 0; i < d.size() - 1; ++i) {
    path.push_back(d[i]);
  }

  std::vector<NodeIndex> c(path.size());
  for (size_t i = 0; i < path.size(); ++i) {
    c[i] = sibling(path[i]);
  }

  return c;
}

bool
in_path(NodeIndex x, NodeIndex y)
{
  auto lx = level(x);
  auto ly = level(y);
  return lx <= ly && (x.val >> (ly + 1) == y.val >> (ly + 1));
}

// Common ancestor of two leaves
NodeIndex
ancestor(LeafIndex l, LeafIndex r)
{
  auto ln = NodeIndex(l);
  auto rn = NodeIndex(r);
  if (ln == rn) {
    return ln;
  }

  uint8_t k = 0;
  while (ln != rn) {
    ln.val = ln.val >> 1U;
    rn.val = rn.val >> 1U;
    k += 1;
  }

  uint32_t prefix = ln.val << k;
  uint32_t stop = (1U << uint8_t(k - 1));
  // NOLINTNEXTLINE(modernize-return-braced-init-list)
  return NodeIndex(prefix + (stop - 1));
}

} // namespace tree_math
} // namespace mls
