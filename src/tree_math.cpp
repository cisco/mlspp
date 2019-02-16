#include "tree_math.h"

#include <algorithm>

namespace mls {
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
level(uint32_t x)
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

uint32_t
node_width(uint32_t n)
{
  return 2 * (n - 1) + 1;
}

uint32_t
size_from_width(uint32_t w)
{
  return (w >> one) + 1;
}

uint32_t
root(uint32_t n)
{
  uint32_t w = node_width(n);
  return (one << log2(w)) - 1;
}

uint32_t
left(uint32_t x)
{
  if (level(x) == 0) {
    return x;
  }

  return x ^ (one << (level(x) - 1));
}

uint32_t
right(uint32_t x, uint32_t n)
{
  if (level(x) == 0) {
    return x;
  }

  uint32_t r = x ^ (uint32_t(0x03) << (level(x) - 1));
  while (r >= node_width(n)) {
    r = left(r);
  }
  return r;
}

static uint32_t
parent_step(uint32_t x)
{
  auto k = level(x);
  return (x | (one << k)) & ~(one << (k + 1));
}

uint32_t
parent(uint32_t x, uint32_t n)
{
  if (x == root(n)) {
    return x;
  }

  auto p = parent_step(x);
  while (p >= node_width(n)) {
    p = parent_step(p);
  }
  return p;
}

uint32_t
sibling(uint32_t x, uint32_t n)
{
  auto p = parent(x, n);
  if (x < p) {
    return right(p, n);
  }

  if (x > p) {
    return left(p);
  }

  // root's sibling is itself
  return p;
}

std::vector<uint32_t>
dirpath(uint32_t x, uint32_t n)
{
  std::vector<uint32_t> d;

  auto r = root(n);
  for (auto c = x; c != r; c = parent(c, n)) {
    d.push_back(c);
  }

  return d;
}

std::vector<uint32_t>
copath(uint32_t x, uint32_t n)
{
  auto d = dirpath(x, n);
  std::vector<uint32_t> c(d.size());
  for (size_t i = 0; i < d.size(); ++i) {
    c[i] = sibling(d[i], n);
  }
  return c;
}

} // namespace tree_math
} // namespace mls
