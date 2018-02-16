#include "tree_math.h"

namespace mls {
namespace tree_math {

static size_t
log2(size_t x)
{
  if (x == 0) {
    return 0;
  }

  size_t k = 0;
  while ((x >> k) > 0) {
    k += 1;
  }
  return k - 1;
}

static size_t
level(size_t x)
{
  if ((x & 0x01) == 0) {
    return 0;
  }

  size_t k = 0;
  while (((x >> k) & 0x01) == 1) {
    k += 1;
  }
  return k;
}

static size_t
node_width(size_t n)
{
  return 2 * (n - 1) + 1;
}

size_t
root(size_t n)
{
  size_t w = node_width(n);
  return (1 << log2(w)) - 1;
}

size_t
left(size_t x)
{
  if (level(x) == 0) {
    return x;
  }

  return x ^ (0x01 << (level(x) - 1));
}

size_t
right(size_t x, size_t n)
{
  if (level(x) == 0) {
    return x;
  }

  size_t r = x ^ (0x03 << (level(x) - 1));
  while (r >= node_width(n)) {
    r = left(r);
  }
  return r;
}

static size_t
parent_step(size_t x)
{
  auto k = level(x);
  size_t one = 1;
  return (x | (one << k)) & ~(one << (k + 1));
}

size_t
parent(size_t x, size_t n)
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

size_t
sibling(size_t x, size_t n)
{
  auto p = parent(x, n);
  if (x < p) {
    return right(p, n);
  } else if (x > p) {
    return left(p);
  }

  // root's sibling is itself
  return p;
}

static size_t
subtree_size(size_t x, size_t n)
{
  auto w = node_width(n);
  auto lr = (1 << level(x)) - 1;
  auto rr = lr;
  if (x + rr >= w) {
    rr = w - x - 1;
  }

  return (lr + rr) / 2 + 1;
}

std::vector<size_t>
frontier(size_t n)
{
  if (n == 0) {
    return std::vector<size_t>{};
  }

  auto r = root(n);
  auto s = subtree_size(r, n);
  std::vector<size_t> f;
  while (s != (1 << log2(s))) {
    auto l = left(r);
    r = right(r, n);
    s = subtree_size(r, n);
    f.push_back(l);
  }
  f.push_back(r);
  return f;
}

std::vector<size_t>
dirpath(size_t x, size_t n)
{
  std::vector<size_t> d;
  auto p = parent(x, n);
  auto r = root(n);
  while (p != r) {
    d.insert(d.begin(), p);
    p = parent(p, n);
  }
  return d;
}

std::vector<size_t>
copath(size_t x, size_t n)
{
  auto d = dirpath(x, n);

  // Add leaf, which is missing from direct path
  if (x != sibling(x, n)) {
    d.push_back(x);
  }

  std::vector<size_t> c(d.size());
  std::transform(d.begin(), d.end(), c.begin(), [n](size_t& x) -> size_t {
    return sibling(x, n);
  });
  return c;
}

std::vector<size_t>
leaves(size_t n)
{
  std::vector<size_t> out(n);
  for (size_t i = 0; i < n; i += 1) {
    out[i] = 2 * i;
  }
  return out;
}

} // namespace tree_math
} // namespace mls
