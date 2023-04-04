#include "grease.h"

#include <random>
#include <set>

namespace mls {

// Randomness parmeters:
// * Given a list of N items, insert max(1, rand(p_grease * N)) GREASE values
// * Each GREASE value added is distinct, unless more than 15 values are needed
// * For extensions, each GREASE extension has rand(n_grease_ext) random bytes
//   of data
const size_t log_p_grease = 1; // -log2(p_grease) => p_grease = 1/2
const size_t max_grease_ext_size = 16;

const std::array<uint16_t, 15> grease_values = { 0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
                                                 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
                                                 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
                                                 0xCACA, 0xDADA, 0xEAEA };

static size_t
rand_int(size_t n)
{
  static auto seed = std::random_device()();
  static auto rng = std::mt19937(seed);
  return std::uniform_int_distribution<size_t>(0, n)(rng);
}

static uint16_t
grease_value()
{
  const auto where = rand_int(grease_values.size() - 1);
  return grease_values.at(where);
}

static bool
grease_value(uint16_t val)
{
  static constexpr auto grease_mask = uint16_t(0x0F0F);
  return ((val & grease_mask) == 0x0A0A) && val != 0xFAFA;
}

static std::set<uint16_t>
grease_sample(size_t count)
{
  auto vals = std::set<uint16_t>{};

  while (vals.size() < count) {
    uint16_t val = grease_value();
    while (vals.count(val) > 0 && vals.size() < grease_values.size()) {
      val = grease_value();
    }

    vals.insert(val);
  }

  return vals;
}

template<typename T>
static std::vector<T>
grease(std::vector<T>&& in)
{
  auto out = in;

  const auto count = std::max(size_t(1), rand_int(in.size() >> log_p_grease));
  for (const auto val : grease_sample(count)) {
    const auto where = static_cast<ptrdiff_t>(rand_int(out.size()));
    out.insert(std::begin(out) + where, static_cast<T>(val));
  }

  return out;
}

Capabilities
grease(Capabilities&& capabilities, const ExtensionList& extensions)
{
  auto capas = Capabilities{
    std::move(capabilities.versions),
    grease(std::move(capabilities.cipher_suites)),
    grease(std::move(capabilities.extensions)),
    grease(std::move(capabilities.proposals)),
    grease(std::move(capabilities.credentials)),
  };

  // Ensure that the GREASE extensions are reflected in Capabilities.extensions
  for (const auto& ext : extensions.extensions) {
    if (!grease_value(ext.type)) {
      continue;
    }

    if (stdx::contains(capas.extensions, ext.type)) {
      continue;
    }

    const auto where =
      static_cast<ptrdiff_t>(rand_int(capas.extensions.size()));
    const auto where_ptr = std::begin(capas.extensions) + where;
    capas.extensions.insert(where_ptr, ext.type);
  }

  return capas;
}

ExtensionList
grease(ExtensionList&& extensions)
{
  auto ext = extensions.extensions;

  const auto count = std::max(size_t(1), rand_int(ext.size() >> log_p_grease));
  for (const auto ext_type : grease_sample(count)) {
    const auto where = static_cast<ptrdiff_t>(rand_int(ext.size()));
    auto ext_data = random_bytes(rand_int(max_grease_ext_size));
    ext.insert(std::begin(ext) + where, { ext_type, std::move(ext_data) });
  }

  return { ext };
}

} // namespace mls
