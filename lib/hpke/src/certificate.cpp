#include <hpke/certificate.h>

namespace hpke {

struct Certificate::Internals
{
  const int value;

  explicit Internals(int value_in) : value(value_in) {}
};

Certificate::Certificate(int value_in)
  : internals(std::make_unique<Internals>(value_in))
{}

Certificate::Certificate(const Certificate& other)
  : internals(std::make_unique<Internals>(other.internals->value))
{}

Certificate::Certificate(Certificate&& other) = default;
Certificate::~Certificate() = default;

int
Certificate::value() const
{
  return internals->value;
}

} // namespace hpke
