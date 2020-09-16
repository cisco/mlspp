#pragma once

#include <memory>

#include <bytes/bytes.h>
using namespace bytes_ns;

namespace hpke {

struct Certificate
{
  // TODO replace with real public members
  /*
  const Signature::ID public_key_algorithm;
  const Signature::PublicKey public_key;
  const bytes raw;

  static Certificate parse(const bytes& der);
  bool valid_from(const Certificate& parent);

  private:
  */

  Certificate() = delete;
  Certificate(int value_in);
  Certificate(const Certificate& other);
  Certificate(Certificate&& other);
  ~Certificate();

  int value() const;

  private:
  struct Internals;
  std::unique_ptr<Internals> internals;

  // TODO constructors down here
  // Certificate(Signature::ID,
  //             Signature::PublicKey,
  //             bytes,
  //             Internals*);
};

} // namespace hpke
