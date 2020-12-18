#include <mls_vectors/mls_vectors.h>

///
/// TreeMathTestVector
///
TreeMathTestVector TreeMathTestVector::create(uint32_t /* n_leaves */)
{
  return {};
}

std::optional<std::string>
TreeMathTestVector::verify(const TreeMathTestVector& /* tv */)
{
  return std::nullopt;
}

///
/// HashRatchetTestVector
///

HashRatchetTestVector HashRatchetTestVector::create(
  CipherSuite /* suite */,
  uint32_t /* n_leaves */,
  uint32_t /* n_generations */)
{
  return {};
}

std::optional<std::string>
HashRatchetTestVector::verify(const HashRatchetTestVector& /* tv */)
{
  return std::nullopt;
}

///
/// SecretTreeTestVector
///

SecretTreeTestVector SecretTreeTestVector::create(CipherSuite /* suite */,
                                                  uint32_t /* n_leaves */)
{
  return {};
}

std::optional<std::string>
SecretTreeTestVector::verify(const SecretTreeTestVector& /* tv */)
{
  return std::nullopt;
}

///
/// KeyScheduleTestVector
///

KeyScheduleTestVector KeyScheduleTestVector::create(CipherSuite /* suite */,
                                                    uint32_t /* n_epochs */)
{
  return {};
}

std::optional<std::string>
KeyScheduleTestVector::verify(const KeyScheduleTestVector& /* tv */)
{
  return std::nullopt;
}

///
/// TreeHashingTestVector
///

TreeHashingTestVector TreeHashingTestVector::create(CipherSuite /* suite */,
                                                    uint32_t /* n_leaves */)
{
  return {};
}

std::optional<std::string>
TreeHashingTestVector::verify(const TreeHashingTestVector& /* tv */)
{
  return std::nullopt;
}

///
/// MessagesTestVector
///

MessagesTestVector
MessagesTestVector::create()
{
  return {};
}

std::optional<std::string>
MessagesTestVector::verify(const MessagesTestVector& /* tv */)
{
  return std::nullopt;
}
