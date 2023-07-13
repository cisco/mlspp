#include <mls_vectors/mls_vectors.h>

namespace mls_vectors {

using namespace mls;

PseudoRandom::Generator::Generator(CipherSuite suite_in,
                                   const std::string& label)
  : suite(suite_in)
  , seed(suite.hpke().kdf.extract({}, from_ascii(label)))
{
}

PseudoRandom::Generator::Generator(CipherSuite suite_in, bytes&& seed_in)
  : suite(suite_in)
  , seed(seed_in)
{
}

PseudoRandom::Generator
PseudoRandom::Generator::sub(const std::string& label) const
{
  return { suite, suite.derive_secret(seed, label) };
}

bytes
PseudoRandom::Generator::secret(const std::string& label) const
{
  return suite.derive_secret(seed, label);
}

bytes
PseudoRandom::Generator::generate(const std::string& label, size_t size) const
{
  return suite.expand_with_label(seed, label, {}, size);
}

uint16_t
PseudoRandom::Generator::uint16(const std::string& label) const
{
  auto data = generate(label, 2);
  return tls::get<uint16_t>(data);
}

uint32_t
PseudoRandom::Generator::uint32(const std::string& label) const
{
  auto data = generate(label, 4);
  return tls::get<uint16_t>(data);
}

uint64_t
PseudoRandom::Generator::uint64(const std::string& label) const
{
  auto data = generate(label, 8);
  return tls::get<uint16_t>(data);
}

SignaturePrivateKey
PseudoRandom::Generator::signature_key(const std::string& label) const
{
  auto data = generate(label, suite.secret_size());
  return SignaturePrivateKey::derive(suite, data);
}

HPKEPrivateKey
PseudoRandom::Generator::hpke_key(const std::string& label) const
{
  auto data = generate(label, suite.secret_size());
  return HPKEPrivateKey::derive(suite, data);
}

size_t
PseudoRandom::Generator::output_length() const
{
  return suite.secret_size();
}

PseudoRandom::PseudoRandom(CipherSuite suite, const std::string& label)
  : prg(suite, label)
{
}

} // namespace mls_vectors
