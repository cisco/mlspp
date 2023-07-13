#include "common.h"
#include <mls_vectors/mls_vectors.h>

namespace mls_vectors {

using namespace mls;

CryptoBasicsTestVector::RefHash::RefHash(CipherSuite suite,
                                         PseudoRandom::Generator&& prg)
  : label("RefHash")
  , value(prg.secret("value"))
  , out(suite.raw_ref(from_ascii(label), value))
{
}

std::optional<std::string>
CryptoBasicsTestVector::RefHash::verify(CipherSuite suite) const
{
  VERIFY_EQUAL("ref hash", out, suite.raw_ref(from_ascii(label), value));
  return std::nullopt;
}

CryptoBasicsTestVector::ExpandWithLabel::ExpandWithLabel(
  CipherSuite suite,
  PseudoRandom::Generator&& prg)
  : secret(prg.secret("secret"))
  , label("ExpandWithLabel")
  , context(prg.secret("context"))
  , length(static_cast<uint16_t>(prg.output_length()))
  , out(suite.expand_with_label(secret, label, context, length))
{
}

std::optional<std::string>
CryptoBasicsTestVector::ExpandWithLabel::verify(CipherSuite suite) const
{
  VERIFY_EQUAL("expand with label",
               out,
               suite.expand_with_label(secret, label, context, length));
  return std::nullopt;
}

CryptoBasicsTestVector::DeriveSecret::DeriveSecret(
  CipherSuite suite,
  PseudoRandom::Generator&& prg)
  : secret(prg.secret("secret"))
  , label("DeriveSecret")
  , out(suite.derive_secret(secret, label))
{
}

std::optional<std::string>
CryptoBasicsTestVector::DeriveSecret::verify(CipherSuite suite) const
{
  VERIFY_EQUAL("derive secret", out, suite.derive_secret(secret, label));
  return std::nullopt;
}

CryptoBasicsTestVector::DeriveTreeSecret::DeriveTreeSecret(
  CipherSuite suite,
  PseudoRandom::Generator&& prg)
  : secret(prg.secret("secret"))
  , label("DeriveTreeSecret")
  , generation(prg.uint32("generation"))
  , length(static_cast<uint16_t>(prg.output_length()))
  , out(suite.derive_tree_secret(secret, label, generation, length))
{
}

std::optional<std::string>
CryptoBasicsTestVector::DeriveTreeSecret::verify(CipherSuite suite) const
{
  VERIFY_EQUAL("derive tree secret",
               out,
               suite.derive_tree_secret(secret, label, generation, length));
  return std::nullopt;
}

CryptoBasicsTestVector::SignWithLabel::SignWithLabel(
  CipherSuite suite,
  PseudoRandom::Generator&& prg)
  : priv(prg.signature_key("priv"))
  , pub(priv.public_key)
  , content(prg.secret("content"))
  , label("SignWithLabel")
  , signature(priv.sign(suite, label, content))
{
}

std::optional<std::string>
CryptoBasicsTestVector::SignWithLabel::verify(CipherSuite suite) const
{
  VERIFY("verify with label", pub.verify(suite, label, content, signature));

  auto new_signature = priv.sign(suite, label, content);
  VERIFY("sign with label", pub.verify(suite, label, content, new_signature));

  return std::nullopt;
}

CryptoBasicsTestVector::EncryptWithLabel::EncryptWithLabel(
  CipherSuite suite,
  PseudoRandom::Generator&& prg)
  : priv(prg.hpke_key("priv"))
  , pub(priv.public_key)
  , label("EncryptWithLabel")
  , context(prg.secret("context"))
  , plaintext(prg.secret("plaintext"))
{
  auto ct = pub.encrypt(suite, label, context, plaintext);
  kem_output = ct.kem_output;
  ciphertext = ct.ciphertext;
}

std::optional<std::string>
CryptoBasicsTestVector::EncryptWithLabel::verify(CipherSuite suite) const
{
  auto ct = HPKECiphertext{ kem_output, ciphertext };
  auto pt = priv.decrypt(suite, label, context, ct);
  VERIFY_EQUAL("decrypt with label", pt, plaintext);

  auto new_ct = pub.encrypt(suite, label, context, plaintext);
  auto new_pt = priv.decrypt(suite, label, context, new_ct);
  VERIFY_EQUAL("encrypt with label", new_pt, plaintext);

  return std::nullopt;
}

CryptoBasicsTestVector::CryptoBasicsTestVector(CipherSuite suite)
  : PseudoRandom(suite, "crypto-basics")
  , cipher_suite(suite)
  , ref_hash(suite, prg.sub("ref_hash"))
  , expand_with_label(suite, prg.sub("expand_with_label"))
  , derive_secret(suite, prg.sub("derive_secret"))
  , derive_tree_secret(suite, prg.sub("derive_tree_secret"))
  , sign_with_label(suite, prg.sub("sign_with_label"))
  , encrypt_with_label(suite, prg.sub("encrypt_with_label"))
{
}

std::optional<std::string>
CryptoBasicsTestVector::verify() const
{
  auto result = ref_hash.verify(cipher_suite);
  if (result) {
    return result;
  }

  result = expand_with_label.verify(cipher_suite);
  if (result) {
    return result;
  }

  result = derive_secret.verify(cipher_suite);
  if (result) {
    return result;
  }

  result = derive_tree_secret.verify(cipher_suite);
  if (result) {
    return result;
  }

  result = sign_with_label.verify(cipher_suite);
  if (result) {
    return result;
  }

  result = encrypt_with_label.verify(cipher_suite);
  if (result) {
    return result;
  }

  return std::nullopt;
}

} // namespace mls_vectors
