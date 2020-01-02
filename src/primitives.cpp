#include "primitives.h"

#include "openssl/err.h"
#include "openssl/evp.h"

#include <stdexcept>

namespace mls {
namespace primitive {

std::runtime_error
openssl_error()
{
  uint64_t code = ERR_get_error();
  return std::runtime_error(ERR_error_string(code, nullptr));
}

static const size_t key_size_128 = 16;
static const size_t key_size_192 = 24;
static const size_t key_size_256 = 32;

static const EVP_CIPHER*
openssl_cipher(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::P256_SHA256_AES128GCM:
    case CipherSuite::X25519_SHA256_AES128GCM:
      return EVP_aes_128_gcm();

    case CipherSuite::P521_SHA512_AES256GCM:
    case CipherSuite::X448_SHA512_AES256GCM:
      return EVP_aes_256_gcm();

    default:
      throw InvalidParameterError("Unsupported ciphersuite");
  }
}

static size_t
openssl_tag_size(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::P256_SHA256_AES128GCM:
    case CipherSuite::P521_SHA512_AES256GCM:
    case CipherSuite::X25519_SHA256_AES128GCM:
    case CipherSuite::X448_SHA512_AES256GCM:
      return 16;

    default:
      throw InvalidParameterError("Unsupported ciphersuite");
  }
}

bytes
seal(CipherSuite suite,
     const bytes& key,
     const bytes& nonce,
     const bytes& aad,
     const bytes& plaintext)
{
  auto ctx = make_typed_unique(EVP_CIPHER_CTX_new());
  if (ctx.get() == nullptr) {
    throw openssl_error();
  }

  auto cipher = openssl_cipher(suite);
  if (1 != EVP_EncryptInit(ctx.get(), cipher, key.data(), nonce.data())) {
    throw openssl_error();
  }

  int outlen = 0;
  if (!aad.empty()) {
    if (1 != EVP_EncryptUpdate(
               ctx.get(), nullptr, &outlen, aad.data(), aad.size())) {
      throw openssl_error();
    }
  }

  bytes ciphertext(plaintext.size());
  if (1 != EVP_EncryptUpdate(ctx.get(),
                             ciphertext.data(),
                             &outlen,
                             plaintext.data(),
                             plaintext.size())) {
    throw openssl_error();
  }

  // Providing nullptr as an argument is safe here because this
  // function never writes with GCM; it only computes the tag
  if (1 != EVP_EncryptFinal(ctx.get(), nullptr, &outlen)) {
    throw openssl_error();
  }

  auto tag_size = openssl_tag_size(suite);
  bytes tag(tag_size);
  if (1 != EVP_CIPHER_CTX_ctrl(
             ctx.get(), EVP_CTRL_GCM_GET_TAG, tag_size, tag.data())) {
    throw openssl_error();
  }

  return ciphertext + tag;
}

bytes
open(CipherSuite suite,
     const bytes& key,
     const bytes& nonce,
     const bytes& aad,
     const bytes& ciphertext)
{
  auto tag_size = openssl_tag_size(suite);
  if (ciphertext.size() < tag_size) {
    throw InvalidParameterError("AES-GCM ciphertext smaller than tag size");
  }

  auto ctx = make_typed_unique(EVP_CIPHER_CTX_new());
  if (ctx.get() == nullptr) {
    throw openssl_error();
  }

  auto cipher = openssl_cipher(suite);
  if (1 != EVP_DecryptInit(ctx.get(), cipher, key.data(), nonce.data())) {
    throw openssl_error();
  }

  bytes tag(ciphertext.end() - tag_size, ciphertext.end());
  if (1 != EVP_CIPHER_CTX_ctrl(
             ctx.get(), EVP_CTRL_GCM_SET_TAG, tag_size, tag.data())) {
    throw openssl_error();
  }

  int out_size;
  if (!aad.empty()) {
    if (1 != EVP_DecryptUpdate(
               ctx.get(), nullptr, &out_size, aad.data(), aad.size())) {
      throw openssl_error();
    }
  }

  bytes plaintext(ciphertext.size() - tag_size);
  if (1 != EVP_DecryptUpdate(ctx.get(),
                             plaintext.data(),
                             &out_size,
                             ciphertext.data(),
                             ciphertext.size() - tag_size)) {
    throw openssl_error();
  }

  // Providing nullptr as an argument is safe here because this
  // function never writes with GCM; it only verifies the tag
  if (1 != EVP_DecryptFinal(ctx.get(), nullptr, &out_size)) {
    throw InvalidParameterError("AES-GCM authentication failure");
  }

  return plaintext;
}

}; // namespace primitive
}; // namespace mls
