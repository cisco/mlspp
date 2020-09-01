#include "aead_cipher.h"
#include "openssl_common.h"

#include <openssl/evp.h>

namespace hpke {

static size_t
cipher_key_size(AEAD::ID cipher)
{
  switch (cipher) {
    case AEAD::ID::AES_128_GCM:
      return 16;

    case AEAD::ID::AES_256_GCM:
    case AEAD::ID::CHACHA20_POLY1305:
      return 32;

    default:
      throw std::runtime_error("Unsupported algorithm");
  }
}

static size_t
cipher_nonce_size(AEAD::ID cipher)
{
  switch (cipher) {
    case AEAD::ID::AES_128_GCM:
    case AEAD::ID::AES_256_GCM:
    case AEAD::ID::CHACHA20_POLY1305:
      return 12;

    default:
      throw std::runtime_error("Unsupported algorithm");
  }
}

static size_t
cipher_tag_size(AEAD::ID cipher)
{
  switch (cipher) {
    case AEAD::ID::AES_128_GCM:
    case AEAD::ID::AES_256_GCM:
    case AEAD::ID::CHACHA20_POLY1305:
      return 16;

    default:
      throw std::runtime_error("Unsupported algorithm");
  }
}

static const EVP_CIPHER*
openssl_cipher(AEAD::ID cipher)
{
  switch (cipher) {
    case AEAD::ID::AES_128_GCM:
      return EVP_aes_128_gcm();

    case AEAD::ID::AES_256_GCM:
      return EVP_aes_256_gcm();

    case AEAD::ID::CHACHA20_POLY1305:
      return EVP_chacha20_poly1305();

    default:
      throw std::runtime_error("Unsupported algorithm");
  }
}

AEADCipher::AEADCipher(AEAD::ID cipher_in)
  : cipher(cipher_in)
  , nk(cipher_key_size(cipher_in))
  , nn(cipher_nonce_size(cipher_in))
  , tag_size(cipher_tag_size(cipher_in))
{}

std::unique_ptr<AEAD>
AEADCipher::clone() const
{
  return std::make_unique<AEADCipher>(cipher);
}

bytes
AEADCipher::seal(const bytes& key,
                 const bytes& nonce,
                 const bytes& aad,
                 const bytes& pt) const
{
  auto ctx = make_typed_unique(EVP_CIPHER_CTX_new());
  if (ctx == nullptr) {
    throw openssl_error();
  }

  const auto* ocipher = openssl_cipher(cipher);
  if (1 != EVP_EncryptInit(ctx.get(), ocipher, key.data(), nonce.data())) {
    throw openssl_error();
  }

  int outlen = 0;
  if (!aad.empty()) {
    if (1 != EVP_EncryptUpdate(
               ctx.get(), nullptr, &outlen, aad.data(), aad.size())) {
      throw openssl_error();
    }
  }

  bytes ct(pt.size());
  if (1 !=
      EVP_EncryptUpdate(ctx.get(), ct.data(), &outlen, pt.data(), pt.size())) {
    throw openssl_error();
  }

  // Providing nullptr as an argument is safe here because this
  // function never writes with GCM; it only computes the tag
  if (1 != EVP_EncryptFinal(ctx.get(), nullptr, &outlen)) {
    throw openssl_error();
  }

  bytes tag(tag_size);
  if (1 != EVP_CIPHER_CTX_ctrl(
             ctx.get(), EVP_CTRL_GCM_GET_TAG, tag_size, tag.data())) {
    throw openssl_error();
  }

  ct.insert(ct.end(), tag.begin(), tag.end());
  return ct;
}

std::optional<bytes>
AEADCipher::open(const bytes& key,
                 const bytes& nonce,
                 const bytes& aad,
                 const bytes& ct) const
{
  if (ct.size() < tag_size) {
    throw std::runtime_error("AEAD ciphertext smaller than tag size");
  }

  auto ctx = make_typed_unique(EVP_CIPHER_CTX_new());
  if (ctx == nullptr) {
    throw openssl_error();
  }

  const auto* ocipher = openssl_cipher(cipher);
  if (1 != EVP_DecryptInit(ctx.get(), ocipher, key.data(), nonce.data())) {
    throw openssl_error();
  }

  auto inner_ct_size = ct.size() - tag_size;
  auto tag = bytes(ct.begin() + inner_ct_size, ct.end());
  if (1 != EVP_CIPHER_CTX_ctrl(
             ctx.get(), EVP_CTRL_GCM_SET_TAG, tag_size, tag.data())) {
    throw openssl_error();
  }

  int out_size = 0;
  if (!aad.empty()) {
    if (1 != EVP_DecryptUpdate(
               ctx.get(), nullptr, &out_size, aad.data(), aad.size())) {
      throw openssl_error();
    }
  }

  bytes pt(inner_ct_size);
  if (1 != EVP_DecryptUpdate(
             ctx.get(), pt.data(), &out_size, ct.data(), inner_ct_size)) {
    throw openssl_error();
  }

  // Providing nullptr as an argument is safe here because this
  // function never writes with GCM; it only verifies the tag
  if (1 != EVP_DecryptFinal(ctx.get(), nullptr, &out_size)) {
    throw std::runtime_error("AEAD authentication failure");
  }

  return pt;
}

size_t
AEADCipher::key_size() const
{
  return nk;
}

size_t
AEADCipher::nonce_size() const
{
  return nn;
}

} // namespace hpke
