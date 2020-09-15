#include <doctest/doctest.h>
#include <mls/credential.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <vector>

using namespace mls;
using hpke::Digest;

// TODO(SNK): extend it once we add full chain support.
struct CertTemplate
{
  bool is_ca;
};

static std::runtime_error
openssl_error()
{
  uint64_t code = ERR_get_error();
  return std::runtime_error(ERR_error_string(code, nullptr));
}

void
rand_serial(ASN1_INTEGER* ai)
{
  // https://docs.huihoo.com/doxygen/openssl/1.0.1c/apps_8c_source.html
  BIGNUM* btmp = BN_new();
  if (btmp == nullptr) {
    throw openssl_error();
  }

  if (BN_pseudo_rand(btmp, 64, 0, 0) == 0) {
    throw openssl_error();
  }

  if (BN_to_ASN1_INTEGER(btmp, ai) == nullptr) {
    throw openssl_error();
  }

  BN_free(btmp);
}

int
generate_set_random_serial(X509* crt)
{
  ASN1_INTEGER* serial = ASN1_INTEGER_new();
  if (serial == nullptr) {
    throw openssl_error();
  }
  rand_serial(serial);
  if (X509_set_serialNumber(crt, serial) == 0) {
    throw openssl_error();
  }
  ASN1_INTEGER_free(serial);
  return 1;
}

// Generate a <priv,pub>ed2519 signing key pair.
std::tuple<EVP_PKEY*, EVP_PKEY*>
newEd25519SigningKeyPair()
{
  size_t secret_size = 32;
  size_t raw_len = 0;

  auto data = random_bytes(secret_size);
  auto digest = Digest::get<Digest::ID::SHA256>().hash(data);
  // digest.resize(secret_size);
  auto* pkey = EVP_PKEY_new_raw_private_key(
    EVP_PKEY_ED25519, nullptr, data.data(), data.size());

  if (pkey == nullptr) {
    throw openssl_error();
  }

  if (1 != EVP_PKEY_get_raw_private_key(pkey, nullptr, &raw_len)) {
    throw openssl_error();
  }

  bytes raw(raw_len);
  uint8_t* data_ptr = raw.data();
  if (1 != EVP_PKEY_get_raw_private_key(pkey, data_ptr, &raw_len)) {
    throw openssl_error();
  }

  auto* pubKey = EVP_PKEY_new_raw_public_key(
    EVP_PKEY_ED25519, nullptr, raw.data(), raw.size());
  if (pubKey == nullptr) {
    throw openssl_error();
  }

  return std::make_tuple(pkey, pubKey);
}

X509*
make_cert(CertTemplate cert_template,
          std::string identity,
          EVP_PKEY* public_key,
          EVP_PKEY* priv_key)
{
  X509* cert = nullptr;
  X509V3_CTX ctx;
  X509_EXTENSION* ext = nullptr;
  BIGNUM* serial_number = nullptr;
  X509_NAME* name = nullptr;

  cert = X509_new();

  if (X509_set_pubkey(cert, public_key) == 0) {
    throw openssl_error();
  }

  if (generate_set_random_serial(cert) == 0) {
    throw openssl_error();
  }

  if (X509_set_version(cert, 0x02) == 0) {
    throw openssl_error();
  }

  if ((name = X509_NAME_new()) == nullptr ||
      X509_NAME_add_entry_by_NID(
        name,
        NID_commonName,
        MBSTRING_UTF8,
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        reinterpret_cast<unsigned char*>(identity.data()),
        -1,
        -1,
        0) == 0 ||
      X509_set_subject_name(cert, name) == 0 ||
      X509_set_issuer_name(cert, name) == 0) {
    throw openssl_error();
  }

  // validity
  int days = 1;
  X509_gmtime_adj(X509_get_notBefore(cert), 0);

  X509_gmtime_adj(X509_get_notAfter(cert),
                  static_cast<int64_t>(60 * 60 * 24 * days));

  if (cert_template.is_ca) {
    ext = X509V3_EXT_conf(nullptr, &ctx, "basicConstraints", "CA:TRUE");
  } else {
    ext = X509V3_EXT_conf(nullptr, &ctx, "basicConstraints", "CA:FALSE");
  }

  X509_add_ext(cert, ext, -1);
  X509_EXTENSION_free(ext);

  if (X509_sign(cert, priv_key, nullptr) == 0) {
    throw openssl_error();
  }

  /*
   BIO *outbio = nullptr;
  outbio  = BIO_new(BIO_s_file());
  outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
  if (! PEM_write_bio_X509(outbio, cert)) {
    BIO_printf(outbio, "Error printing the signed certificate\n");
  }
   */
  BN_free(serial_number);

  return cert;
}

TEST_CASE("Basic Credential")
{
  auto suite = CipherSuite{ CipherSuite::ID::P256_AES128GCM_SHA256_P256 };

  auto user_id = bytes{ 0x00, 0x01, 0x02, 0x03 };
  auto priv = SignaturePrivateKey::generate(suite);
  auto pub = priv.public_key;

  auto cred = Credential::basic(user_id, pub);
  REQUIRE(cred.identity() == user_id);
  REQUIRE(cred.public_key() == pub);
}

TEST_CASE("X509 Credential Basic")
{
  auto key_pair = newEd25519SigningKeyPair();
  CertTemplate caTemplate = { true };
  std::string subject_identity = "cypto-core";
  auto* leaf_cert = make_cert(
    caTemplate, subject_identity, std::get<1>(key_pair), std::get<0>(key_pair));
  REQUIRE(leaf_cert != nullptr);

  int len = i2d_X509(leaf_cert, nullptr);
  bytes leaf_cert_raw(len);
  unsigned char* tmp = leaf_cert_raw.data();
  i2d_X509(leaf_cert, &tmp);
  std::vector<bytes> cert_chain = { leaf_cert_raw };
  auto cred = Credential::x509(cert_chain);
  REQUIRE(cred.public_key().data.empty() == false);
}