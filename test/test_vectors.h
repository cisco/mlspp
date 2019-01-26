#include "common.h"
#include "messages.h"
#include "state.h"
#include "tls_syntax.h"
#include <string>

using namespace mls;

struct TreeMathTestVectors
{
  static const std::string file_name;
  static const size_t tree_size = 255;

  tls::vector<uint32_t, 4> root;
  tls::vector<uint32_t, 4> left;
  tls::vector<uint32_t, 4> right;
  tls::vector<uint32_t, 4> parent;
  tls::vector<uint32_t, 4> sibling;
};

struct CryptoTestVectors
{
  static const std::string file_name;

  struct TestCase
  {
    // HKDF-Extract
    tls::opaque<1> hkdf_extract_salt;
    tls::opaque<1> hkdf_extract_ikm;
    tls::opaque<1> hkdf_extract_out;

    // Derive-Secret
    tls::opaque<1> derive_secret_secret;
    tls::opaque<1> derive_secret_label;
    GroupState derive_secret_state;
    uint32_t derive_secret_length;
    tls::opaque<1> derive_secret_out;

    // Derive-Key-Pair
    tls::opaque<1> derive_key_pair_seed;
    DHPublicKey derive_key_pair_pub;

    // ECIES
    tls::opaque<1> ecies_seed;
    tls::opaque<1> ecies_plaintext;
    DHPublicKey ecies_recipient_pub;
    ECIESCiphertext ecies_out;

    TestCase(CipherSuite suite)
      : derive_secret_state(suite)
      , derive_key_pair_pub(suite)
      , ecies_recipient_pub(suite)
      , ecies_out(suite)
    {}
  };

  CryptoTestVectors()
    : case_p256(CipherSuite::P256_SHA256_AES128GCM)
    , case_x25519(CipherSuite::X25519_SHA256_AES128GCM)
    , case_p521(CipherSuite::P521_SHA512_AES256GCM)
    , case_x448(CipherSuite::X448_SHA512_AES256GCM)
  {}

  TestCase case_p256;
  TestCase case_x25519;
  TestCase case_p521;
  TestCase case_x448;
};

struct MessagesTestVectors
{
  static const std::string file_name;

  MessagesTestVectors()
    : user_init_key_all()
    , case_p256_p256(CipherSuite::P256_SHA256_AES128GCM)
    , case_x25519_ed25519(CipherSuite::X25519_SHA256_AES128GCM)
    , case_p521_p521(CipherSuite::P521_SHA512_AES256GCM)
    , case_x448_ed448(CipherSuite::X448_SHA512_AES256GCM)
  {}

  struct TestCase
  {
    CipherSuite cipher_suite;
    UserInitKey user_init_key;
    WelcomeInfo welcome_info;
    Welcome welcome;
    Handshake add;
    Handshake update;
    Handshake remove;

    TestCase(CipherSuite suite)
      : cipher_suite(suite)
      , user_init_key()
      , welcome_info(suite)
      , welcome()
      , add(suite)
      , update(suite)
      , remove(suite)
    {}
  };

  UserInitKey user_init_key_all;

  TestCase case_p256_p256;
  TestCase case_x25519_ed25519;
  TestCase case_p521_p521;
  TestCase case_x448_ed448;
};

struct TestVectors
{
  TreeMathTestVectors tree_math;
  CryptoTestVectors crypto;
  MessagesTestVectors messages;

  static const TestVectors& get();
  void dump();

private:
  static bool _initialized;
  static TestVectors _vectors;
};
