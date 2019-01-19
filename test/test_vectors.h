#include "common.h"
#include "messages.h"
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

  struct CipherSuiteCase
  {
    CipherSuite cipher_suite;
    UserInitKey user_init_key;
    WelcomeInfo welcome_info;
    Welcome welcome;
    Handshake add;
    Handshake update;
    Handshake remove;

    CipherSuiteCase(CipherSuite suite)
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

  CipherSuiteCase case_p256_p256;
  CipherSuiteCase case_x25519_ed25519;
  CipherSuiteCase case_p521_p521;
  CipherSuiteCase case_x448_ed448;
};

struct TestVectors
{
  TreeMathTestVectors tree_math;
  MessagesTestVectors messages;

  static const TestVectors& get();
  void dump();

private:
  static bool _initialized;
  static TestVectors _vectors;
};
