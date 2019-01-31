#include "common.h"
#include "messages.h"
#include "session.h"
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

tls::istream&
operator>>(tls::istream& str, TreeMathTestVectors& tv);
tls::ostream&
operator<<(tls::ostream& str, const TreeMathTestVectors& tv);

/////

struct CryptoTestVectors
{
  static const std::string file_name;

  tls::opaque<1> hkdf_extract_salt;
  tls::opaque<1> hkdf_extract_ikm;

  tls::opaque<1> derive_secret_secret;
  tls::opaque<1> derive_secret_label;
  uint32_t derive_secret_length;

  tls::opaque<1> derive_key_pair_seed;

  tls::opaque<1> ecies_plaintext;

  struct TestCase
  {
    // HKDF-Extract
    tls::opaque<1> hkdf_extract_out;

    // Derive-Secret
    GroupState derive_secret_state;
    tls::opaque<1> derive_secret_out;

    // Derive-Key-Pair
    DHPublicKey derive_key_pair_pub;

    // ECIES
    ECIESCiphertext ecies_out;

    TestCase(CipherSuite suite)
      : derive_secret_state(suite)
      , derive_key_pair_pub(suite)
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

tls::istream&
operator>>(tls::istream& str, CryptoTestVectors& tv);
tls::ostream&
operator<<(tls::ostream& str, const CryptoTestVectors& tv);

/////

struct MessagesTestVectors
{
  static const std::string file_name;

  struct TestCase
  {
    CipherSuite cipher_suite;
    SignatureScheme sig_scheme;

    tls::opaque<4> user_init_key;
    tls::opaque<4> welcome_info;
    tls::opaque<4> welcome;
    tls::opaque<4> add;
    tls::opaque<4> update;
    tls::opaque<4> remove;
  };

  uint32_t epoch;
  uint32_t signer_index;
  uint32_t removed;
  tls::opaque<1> user_id;
  tls::opaque<1> group_id;
  tls::opaque<1> uik_id;
  tls::opaque<1> dh_seed;
  tls::opaque<1> sig_seed;
  tls::opaque<1> random;

  SignatureScheme uik_all_scheme;
  tls::opaque<4> user_init_key_all;

  TestCase case_p256_p256;
  TestCase case_x25519_ed25519;
  TestCase case_p521_p521;
  TestCase case_x448_ed448;
};

tls::istream&
operator>>(tls::istream& str, MessagesTestVectors::TestCase& tv);
tls::ostream&
operator<<(tls::ostream& str, const MessagesTestVectors::TestCase& tc);

tls::istream&
operator>>(tls::istream& str, MessagesTestVectors& tv);
tls::ostream&
operator<<(tls::ostream& str, const MessagesTestVectors& tv);

/////

// Splitting the test data from the file definition here allows us
// to have a consistent struct for different scenarios that live in
// different files.
struct SessionTestVectors
{
  struct Epoch
  {
    tls::opaque<4> welcome; // may be zero-size
    tls::opaque<4> handshake;

    epoch_t epoch;
    tls::opaque<1> epoch_secret;
    tls::opaque<1> application_secret;
    tls::opaque<1> confirmation_key;
    tls::opaque<1> init_secret;

    Epoch() = default;

    Epoch(const bytes& welcome,
          const bytes& handshake,
          const mls::test::TestSession& session)
      : welcome(welcome)
      , handshake(handshake)
      , epoch(session.current_epoch())
      , epoch_secret(session.current_epoch_secret())
      , application_secret(session.current_application_secret())
      , confirmation_key(session.current_confirmation_key())
      , init_secret(session.current_init_secret())
    {}
  };

  struct TestCase
  {
    CipherSuite cipher_suite;
    SignatureScheme sig_scheme;
    tls::vector<Epoch, 4> transcript;
  };

  uint32_t group_size;
  tls::opaque<1> group_id;

  TestCase case_p256_p256;
  TestCase case_x25519_ed25519;
  TestCase case_p521_p521;
  TestCase case_x448_ed448;
};

tls::istream&
operator>>(tls::istream& str, SessionTestVectors& tv);
tls::ostream&
operator<<(tls::ostream& str, const SessionTestVectors& tv);

struct BasicSessionTestVectors : SessionTestVectors
{
  static const std::string file_name;
};

/////

template<typename T>
struct TestLoader
{
  static const T& get();

private:
  static bool _initialized;
  static T _vectors;
};
