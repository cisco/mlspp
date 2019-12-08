#include "messages.h"
#include "test_vectors.h"
#include "tls_syntax.h"
#include <gtest/gtest.h>

using namespace mls;

template<typename T, typename... Tp>
void
tls_round_trip(const bytes& vector,
               T& constructed,
               bool reproducible,
               Tp... args)
{
  auto marshaled = tls::marshal(constructed);

  std::cout << "mar " << marshaled << std::endl;
  std::cout << "vec " << vector << std::endl;

  if (reproducible) {
    ASSERT_EQ(vector, marshaled);
  }

  auto unmarshaled = tls::get<T>(vector, args...);
  ASSERT_EQ(constructed, unmarshaled);
  ASSERT_EQ(tls::marshal(unmarshaled), vector);
}

bool
deterministic_signature_scheme(SignatureScheme scheme)
{
  switch (scheme) {
    case SignatureScheme::P256_SHA256:
      return false;
    case SignatureScheme::P521_SHA512:
      return false;
    case SignatureScheme::Ed25519:
      return true;
    case SignatureScheme::Ed448:
      return true;
  }

  return false;
}

class MessagesTest : public ::testing::Test
{
protected:
  const MessagesTestVectors& tv;

  MessagesTest()
    : tv(TestLoader<MessagesTestVectors>::get())
  {}

  void tls_round_trip_all(const MessagesTestVectors::TestCase& tc,
                          bool reproducible)
  {
    // Miscellaneous data items we need to construct messages
    auto dh_priv = DHPrivateKey::derive(tc.cipher_suite, tv.dh_seed);
    auto dh_key = dh_priv.public_key();
    auto sig_priv = SignaturePrivateKey::derive(tc.sig_scheme, tv.sig_seed);
    auto sig_key = sig_priv.public_key();
    auto cred = Credential::basic(tv.user_id, sig_priv);

    DeterministicHPKE lock;
    auto ratchet_tree =
      TestRatchetTree{ tc.cipher_suite,
                       { tv.random, tv.random, tv.random, tv.random },
                       { cred, cred, cred, cred } };
    ratchet_tree.blank_path(LeafIndex{ 2 }, true);

    DirectPath direct_path(ratchet_tree.cipher_suite());
    bytes dummy;
    std::tie(direct_path, dummy) =
      ratchet_tree.encap(LeafIndex{ 0 }, {}, tv.random);

    // ClientInitKey
    ClientInitKey client_init_key{ dh_priv, cred };
    client_init_key.signature = tv.random;
    tls_round_trip(tc.client_init_key, client_init_key, reproducible);

    // GroupInfo, KeyPackage, EncryptedKeyPackage, and Welcome
    auto group_info =
      GroupInfo{ tv.group_id, tv.epoch,  ratchet_tree, tv.random,
                 tv.random,   tv.random, direct_path,  tv.random };
    group_info.signer_index = tv.signer_index;
    group_info.signature = tv.random;
    tls_round_trip(tc.group_info, group_info, true, tc.cipher_suite);

    auto key_package = KeyPackage{ tv.random };
    tls_round_trip(tc.key_package, key_package, true);

    auto encrypted_key_package =
      EncryptedKeyPackage{ tv.random, dh_key.encrypt({}, tv.random) };
    tls_round_trip(
      tc.encrypted_key_package, encrypted_key_package, true, tc.cipher_suite);

    Welcome welcome;
    welcome.version = ProtocolVersion::mls10;
    welcome.cipher_suite = tc.cipher_suite;
    welcome.key_packages = { encrypted_key_package, encrypted_key_package };
    welcome.encrypted_group_info = tv.random;
    tls_round_trip(tc.welcome, welcome, true);

    // Proposals
    auto add_prop = Proposal{ Add{ client_init_key } };
    auto add_hs =
      MLSPlaintext{ tv.group_id, tv.epoch, tv.signer_index, add_prop };
    add_hs.signature = tv.random;
    tls_round_trip(tc.add_proposal, add_hs, true, tc.cipher_suite);

    auto update_prop = Proposal{ Update{ dh_key } };
    auto update_hs =
      MLSPlaintext{ tv.group_id, tv.epoch, tv.signer_index, update_prop };
    update_hs.signature = tv.random;
    tls_round_trip(tc.update_proposal, update_hs, true, tc.cipher_suite);

    auto remove_prop = Proposal{ Remove{ tv.signer_index } };
    auto remove_hs =
      MLSPlaintext{ tv.group_id, tv.epoch, tv.signer_index, remove_prop };
    remove_hs.signature = tv.random;
    tls_round_trip(tc.remove_proposal, remove_hs, true, tc.cipher_suite);

    // Commit
    auto commit = Commit{
      { tv.random, tv.random },
      { tv.random, tv.random },
      { tv.random, tv.random },
      { tv.random, tv.random },
      direct_path,
    };
    tls_round_trip(tc.commit, commit, true, tc.cipher_suite);

    // MLSCiphertext
    MLSCiphertext ciphertext{
      tv.group_id, tv.epoch,  ContentType::application,
      tv.random,   tv.random, tv.random,
    };
    tls_round_trip(tc.ciphertext, ciphertext, true);
  }
};

TEST_F(MessagesTest, Suite_P256_P256)
{
  tls_round_trip_all(tv.case_p256_p256, false);
}

TEST_F(MessagesTest, Suite_X25519_Ed25519)
{
  tls_round_trip_all(tv.case_x25519_ed25519, true);
}
