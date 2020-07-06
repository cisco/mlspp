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
  if (reproducible) {
    std::cout << "vec " << vector << std::endl;
    std::cout << "mar " << marshaled << std::endl;
    ASSERT_EQ(vector, marshaled);
  }

  auto unmarshaled = tls::get<T>(vector, args...);
  ASSERT_EQ(constructed, unmarshaled);
  ASSERT_EQ(tls::marshal(unmarshaled), vector);
}

class MessagesTest : public ::testing::Test
{
protected:
  const MessagesTestVectors& tv;

  MessagesTest()
    : tv(TestLoader<MessagesTestVectors>::get())
  {}
};

TEST_F(MessagesTest, Extensions)
{
  auto sv0 = SupportedVersionsExtension{ { ProtocolVersion::mls10 } };
  auto sc0 = SupportedCipherSuitesExtension{ {
    CipherSuite::P256_AES128GCM_SHA256_P256,
    CipherSuite::X25519_AES128GCM_SHA256_Ed25519,
  } };
  auto lt0 = LifetimeExtension{ 0xA0A0A0A0A0A0A0A0, 0xB0B0B0B0B0B0B0B0 };
  auto kid0 = KeyIDExtension{ { 0, 1, 2, 3 } };
  auto ph0 = ParentHashExtension{ { 4, 5, 6, 7 } };

  ExtensionList exts;
  exts.add(sv0);
  exts.add(sc0);
  exts.add(lt0);
  exts.add(kid0);
  exts.add(ph0);

  auto sv1 = exts.find<SupportedVersionsExtension>();
  auto sc1 = exts.find<SupportedCipherSuitesExtension>();
  auto lt1 = exts.find<LifetimeExtension>();
  auto kid1 = exts.find<KeyIDExtension>();
  auto ph1 = exts.find<ParentHashExtension>();

  ASSERT_EQ(sv0, sv1);
  ASSERT_EQ(sc0, sc1);
  ASSERT_EQ(lt0, lt1);
  ASSERT_EQ(kid0, kid1);
  ASSERT_EQ(ph0, ph1);
}

TEST_F(MessagesTest, Interop)
{
  for (const auto& tc : tv.cases) {
    auto reproducible = deterministic_signature_scheme(tc.cipher_suite);

    // Miscellaneous data items we need to construct messages
    auto dh_priv = HPKEPrivateKey::derive(tc.cipher_suite, tv.dh_seed);
    auto dh_key = dh_priv.public_key();
    auto sig_priv = SignaturePrivateKey::derive(tc.cipher_suite, tv.sig_seed);
    auto sig_key = sig_priv.public_key();
    auto cred = Credential::basic(tv.user_id, sig_priv.public_key());

    DeterministicHPKE lock;
    auto tree =
      TestTreeKEMPublicKey{ tc.cipher_suite,
                            { tv.random, tv.random, tv.random, tv.random } };
    tree.blank_path(LeafIndex{ 2 });

    auto [dummy, direct_path] =
      tree.encap(LeafIndex{ 0 }, {}, tv.random, sig_priv, std::nullopt);
    silence_unused(dummy);
    std::get<KeyPackage>(tree.nodes[0].node.value().node).signature = tv.random;
    direct_path.leaf_key_package.signature = tv.random;

    // KeyPackage
    auto ext_list =
      ExtensionList{ { { ExtensionType::lifetime, bytes(8, 0) } } };
    auto key_package =
      KeyPackage{ tc.cipher_suite, dh_priv.public_key(), cred, sig_priv };
    key_package.extensions = ext_list;
    key_package.signature = tv.random;
    tls_round_trip(tc.key_package, key_package, reproducible);

    // GroupInfo, GroupSecrets, EncryptedGroupSecrets, and Welcome
    auto group_info =
      GroupInfo{ tv.group_id, tv.epoch, tree, tv.random, tv.random, ext_list, tv.random };
    group_info.signer_index = LeafIndex(tv.sender.sender);
    group_info.signature = tv.random;
    tls_round_trip(tc.group_info, group_info, true, tc.cipher_suite);

    auto group_secrets = GroupSecrets{ tv.random };
    tls_round_trip(tc.group_secrets, group_secrets, true);

    auto encrypted_group_secrets =
      EncryptedGroupSecrets{ tv.random,
                             dh_key.encrypt(tc.cipher_suite, {}, tv.random) };
    tls_round_trip(tc.encrypted_group_secrets, encrypted_group_secrets, true);

    Welcome welcome;
    welcome.version = ProtocolVersion::mls10;
    welcome.cipher_suite = tc.cipher_suite;
    welcome.secrets = { encrypted_group_secrets, encrypted_group_secrets };
    welcome.encrypted_group_info = tv.random;
    tls_round_trip(tc.welcome, welcome, true);

    // Proposals
    auto add_prop = Proposal{ Add{ key_package } };
    auto add_hs = MLSPlaintext{ tv.group_id, tv.epoch, tv.sender, add_prop };
    add_hs.signature = tv.random;
    tls_round_trip(tc.add_proposal, add_hs, true);

    auto update_prop = Proposal{ Update{ key_package } };
    auto update_hs =
      MLSPlaintext{ tv.group_id, tv.epoch, tv.sender, update_prop };
    update_hs.signature = tv.random;
    tls_round_trip(tc.update_proposal, update_hs, true);

    auto remove_prop = Proposal{ Remove{ LeafIndex(tv.sender.sender) } };
    auto remove_hs =
      MLSPlaintext{ tv.group_id, tv.epoch, tv.sender, remove_prop };
    remove_hs.signature = tv.random;
    tls_round_trip(tc.remove_proposal, remove_hs, true);

    // Commit
    auto commit = Commit{
      { { tv.random }, { tv.random } },
      { { tv.random }, { tv.random } },
      { { tv.random }, { tv.random } },
      direct_path,
    };
    tls_round_trip(tc.commit, commit, true);

    // MLSCiphertext
    MLSCiphertext ciphertext{
      tv.group_id, tv.epoch,  ContentType::application,
      tv.random,   tv.random, tv.random,
    };
    tls_round_trip(tc.ciphertext, ciphertext, true);
  }
}
