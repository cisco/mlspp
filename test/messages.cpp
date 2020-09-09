#include "test_vectors.h"
#include <doctest/doctest.h>
#include <mls/messages.h>
#include <tls/tls_syntax.h>

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
    REQUIRE(vector == marshaled);
  }

  auto unmarshaled = tls::get<T>(vector, args...);
  REQUIRE(constructed == unmarshaled);
  REQUIRE(tls::marshal(unmarshaled) == vector);
}

TEST_CASE("Extensions")
{
  auto sv0 = SupportedVersionsExtension{ { ProtocolVersion::mls10 } };
  auto sc0 = SupportedCipherSuitesExtension{ {
    CipherSuite::ID::P256_AES128GCM_SHA256_P256,
    CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519,
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

  REQUIRE(sv0 == sv1);
  REQUIRE(sc0 == sc1);
  REQUIRE(lt0 == lt1);
  REQUIRE(kid0 == kid1);
  REQUIRE(ph0 == ph1);
}

TEST_CASE("Messages Interop")
{
  const auto& tv = TestLoader<MessagesTestVectors>::get();

  for (const auto& tc : tv.cases) {
    auto reproducible = deterministic_signature_scheme(tc.cipher_suite);

    // Miscellaneous data items we need to construct messages
    auto dh_priv = HPKEPrivateKey::derive(tc.cipher_suite, tv.dh_seed);
    auto dh_key = dh_priv.public_key;
    auto sig_priv = SignaturePrivateKey::derive(tc.cipher_suite, tv.sig_seed);
    auto sig_key = sig_priv.public_key;
    auto cred = Credential::basic(tv.user_id, sig_priv.public_key);
    auto fake_hpke_ciphertext = HPKECiphertext{ tv.random, tv.random };

    auto tree =
      TestTreeKEMPublicKey{ tc.cipher_suite,
                            { tv.random, tv.random, tv.random, tv.random } };
    tree.blank_path(LeafIndex{ 2 });

    // KeyPackage
    auto ext_list =
      ExtensionList{ { { ExtensionType::lifetime, bytes(8, 0) } } };
    auto key_package =
      KeyPackage{ tc.cipher_suite, dh_priv.public_key, cred, sig_priv };
    key_package.extensions = ext_list;
    key_package.signature = tv.random;
    tls_round_trip(tc.key_package, key_package, reproducible);

    // DirectPath
    auto direct_path =
      DirectPath{ key_package,
                  {
                    { dh_key, { fake_hpke_ciphertext, fake_hpke_ciphertext } },
                    { dh_key, { fake_hpke_ciphertext, fake_hpke_ciphertext } },
                  } };
    tls_round_trip(tc.direct_path, direct_path, reproducible);

    // GroupInfo, GroupSecrets, EncryptedGroupSecrets, and Welcome
    auto group_info = GroupInfo{ tv.group_id, tv.epoch, tree,     tv.random,
                                 tv.random,   ext_list, tv.random };
    group_info.signer_index = LeafIndex(tv.sender.sender);
    group_info.signature = tv.random;
    tls_round_trip(tc.group_info, group_info, true, tc.cipher_suite);

    auto group_secrets = GroupSecrets{ tv.random, std::nullopt };
    tls_round_trip(tc.group_secrets, group_secrets, true);

    auto encrypted_group_secrets =
      EncryptedGroupSecrets{ tv.random,
                             HPKECiphertext{ tv.random, tv.random } };
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
      tv.group_id, tv.epoch,  ContentType::application, tv.random, tv.random,
      tv.random,   tv.random,
    };
    tls_round_trip(tc.ciphertext, ciphertext, true);
  }
}
