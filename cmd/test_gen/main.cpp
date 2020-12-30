#include <mls/crypto.h>

#include "test_vectors.h"

#include <hpke/random.h>

#include <fstream>
#include <iostream>

static CryptoTestVectors
generate_crypto()
{
  CryptoTestVectors tv;

  std::vector<CipherSuite> suites{
    { CipherSuite::ID::P256_AES128GCM_SHA256_P256 },
    { CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519 },
  };

  tv.kdf_extract_salt = { 0, 1, 2, 3 };
  tv.kdf_extract_ikm = { 4, 5, 6, 7 };

  tv.derive_key_pair_seed = { 0, 1, 2, 3 };

  tv.hpke_aad = bytes(128, 0xB1);
  tv.hpke_plaintext = bytes(128, 0xB2);

  // Construct a test case for each suite
  for (auto suite : suites) {
    // kdf-Extract
    auto kdf_extract_out =
      suite.hpke().kdf.extract(tv.kdf_extract_salt, tv.kdf_extract_ikm);

    // Derive-Key-Pair
    auto priv = HPKEPrivateKey::derive(suite, tv.derive_key_pair_seed);
    auto derive_key_pair_pub = priv.public_key;

    // HPKE
    auto hpke_out =
      derive_key_pair_pub.encrypt(suite, tv.hpke_aad, tv.hpke_plaintext);

    tv.cases.push_back(
      { suite, kdf_extract_out, derive_key_pair_pub, hpke_out });
  }

  return tv;
}

static TreeKEMTestVectors
generate_treekem()
{
  TreeKEMTestVectors tv;

  std::vector<CipherSuite> suites{
    { CipherSuite::ID::P256_AES128GCM_SHA256_P256 },
    { CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519 },
  };

  size_t n_leaves = 10;
  tv.init_secrets.resize(n_leaves);
  tv.leaf_secrets.resize(n_leaves);
  for (size_t i = 0; i < n_leaves; ++i) {
    tv.init_secrets[i].data = hpke::random_bytes(32);
    tv.leaf_secrets[i].data = hpke::random_bytes(32);
  }

  for (size_t i = 0; i < suites.size(); ++i) {
    auto suite = suites[i];

    TreeKEMTestVectors::TestCase tc;
    tc.cipher_suite = suite;

    TreeKEMPublicKey tree{ suite };

    // Add the leaves
    for (uint32_t j = 0; j < n_leaves; ++j) {
      auto context = bytes{ uint8_t(i), uint8_t(j) };
      auto init_priv = HPKEPrivateKey::derive(suite, tv.init_secrets[j].data);
      auto sig_priv =
        SignaturePrivateKey::derive(suite, tv.init_secrets[j].data);
      auto cred = Credential::basic(context, sig_priv.public_key);
      auto kp =
        KeyPackage{ suite, init_priv.public_key, cred, sig_priv, std::nullopt };

      auto index = tree.add_leaf(kp);
      tree.encap(
        index, context, tv.leaf_secrets[j].data, sig_priv, std::nullopt);

      tc.trees.push_back(tree);
    }

    // Blank out even-numbered leaves
    for (uint32_t j = 0; j < n_leaves; j += 2) {
      tree.blank_path(LeafIndex{ j });
      tc.trees.push_back(tree);
    }

    tv.cases.push_back(tc);
  }

  return tv;
}

static MessagesTestVectors
generate_messages()
{
  MessagesTestVectors tv;

  std::vector<CipherSuite> suites{
    { CipherSuite::ID::P256_AES128GCM_SHA256_P256 },
    { CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519 },
  };

  // Set the inputs
  tv.epoch = 0xA0A1A2A3;
  tv.sender = Sender{ SenderType::member, 0xB0B1B2B3 };
  tv.removed = LeafIndex{ 0xC0C1C2C3 };
  tv.user_id = bytes(16, 0xD1);
  tv.group_id = bytes(16, 0xD2);
  tv.key_package_id = bytes(16, 0xD3);
  tv.dh_seed = bytes(32, 0xD4);
  tv.sig_seed = bytes(32, 0xD5);
  tv.random = bytes(32, 0xD6);

  // Construct a test case for each suite
  for (auto suite : suites) {
    // Miscellaneous data items we need to construct messages
    auto dh_priv = HPKEPrivateKey::derive(suite, tv.dh_seed);
    auto dh_key = dh_priv.public_key;
    auto sig_priv = SignaturePrivateKey::derive(suite, tv.sig_seed);
    auto sig_key = sig_priv.public_key;
    auto cred = Credential::basic(tv.user_id, sig_priv.public_key);
    auto fake_hpke_ciphertext = HPKECiphertext{ tv.random, tv.random };

    auto tree = TestTreeKEMPublicKey{
      suite,
      { tv.random, tv.random, tv.random, tv.random },
    };
    tree.blank_path(LeafIndex{ 2 });

    // Construct KeyPackage
    auto ext_list =
      ExtensionList{ { { ExtensionType::lifetime, bytes(8, 0) } } };
    auto key_package =
      KeyPackage{ suite, dh_priv.public_key, cred, sig_priv, { { ext_list } } };
    key_package.signature = tv.random;

    // Construct UpdatePath
    auto update_path =
      UpdatePath{ key_package,
                  {
                    { dh_key, { fake_hpke_ciphertext, fake_hpke_ciphertext } },
                    { dh_key, { fake_hpke_ciphertext, fake_hpke_ciphertext } },
                  } };

    // Construct Welcome
    auto group_info = GroupInfo{ tv.group_id, tv.epoch, tree,     tv.random,
                                 tv.random,   ext_list, tv.random };
    group_info.signer_index = LeafIndex(tv.sender.sender);
    group_info.signature = tv.random;

    auto group_secrets = GroupSecrets{ tv.random, std::nullopt };
    auto encrypted_group_secrets =
      EncryptedGroupSecrets{ tv.random,
                             HPKECiphertext{ tv.random, tv.random } };

    Welcome welcome;
    welcome.version = ProtocolVersion::mls10;
    welcome.cipher_suite = suite;
    welcome.secrets = { encrypted_group_secrets, encrypted_group_secrets };
    welcome.encrypted_group_info = tv.random;

    // Construct Proposals
    auto add_prop = Proposal{ Add{ key_package } };
    auto add_hs = MLSPlaintext{ tv.group_id, tv.epoch, tv.sender, add_prop };
    add_hs.signature = tv.random;
    add_hs.membership_tag = { tv.random };

    auto update_prop = Proposal{ Update{ key_package } };
    auto update_hs =
      MLSPlaintext{ tv.group_id, tv.epoch, tv.sender, update_prop };
    update_hs.signature = tv.random;
    update_hs.membership_tag = { tv.random };

    auto remove_prop = Proposal{ Remove{ LeafIndex(tv.sender.sender) } };
    auto remove_hs =
      MLSPlaintext{ tv.group_id, tv.epoch, tv.sender, remove_prop };
    remove_hs.signature = tv.random;
    remove_hs.membership_tag = { tv.random };

    // Construct Commit
    auto commit = Commit{
      { { tv.random }, { tv.random } },
      update_path,
    };
    auto commit_hs = MLSPlaintext{ tv.group_id, tv.epoch, tv.sender, commit };
    commit_hs.signature = tv.random;
    commit_hs.confirmation_tag = { tv.random };
    commit_hs.membership_tag = { tv.random };

    // Construct an MLSCiphertext
    auto ciphertext = MLSCiphertext{
      tv.group_id, tv.epoch,  ContentType::application,
      tv.random,   tv.random, tv.random,
    };

    tv.cases.push_back({ suite,
                         tls::marshal(key_package),
                         tls::marshal(update_path),
                         tls::marshal(group_info),
                         tls::marshal(group_secrets),
                         tls::marshal(encrypted_group_secrets),
                         tls::marshal(welcome),
                         tls::marshal(add_hs),
                         tls::marshal(update_hs),
                         tls::marshal(remove_hs),
                         tls::marshal(commit_hs),
                         tls::marshal(ciphertext) });
  }

  return tv;
}

template<typename T>
void
write_test_vectors(const T& vectors)
{
  auto marshaled = tls::marshal(vectors);

  std::ofstream file(T::file_name, std::ios::out | std::ios::binary);
  if (!file) {
    throw std::invalid_argument("Could not create ofstream for: " +
                                T::file_name);
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  const auto* data = reinterpret_cast<const char*>(marshaled.data());
  file.write(data, marshaled.size());
}

template<typename T>
void
verify_equal_marshaled(const T& lhs, const T& rhs)
{
  auto lhsb = tls::marshal(lhs);
  auto rhsb = tls::marshal(rhs);
  if (lhsb != rhsb) {
    throw std::runtime_error("difference in marshaled values");
  }
}

template<typename F>
void
verify_reproducible(const F& generator)
{
  auto v0 = generator();
  auto v1 = generator();
  verify_equal_marshaled(v0, v1);
}

int
main() // NOLINT(bugprone-exception-escape)
{
  auto crypto = generate_crypto();
  write_test_vectors(crypto);

  auto tree = generate_treekem();
  write_test_vectors(tree);

  auto messages = generate_messages();
  write_test_vectors(messages);

  // Verify that the test vectors load
  try {
    TestLoader<CryptoTestVectors>::get();
    TestLoader<TreeKEMTestVectors>::get();
    TestLoader<MessagesTestVectors>::get();
  } catch (...) {
    std::cerr << "Error: Generated test vectors failed to load" << std::endl;
  }

  return 0;
}
