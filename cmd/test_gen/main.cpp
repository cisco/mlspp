#include <mls/crypto.h>
#include <mls/tree_math.h>

#include "test_vectors.h"

#include <hpke/random.h>

#include <fstream>
#include <iostream>

static TreeMathTestVectors
generate_tree_math()
{
  TreeMathTestVectors tv;
  tv.n_leaves = LeafCount{ 63 };

  for (uint32_t n = 1; n <= tv.n_leaves.val; ++n) {
    auto w = NodeCount{ LeafCount{ n } };
    auto val = tree_math::root(w);
    tv.root.push_back(val);
  }

  auto w = NodeCount{ tv.n_leaves };
  for (uint32_t x = 0; x < w.val; ++x) {
    auto left = tree_math::left(NodeIndex{ x });
    tv.left.push_back(left);

    auto right = tree_math::right(NodeIndex{ x }, w);
    tv.right.push_back(right);

    auto parent = tree_math::parent(NodeIndex{ x }, w);
    tv.parent.push_back(parent);

    auto sibling = tree_math::sibling(NodeIndex{ x }, w);
    tv.sibling.push_back(sibling);

    auto dirpath = tree_math::dirpath(NodeIndex{ x }, w);
    tv.dirpath.push_back(TreeMathTestVectors::NodeVector{ dirpath });

    auto copath = tree_math::copath(NodeIndex{ x }, w);
    tv.copath.push_back(TreeMathTestVectors::NodeVector{ copath });

    for (uint32_t l = 0; l < tv.n_leaves.val - 1; ++l) {
      auto ancestors = std::vector<NodeIndex>();
      for (uint32_t r = l + 1; r < tv.n_leaves.val; ++r) {
        auto a = tree_math::ancestor(LeafIndex(l), LeafIndex(r));
        ancestors.push_back(a);
      }
      tv.ancestor.emplace_back(TreeMathTestVectors::NodeVector{ ancestors });
    }
  }

  return tv;
}

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
      suite.get().hpke.kdf.extract(tv.kdf_extract_salt, tv.kdf_extract_ikm);

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

static HashRatchetTestVectors
generate_hash_ratchet()
{
  HashRatchetTestVectors tv;

  std::vector<CipherSuite> suites{
    { CipherSuite::ID::P256_AES128GCM_SHA256_P256 },
    { CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519 },
  };

  tv.n_members = 16;
  tv.n_generations = 16;
  tv.base_secret = bytes(32, 0xA0);

  for (auto suite : suites) {
    HashRatchetTestVectors::TestCase tc;
    tc.cipher_suite = suite;
    tc.key_sequences.resize(tv.n_members);

    for (uint32_t j = 0; j < tv.n_members; ++j) {
      HashRatchet ratchet{ suite, NodeIndex{ LeafIndex{ j } }, tv.base_secret };
      for (uint32_t k = 0; k < tv.n_generations; ++k) {
        auto key_nonce = ratchet.get(k);
        tc.key_sequences.at(j).steps.push_back(
          { key_nonce.key, key_nonce.nonce });
      }
    }

    tv.cases.push_back(tc);
  }

  return tv;
}

static KeyScheduleTestVectors
generate_key_schedule()
{
  KeyScheduleTestVectors tv;

  std::vector<CipherSuite> suites{
    { CipherSuite::ID::P256_AES128GCM_SHA256_P256 },
    { CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519 },
  };

  GroupContext base_group_context{
    { 0xA0, 0xA0, 0xA0, 0xA0 }, 0, bytes(32, 0xA1), bytes(32, 0xA2), {},
  };

  tv.n_epochs = 50;
  tv.target_generation = 3;
  tv.base_init_secret = bytes(32, 0xA3);
  tv.base_group_context = tls::marshal(base_group_context);
  tv.ciphertext = bytes(96, 0xA4);

  // Construct a test case for each suite
  for (auto suite : suites) {
    KeyScheduleTestVectors::TestCase tc;
    tc.cipher_suite = suite;

    auto secret_size = suite.secret_size();

    auto group_context = base_group_context;
    auto commit_secret = bytes(secret_size, 0);
    uint32_t min_members = 5;
    uint32_t max_members = 20;
    auto n_members = min_members;

    KeyScheduleEpoch epoch;
    epoch.suite = suite;
    epoch.init_secret = tv.base_init_secret;

    for (size_t j = 0; j < tv.n_epochs; ++j) {
      auto ctx = tls::marshal(group_context);
      epoch = epoch.next(commit_secret, {}, ctx, LeafCount{ n_members });

      auto handshake_keys = std::vector<KeyScheduleTestVectors::KeyAndNonce>();
      auto application_keys =
        std::vector<KeyScheduleTestVectors::KeyAndNonce>();
      for (LeafIndex k{ 0 }; k.val < n_members; ++k.val) {
        auto hs = epoch.keys.get(
          GroupKeySource::RatchetType::handshake, k, tv.target_generation);
        handshake_keys.push_back({ hs.key, hs.nonce });

        auto app = epoch.keys.get(
          GroupKeySource::RatchetType::application, k, tv.target_generation);
        application_keys.push_back({ app.key, app.nonce });
      }

      auto [sender_data_key, sender_data_nonce] =
        epoch.sender_data(tv.ciphertext);

      tc.epochs.push_back({
        LeafCount{ n_members },
        commit_secret,
        epoch.epoch_secret,
        epoch.sender_data_secret,
        epoch.encryption_secret,
        epoch.exporter_secret,
        epoch.authentication_secret,
        epoch.external_secret,
        epoch.confirmation_key,
        epoch.membership_key,
        epoch.resumption_secret,
        epoch.init_secret,
        epoch.external_priv.public_key,
        handshake_keys,
        application_keys,
        sender_data_key,
        sender_data_nonce,
      });

      for (auto& val : commit_secret) {
        val += 1;
      }
      group_context.epoch += 1;
      n_members =
        ((n_members - min_members) % (max_members - min_members)) + min_members;
    }

    tv.cases.push_back(tc);
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
  auto tree_math = generate_tree_math();
  write_test_vectors(tree_math);

  auto crypto = generate_crypto();
  write_test_vectors(crypto);

  auto hash_ratchet = generate_hash_ratchet();
  write_test_vectors(hash_ratchet);

  auto key_schedule = generate_key_schedule();
  write_test_vectors(key_schedule);

  auto tree = generate_treekem();
  write_test_vectors(tree);

  auto messages = generate_messages();
  write_test_vectors(messages);

  // Verify that the test vectors are reproducible (to the extent
  // possible)
  verify_reproducible(generate_tree_math);
  verify_reproducible(generate_hash_ratchet);
  verify_reproducible(generate_key_schedule);

  // Verify that the test vectors load
  try {
    TestLoader<TreeMathTestVectors>::get();
    TestLoader<CryptoTestVectors>::get();
    TestLoader<HashRatchetTestVectors>::get();
    TestLoader<KeyScheduleTestVectors>::get();
    TestLoader<TreeKEMTestVectors>::get();
    TestLoader<MessagesTestVectors>::get();
  } catch (...) {
    std::cerr << "Error: Generated test vectors failed to load" << std::endl;
  }

  return 0;
}
