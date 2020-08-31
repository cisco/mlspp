#include "mls/crypto.h"
#include "mls/session.h"
#include "mls/tree_math.h"
#include "test_vectors.h"
#include <fstream>
#include <iostream>

TreeMathTestVectors
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

CryptoTestVectors
generate_crypto()
{
  CryptoTestVectors tv;

  std::vector<CipherSuite> suites{
    CipherSuite::P256_AES128GCM_SHA256_P256,
    CipherSuite::X25519_AES128GCM_SHA256_Ed25519,
  };

  tv.hkdf_extract_salt = { 0, 1, 2, 3 };
  tv.hkdf_extract_ikm = { 4, 5, 6, 7 };

  tv.derive_key_pair_seed = { 0, 1, 2, 3 };

  tv.hpke_aad = bytes(128, 0xB1);
  tv.hpke_plaintext = bytes(128, 0xB2);

  // Construct a test case for each suite
  for (auto suite : suites) {
    // HKDF-Extract
    auto hkdf_extract_out =
      hkdf_extract(suite, tv.hkdf_extract_salt, tv.hkdf_extract_ikm);

    // Derive-Key-Pair
    auto priv = HPKEPrivateKey::derive(suite, tv.derive_key_pair_seed);
    auto derive_key_pair_pub = priv.public_key();

    // HPKE
    auto hpke_out =
      derive_key_pair_pub.encrypt(suite, tv.hpke_aad, tv.hpke_plaintext);

    tv.cases.push_back(
      { suite, hkdf_extract_out, derive_key_pair_pub, hpke_out });
  }

  return tv;
}

HashRatchetTestVectors
generate_hash_ratchet()
{
  HashRatchetTestVectors tv;

  std::vector<CipherSuite> suites{
    CipherSuite::P256_AES128GCM_SHA256_P256,
    CipherSuite::X25519_AES128GCM_SHA256_Ed25519,
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

KeyScheduleTestVectors
generate_key_schedule()
{
  KeyScheduleTestVectors tv;

  std::vector<CipherSuite> suites{
    CipherSuite::P256_AES128GCM_SHA256_P256,
    CipherSuite::X25519_AES128GCM_SHA256_Ed25519,
  };

  GroupContext base_group_context{
    { 0xA0, 0xA0, 0xA0, 0xA0 },
    0,
    bytes(32, 0xA1),
    bytes(32, 0xA2),
  };

  tv.n_epochs = 50;
  tv.target_generation = 3;
  tv.base_init_secret = bytes(32, 0xA3);
  tv.base_group_context = tls::marshal(base_group_context);

  // Construct a test case for each suite
  for (auto suite : suites) {
    KeyScheduleTestVectors::TestCase tc;
    tc.cipher_suite = suite;

    auto secret_size = Digest(suite).output_size();

    auto group_context = base_group_context;
    auto update_secret = bytes(secret_size, 0);
    uint32_t min_members = 5;
    uint32_t max_members = 20;
    auto n_members = min_members;

    KeyScheduleEpoch epoch;
    epoch.suite = suite;
    epoch.init_secret = tv.base_init_secret;

    for (size_t j = 0; j < tv.n_epochs; ++j) {
      auto ctx = tls::marshal(group_context);
      epoch = epoch.next(LeafCount{ n_members }, update_secret, ctx);

      auto handshake_keys = std::vector<KeyScheduleTestVectors::KeyAndNonce>();
      auto application_keys =
        std::vector<KeyScheduleTestVectors::KeyAndNonce>();
      for (LeafIndex k{ 0 }; k.val < n_members; ++k.val) {
        auto hs = epoch.handshake_keys.get(k, tv.target_generation);
        handshake_keys.push_back({ hs.key, hs.nonce });

        auto app = epoch.application_keys.get(k, tv.target_generation);
        application_keys.push_back({ app.key, app.nonce });
      }

      tc.epochs.push_back({
        LeafCount{ n_members },
        update_secret,
        epoch.epoch_secret,
        epoch.sender_data_secret,
        epoch.sender_data_key,
        epoch.handshake_secret,
        handshake_keys,
        epoch.application_secret,
        application_keys,
        epoch.confirmation_key,
        epoch.init_secret,
      });

      for (auto& val : update_secret) {
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

TreeKEMTestVectors
generate_treekem()
{
  TreeKEMTestVectors tv;

  std::vector<CipherSuite> suites{
    CipherSuite::P256_AES128GCM_SHA256_P256,
    CipherSuite::X25519_AES128GCM_SHA256_Ed25519,
  };

  size_t n_leaves = 10;
  tv.init_secrets.resize(n_leaves);
  tv.leaf_secrets.resize(n_leaves);
  for (size_t i = 0; i < n_leaves; ++i) {
    tv.init_secrets[i].data = random_bytes(32);
    tv.leaf_secrets[i].data = random_bytes(32);
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
      auto cred = Credential::basic(context, sig_priv.public_key());
      auto kp = KeyPackage{ suite, init_priv.public_key(), cred, sig_priv };

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

MessagesTestVectors
generate_messages()
{
  MessagesTestVectors tv;

  std::vector<CipherSuite> suites{
    CipherSuite::P256_AES128GCM_SHA256_P256,
    CipherSuite::X25519_AES128GCM_SHA256_Ed25519,
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
  DeterministicHPKE lock;
  for (size_t i = 0; i < suites.size(); ++i) {
    auto suite = suites[i];

    // Miscellaneous data items we need to construct messages
    auto dh_priv = HPKEPrivateKey::derive(suite, tv.dh_seed);
    auto dh_key = dh_priv.public_key();
    auto sig_priv = SignaturePrivateKey::derive(suite, tv.sig_seed);
    auto sig_key = sig_priv.public_key();
    auto cred = Credential::basic(tv.user_id, sig_priv.public_key());

    auto tree = TestTreeKEMPublicKey{
      suite,
      { tv.random, tv.random, tv.random, tv.random },
    };
    tree.blank_path(LeafIndex{ 2 });

    auto [dummy, direct_path] =
      tree.encap(LeafIndex{ 0 }, {}, tv.random, sig_priv, std::nullopt);
    silence_unused(dummy);
    std::get<KeyPackage>(tree.nodes[0].node.value().node).signature = tv.random;
    direct_path.leaf_key_package.signature = tv.random;

    // Construct CIK
    auto ext_list =
      ExtensionList{ { { ExtensionType::lifetime, bytes(8, 0) } } };
    auto key_package =
      KeyPackage{ suite, dh_priv.public_key(), cred, sig_priv };
    key_package.extensions = ext_list;
    key_package.signature = tv.random;

    // Construct Welcome
    auto group_info = GroupInfo{ tv.group_id, tv.epoch, tree,     tv.random,
                                 tv.random,   ext_list, tv.random };
    group_info.signer_index = LeafIndex(tv.sender.sender);
    group_info.signature = tv.random;

    auto group_secrets = GroupSecrets{ tv.random };
    auto encrypted_group_secrets =
      EncryptedGroupSecrets{ tv.random, dh_key.encrypt(suite, {}, tv.random) };

    Welcome welcome;
    welcome.version = ProtocolVersion::mls10;
    welcome.cipher_suite = suite;
    welcome.secrets = { encrypted_group_secrets, encrypted_group_secrets };
    welcome.encrypted_group_info = tv.random;

    // Construct Proposals
    auto add_prop = Proposal{ Add{ key_package } };
    auto add_hs = MLSPlaintext{ tv.group_id, tv.epoch, tv.sender, add_prop };
    add_hs.signature = tv.random;

    auto update_prop = Proposal{ Update{ key_package } };
    auto update_hs =
      MLSPlaintext{ tv.group_id, tv.epoch, tv.sender, update_prop };
    update_hs.signature = tv.random;

    auto remove_prop = Proposal{ Remove{ LeafIndex(tv.sender.sender) } };
    auto remove_hs =
      MLSPlaintext{ tv.group_id, tv.epoch, tv.sender, remove_prop };
    remove_hs.signature = tv.random;

    // Construct Commit
    auto commit = Commit{
      { { tv.random }, { tv.random } },
      { { tv.random }, { tv.random } },
      { { tv.random }, { tv.random } },
      direct_path,
    };

    // Construct an MLSCiphertext
    auto ciphertext = MLSCiphertext{
      tv.group_id, tv.epoch,  ContentType::application,
      tv.random,   tv.random, tv.random,
    };

    tv.cases.push_back({ suite,
                         tls::marshal(key_package),
                         tls::marshal(group_info),
                         tls::marshal(group_secrets),
                         tls::marshal(encrypted_group_secrets),
                         tls::marshal(welcome),
                         tls::marshal(add_hs),
                         tls::marshal(update_hs),
                         tls::marshal(remove_hs),
                         tls::marshal(commit),
                         tls::marshal(ciphertext) });
  }

  return tv;
}

bytes
pseudo_random(CipherSuite suite, int seq)
{
  auto seq_data = tls::marshal(uint32_t(seq));
  return Digest(suite).write(seq_data).digest();
}

BasicSessionTestVectors
generate_basic_session()
{
  BasicSessionTestVectors tv;

  std::vector<CipherSuite> suites{
    CipherSuite::P256_AES128GCM_SHA256_P256,
    CipherSuite::P256_AES128GCM_SHA256_P256,
    CipherSuite::X25519_AES128GCM_SHA256_Ed25519,
    CipherSuite::X25519_AES128GCM_SHA256_Ed25519,
  };

  std::vector<bool> encrypts{ false, true, false, true };

  tv.group_size = 5;
  tv.group_id = bytes(16, 0xA0);

  DeterministicHPKE lock;
  for (size_t i = 0; i < suites.size(); ++i) {
    auto suite = suites[i];
    auto encrypt = encrypts[i];
    const bytes key_package_id = { 0, 1, 2, 3 };
    const bytes group_init_secret = { 4, 5, 6, 7 };

    std::vector<SessionTestVectors::Epoch> transcript;

    // Initialize empty sessions
    std::vector<Session::InitInfo> init_infos;
    std::vector<KeyPackage> key_packages;
    std::vector<TestSession> sessions;
    auto ciphersuites = std::vector<CipherSuite>{ suite };
    for (size_t j = 0; j < tv.group_size; ++j) {
      auto init_secret = bytes{ uint8_t(j), 0 };
      auto identity_priv = SignaturePrivateKey::derive(suite, init_secret);
      auto cred = Credential::basic(init_secret, identity_priv.public_key());
      auto init = HPKEPrivateKey::derive(suite, init_secret);
      auto kp = KeyPackage{ suite, init.public_key(), cred, identity_priv };
      auto info = Session::InitInfo{ init_secret, identity_priv, kp };
      key_packages.push_back(kp);
      init_infos.emplace_back(info);
    }

    // Add everyone
    for (size_t j = 1; j < tv.group_size; ++j) {
      auto commit_secret = pseudo_random(suite, transcript.size());

      Welcome welcome;
      bytes add;
      if (j == 1) {
        auto [session, welcome_new] = Session::start(
          tv.group_id, { init_infos[0] }, { key_packages[1] }, commit_secret);
        session.encrypt_handshake(encrypt);

        sessions.push_back(session);
        welcome = welcome_new;
      } else {
        std::tie(welcome, add) =
          sessions[j - 1].add(commit_secret, key_packages[j]);
        for (size_t k = 0; k < j; ++k) {
          sessions[k].handle(add);
        }
      }

      auto joiner = Session::join({ init_infos[j] }, welcome);
      joiner.encrypt_handshake(encrypt);
      sessions.push_back(joiner);

      transcript.emplace_back(welcome, add, commit_secret, sessions[0]);
    }

    // Update everyone (L->R)
    for (size_t j = 0; j < tv.group_size; ++j) {
      auto commit_secret = pseudo_random(suite, transcript.size());
      auto update = sessions[j].update(commit_secret);
      for (auto& session : sessions) {
        session.handle(update);
      }

      transcript.emplace_back(std::nullopt, update, commit_secret, sessions[0]);
    }

    // Remove everyone (R->L)
    for (int j = tv.group_size - 2; j >= 0; --j) {
      auto commit_secret = pseudo_random(suite, transcript.size());
      auto remove = sessions[j].remove(commit_secret, j + 1);
      for (int k = 0; k <= j; ++k) {
        sessions[k].handle(remove);
      }

      for (int k = 0; k <= j; ++k) {
        if (!(sessions[k] == sessions[0])) {
          throw std::runtime_error("bad session during remove");
        }
      }

      transcript.emplace_back(std::nullopt, remove, commit_secret, sessions[0]);
    }

    // Construct the test case
    tv.cases.push_back({ suite, encrypt, key_packages, transcript });
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

  auto data = reinterpret_cast<const char*>(marshaled.data());
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

template<typename F>
void
verify_session_repro(const F& generator)
{
  auto v0 = generator();
  auto v1 = generator();

  for (size_t i = 0; i < v0.cases.size(); ++i) {
    // Randomized signatures break reproducibility
    if (!deterministic_signature_scheme(v0.cases[i].cipher_suite)) {
      continue;
    }

    // Encrypted handshakes break reproducibility (because of random sender data
    // nonces)
    if (v0.cases[i].encrypt) {
      continue;
    }

    verify_equal_marshaled(v0.cases[i], v1.cases[i]);
  }

  // TODO(rlb@ipv.sx): Verify that the parts of the non-EdDSA cases
  // that should reproduce actually do.
}

int
main()
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

  auto basic_session = generate_basic_session();
  write_test_vectors(basic_session);

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
    TestLoader<BasicSessionTestVectors>::get();
  } catch (...) {
    std::cerr << "Error: Generated test vectors failed to load" << std::endl;
  }

  return 0;
}
