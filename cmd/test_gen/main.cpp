#include "crypto.h"
#include "session.h"
#include "test_vectors.h"
#include "tree_math.h"
#include <fstream>
#include <iostream>

TreeMathTestVectors
generate_tree_math()
{
  TreeMathTestVectors tv;
  tv.n_leaves = LeafCount{ 255 };

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
  }

  return tv;
}

CryptoTestVectors
generate_crypto()
{
  CryptoTestVectors tv;

  std::vector<CipherSuite> suites{
    CipherSuite::P256_SHA256_AES128GCM,
    CipherSuite::X25519_SHA256_AES128GCM,
  };

  std::vector<CryptoTestVectors::TestCase*> cases{
    &tv.case_p256,
    &tv.case_x25519,
  };

  tv.hkdf_extract_salt = { 0, 1, 2, 3 };
  tv.hkdf_extract_ikm = { 4, 5, 6, 7 };

  tv.derive_key_pair_seed = { 0, 1, 2, 3 };

  tv.hpke_aad = bytes(128, 0xB1);
  tv.hpke_plaintext = bytes(128, 0xB2);

  // Construct a test case for each suite
  for (size_t i = 0; i < suites.size(); ++i) {
    auto suite = suites[i];
    auto test_case = cases[i];

    // HKDF-Extract
    test_case->hkdf_extract_out =
      hkdf_extract(suite, tv.hkdf_extract_salt, tv.hkdf_extract_ikm);

    // Derive-Key-Pair
    auto priv = HPKEPrivateKey::derive(suite, tv.derive_key_pair_seed);
    auto pub = priv.public_key();
    test_case->derive_key_pair_pub = pub;

    // HPKE
    DeterministicHPKE lock;
    test_case->hpke_out = pub.encrypt(tv.hpke_aad, tv.hpke_plaintext);
  }

  return tv;
}

HashRatchetTestVectors
generate_hash_ratchet()
{
  HashRatchetTestVectors tv;

  std::vector<CipherSuite> suites{
    CipherSuite::P256_SHA256_AES128GCM,
    CipherSuite::X25519_SHA256_AES128GCM,
  };

  std::vector<HashRatchetTestVectors::TestCase*> cases{
    &tv.case_p256,
    &tv.case_x25519,
  };

  tv.n_members = 16;
  tv.n_generations = 16;
  tv.base_secret = bytes(32, 0xA0);

  for (size_t i = 0; i < suites.size(); ++i) {
    auto suite = suites[i];
    auto test_case = cases[i];

    for (uint32_t j = 0; j < tv.n_members; ++j) {
      test_case->emplace_back();

      HashRatchet ratchet{ suite, NodeIndex{ LeafIndex{ j } }, tv.base_secret };
      for (uint32_t k = 0; k < tv.n_generations; ++k) {
        auto key_nonce = ratchet.get(k);
        test_case->at(j).push_back({ key_nonce.key, key_nonce.nonce });
      }
    }
  }

  return tv;
}

KeyScheduleTestVectors
generate_key_schedule()
{
  KeyScheduleTestVectors tv;

  std::vector<CipherSuite> suites{
    CipherSuite::P256_SHA256_AES128GCM,
    CipherSuite::X25519_SHA256_AES128GCM,
  };

  std::vector<KeyScheduleTestVectors::TestCase*> cases{
    &tv.case_p256,
    &tv.case_x25519,
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
  for (size_t i = 0; i < suites.size(); ++i) {
    auto suite = suites[i];
    auto test_case = cases[i];
    auto secret_size = Digest(suite).output_size();

    test_case->suite = suite;

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

      auto handshake_keys =
        tls::vector<KeyScheduleTestVectors::KeyAndNonce, 4>();
      auto application_keys =
        tls::vector<KeyScheduleTestVectors::KeyAndNonce, 4>();
      for (LeafIndex k{ 0 }; k.val < n_members; ++k.val) {
        auto hs = epoch.handshake_keys.get(k, tv.target_generation);
        handshake_keys.push_back({ hs.key, hs.nonce });

        auto app = epoch.application_keys.get(k, tv.target_generation);
        application_keys.push_back({ app.key, app.nonce });
      }

      test_case->epochs.push_back({
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
  }

  return tv;
}

TreeTestVectors::TreeCase
tree_to_case(const TestRatchetTree& tree)
{
  auto nodes = tree.nodes();
  TreeTestVectors::TreeCase tc(nodes.size());
  for (size_t i = 0; i < nodes.size(); ++i) {
    tc[i].hash = nodes[i].hash();
    if (nodes[i].has_value()) {
      tc[i].public_key = nodes[i]->public_key().to_bytes();
    }
  }
  return tc;
}

TreeTestVectors
generate_tree()
{
  TreeTestVectors tv;

  std::vector<CipherSuite> suites{
    CipherSuite::P256_SHA256_AES128GCM,
    CipherSuite::X25519_SHA256_AES128GCM,
  };

  std::vector<SignatureScheme> schemes{
    SignatureScheme::P256_SHA256,
    SignatureScheme::Ed25519,
  };

  std::vector<TreeTestVectors::TestCase*> cases{
    &tv.case_p256_p256,
    &tv.case_x25519_ed25519,
  };

  size_t n_leaves = 10;
  tv.leaf_secrets.resize(n_leaves);
  for (size_t i = 0; i < n_leaves; ++i) {
    tv.leaf_secrets[i] = { uint8_t(i) };
  }

  for (size_t i = 0; i < suites.size(); ++i) {
    auto suite = suites[i];
    auto scheme = schemes[i];
    auto test_case = cases[i];

    TestRatchetTree tree{ suite };

    // Add the leaves
    for (uint32_t j = 0; j < n_leaves; ++j) {
      auto id = bytes(1, uint8_t(j));
      auto sig = SignaturePrivateKey::derive(scheme, id);
      auto cred = Credential::basic(id, sig);
      test_case->credentials.push_back(cred);

      auto priv = HPKEPrivateKey::derive(suite, tv.leaf_secrets[j]);
      tree.add_leaf(
        LeafIndex{ j }, priv.public_key(), test_case->credentials[j]);
      tree.encap(LeafIndex{ j }, {}, tv.leaf_secrets[j]);
      test_case->trees.push_back(tree_to_case(tree));
    }

    // Blank out even-numbered leaves
    for (uint32_t j = 0; j < n_leaves; j += 2) {
      tree.blank_path(LeafIndex{ j }, true);
      test_case->trees.push_back(tree_to_case(tree));
    }
  }

  return tv;
}

MessagesTestVectors
generate_messages()
{
  MessagesTestVectors tv;

  std::vector<CipherSuite> suites{
    CipherSuite::P256_SHA256_AES128GCM,
    CipherSuite::X25519_SHA256_AES128GCM,
  };

  std::vector<SignatureScheme> schemes{
    SignatureScheme::P256_SHA256,
    SignatureScheme::Ed25519,
  };

  std::vector<MessagesTestVectors::TestCase*> cases{
    &tv.case_p256_p256,
    &tv.case_x25519_ed25519,
  };

  // Set the inputs
  tv.epoch = 0xA0A1A2A3;
  tv.signer_index = LeafIndex{ 0xB0B1B2B3 };
  tv.removed = LeafIndex{ 0xC0C1C2C3 };
  tv.user_id = bytes(16, 0xD1);
  tv.group_id = bytes(16, 0xD2);
  tv.client_init_key_id = bytes(16, 0xD3);
  tv.dh_seed = bytes(32, 0xD4);
  tv.sig_seed = bytes(32, 0xD5);
  tv.random = bytes(32, 0xD6);

  // Construct a test case for each suite
  DeterministicHPKE lock;
  for (size_t i = 0; i < suites.size(); ++i) {
    auto suite = suites[i];
    auto scheme = schemes[i];

    // Miscellaneous data items we need to construct messages
    auto dh_priv = HPKEPrivateKey::derive(suite, tv.dh_seed);
    auto dh_key = dh_priv.public_key();
    auto sig_priv = SignaturePrivateKey::derive(scheme, tv.sig_seed);
    auto sig_key = sig_priv.public_key();
    auto cred = Credential::basic(tv.user_id, sig_priv);

    auto ratchet_tree =
      TestRatchetTree{ suite,
                       { tv.random, tv.random, tv.random, tv.random },
                       { cred, cred, cred, cred } };
    ratchet_tree.blank_path(LeafIndex{ 2 }, true);

    DirectPath direct_path(ratchet_tree.cipher_suite());
    bytes dummy;
    std::tie(direct_path, dummy) =
      ratchet_tree.encap(LeafIndex{ 0 }, {}, tv.random);

    // Construct CIK
    auto client_init_key = ClientInitKey{ dh_priv, cred };
    client_init_key.signature = tv.random;

    // Construct Welcome
    auto group_info =
      GroupInfo{ tv.group_id, tv.epoch,  ratchet_tree, tv.random,
                 tv.random,   tv.random, direct_path,  tv.random };
    group_info.signer_index = tv.signer_index;
    group_info.signature = tv.random;

    auto key_package = KeyPackage{ tv.random };
    auto encrypted_key_package =
      EncryptedKeyPackage{ tv.random, dh_key.encrypt({}, tv.random) };

    Welcome welcome;
    welcome.version = ProtocolVersion::mls10;
    welcome.cipher_suite = suite;
    welcome.key_packages = { encrypted_key_package, encrypted_key_package };
    welcome.encrypted_group_info = tv.random;

    // Construct Proposals
    auto add_prop = Proposal{ Add{ client_init_key } };
    auto add_hs =
      MLSPlaintext{ tv.group_id, tv.epoch, tv.signer_index, add_prop };
    add_hs.signature = tv.random;

    auto update_prop = Proposal{ Update{ dh_key } };
    auto update_hs =
      MLSPlaintext{ tv.group_id, tv.epoch, tv.signer_index, update_prop };
    update_hs.signature = tv.random;

    auto remove_prop = Proposal{ Remove{ tv.signer_index } };
    auto remove_hs =
      MLSPlaintext{ tv.group_id, tv.epoch, tv.signer_index, remove_prop };
    remove_hs.signature = tv.random;

    // Construct Commit
    auto commit = Commit{
      { tv.random, tv.random },
      { tv.random, tv.random },
      { tv.random, tv.random },
      { tv.random, tv.random },
      direct_path,
    };

    // Construct an MLSCiphertext
    auto ciphertext = MLSCiphertext{
      tv.group_id, tv.epoch,  ContentType::application,
      tv.random,   tv.random, tv.random,
    };

    *cases[i] = {
      suite,
      scheme,
      tls::marshal(client_init_key),
      tls::marshal(group_info),
      tls::marshal(key_package),
      tls::marshal(encrypted_key_package),
      tls::marshal(welcome),
      tls::marshal(add_hs),
      tls::marshal(update_hs),
      tls::marshal(remove_hs),
      tls::marshal(commit),
      tls::marshal(ciphertext),
    };
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
    CipherSuite::P256_SHA256_AES128GCM,
    CipherSuite::P256_SHA256_AES128GCM,
    CipherSuite::X25519_SHA256_AES128GCM,
    CipherSuite::X25519_SHA256_AES128GCM,
  };

  std::vector<SignatureScheme> schemes{
    SignatureScheme::P256_SHA256,
    SignatureScheme::P256_SHA256,
    SignatureScheme::Ed25519,
    SignatureScheme::Ed25519,
  };

  std::vector<bool> encrypts{ false, true, false, true };

  std::vector<SessionTestVectors::TestCase*> cases{
    &tv.case_p256_p256,
    &tv.case_p256_p256_encrypted,
    &tv.case_x25519_ed25519,
    &tv.case_x25519_ed25519_encrypted,
  };

  tv.group_size = 5;
  tv.group_id = bytes(16, 0xA0);

  DeterministicHPKE lock;
  for (size_t i = 0; i < suites.size(); ++i) {
    auto suite = suites[i];
    auto scheme = schemes[i];
    auto encrypt = encrypts[i];
    const bytes client_init_key_id = { 0, 1, 2, 3 };
    const bytes group_init_secret = { 4, 5, 6, 7 };

    std::vector<SessionTestVectors::Epoch> transcript;

    // Initialize empty sessions
    std::vector<ClientInitKey> client_init_keys;
    std::vector<TestSession> sessions;
    auto ciphersuites = std::vector<CipherSuite>{ suite };
    for (size_t j = 0; j < tv.group_size; ++j) {
      auto seed = bytes{ uint8_t(j), 0 };
      auto identity_priv = SignaturePrivateKey::derive(scheme, seed);
      auto cred = Credential::basic(seed, identity_priv);
      auto init = HPKEPrivateKey::derive(suite, seed);
      client_init_keys.emplace_back(init, cred);
    }

    // Add everyone
    for (size_t j = 1; j < tv.group_size; ++j) {
      auto commit_secret = pseudo_random(suite, transcript.size());

      Welcome welcome;
      bytes add;
      if (j == 1) {
        auto [session, welcome_new] = Session::start(tv.group_id,
                                                     { client_init_keys[0] },
                                                     { client_init_keys[1] },
                                                     commit_secret);
        session.encrypt_handshake(encrypt);

        sessions.push_back(session);
        welcome = welcome_new;
      } else {
        std::tie(welcome, add) =
          sessions[j - 1].add(commit_secret, client_init_keys[j]);
        for (size_t k = 0; k < j; ++k) {
          sessions[k].handle(add);
        }
      }

      auto joiner = Session::join({ client_init_keys[j] }, welcome);
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
    *cases[i] = { suite, scheme, encrypt, client_init_keys, transcript };
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

  // Obviously, inputs should repro
  verify_equal_marshaled(v0.group_size, v1.group_size);
  verify_equal_marshaled(v0.group_id, v1.group_id);

  // EdDSA-based cases should repro
  verify_equal_marshaled(v0.case_x25519_ed25519, v1.case_x25519_ed25519);

  // TODO(rlb@ipv.sx): Verify that the parts of the non-EdDSA cases
  // that should reproduce actually do.
}

int
main()
{
  TreeMathTestVectors tree_math = generate_tree_math();
  write_test_vectors(tree_math);

  CryptoTestVectors crypto = generate_crypto();
  write_test_vectors(crypto);

  HashRatchetTestVectors hash_ratchet = generate_hash_ratchet();
  write_test_vectors(hash_ratchet);

  KeyScheduleTestVectors key_schedule = generate_key_schedule();
  write_test_vectors(key_schedule);

  TreeTestVectors tree = generate_tree();
  write_test_vectors(tree);

  MessagesTestVectors messages = generate_messages();
  write_test_vectors(messages);

  BasicSessionTestVectors basic_session = generate_basic_session();
  write_test_vectors(basic_session);

  // Verify that the test vectors are reproducible (to the extent
  // possible)
  verify_reproducible(generate_tree_math);
  verify_reproducible(generate_crypto);
  verify_reproducible(generate_hash_ratchet);
  verify_reproducible(generate_key_schedule);
  verify_reproducible(generate_tree);
  verify_reproducible(generate_messages);
  verify_session_repro(generate_basic_session);

  // Verify that the test vectors load
  try {
    TestLoader<TreeMathTestVectors>::get();
    TestLoader<CryptoTestVectors>::get();
    TestLoader<HashRatchetTestVectors>::get();
    TestLoader<KeyScheduleTestVectors>::get();
    TestLoader<TreeTestVectors>::get();
    TestLoader<MessagesTestVectors>::get();
    TestLoader<BasicSessionTestVectors>::get();
  } catch (...) {
    std::cerr << "Error: Generated test vectors failed to load" << std::endl;
  }

  return 0;
}
