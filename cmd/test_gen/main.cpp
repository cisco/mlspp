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

ResolutionTestVectors
generate_resolution()
{
  ResolutionTestVectors tv;
  tv.n_leaves = LeafCount{ 7 };

  auto width = NodeCount{ tv.n_leaves };
  uint32_t n_cases = (1 << width.val);

  tv.cases.resize(n_cases);
  for (uint32_t t = 0; t < n_cases; ++t) {
    tv.cases[t].resize(width.val);

    auto nodes = ResolutionTestVectors::make_tree(t, width);
    for (uint32_t i = 0; i < width.val; ++i) {
      auto res = tree_math::resolve(nodes, NodeIndex{ i });
      tv.cases[t][i] = ResolutionTestVectors::compact(res);
    }
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

  std::string derive_secret_label_string = "test";
  tv.derive_secret_secret = bytes(32, 0xA0);
  tv.derive_secret_label =
    bytes(derive_secret_label_string.begin(), derive_secret_label_string.end());
  tv.derive_secret_context = bytes(32, 0xB0);

  tv.derive_key_pair_seed = { 0, 1, 2, 3 };

  tv.ecies_plaintext = bytes(128, 0xB1);

  // Construct a test case for each suite
  for (size_t i = 0; i < suites.size(); ++i) {
    auto suite = suites[i];
    auto test_case = cases[i];

    // HKDF-Extract
    test_case->hkdf_extract_out =
      hkdf_extract(suite, tv.hkdf_extract_salt, tv.hkdf_extract_ikm);

    // Derive-Secret
    test_case->derive_secret_out = derive_secret(suite,
                                                 tv.derive_secret_secret,
                                                 derive_secret_label_string,
                                                 tv.derive_secret_context);

    // Derive-Key-Pair
    auto priv = DHPrivateKey::derive(suite, tv.derive_key_pair_seed);
    auto pub = priv.public_key();
    test_case->derive_key_pair_pub = pub;

    // HPKE
    DeterministicHPKE lock;
    test_case->ecies_out = pub.encrypt(tv.ecies_plaintext);
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

  auto base_suite = CipherSuite::P256_SHA256_AES128GCM;
  auto zero = bytes(Digest(base_suite).output_size(), 0x00);
  GroupContext base_group_context{
    { 0xA0, 0xA0, 0xA0, 0xA0 },
    0,
    bytes(32, 0xA1),
    bytes(32, 0xA2),
  };

  tv.n_epochs = 100;
  tv.base_group_context = tls::marshal(base_group_context);

  // Construct a test case for each suite
  for (size_t i = 0; i < suites.size(); ++i) {
    auto suite = suites[i];
    auto test_case = cases[i];
    auto secret_size = Digest(suite).output_size();

    test_case->suite = suite;

    auto group_context = base_group_context;
    bytes init_secret(secret_size, 0);
    bytes update_secret(secret_size, 0);

    for (size_t j = 0; j < tv.n_epochs; ++j) {
      auto group_context_bytes = tls::marshal(group_context);
      auto epoch_secret =
        State::next_epoch_secret(suite, init_secret, update_secret);
      auto secrets =
        State::derive_epoch_secrets(suite, epoch_secret, group_context);

      test_case->epochs.push_back({
        update_secret,
        secrets.epoch_secret,
        secrets.application_secret,
        secrets.confirmation_key,
        secrets.init_secret,
      });

      init_secret = secrets.init_secret;
      for (auto& val : update_secret) {
        val += 1;
      }
      group_context.epoch += 1;
    }
  }

  return tv;
}

AppKeyScheduleTestVectors
generate_app_key_schedule()
{
  AppKeyScheduleTestVectors tv;

  std::vector<CipherSuite> suites{
    CipherSuite::P256_SHA256_AES128GCM,
    CipherSuite::X25519_SHA256_AES128GCM,
  };

  std::vector<AppKeyScheduleTestVectors::TestCase*> cases{
    &tv.case_p256,
    &tv.case_x25519,
  };

  tv.n_members = 16;
  tv.n_generations = 16;
  tv.application_secret = bytes(32, 0xA0);

  for (size_t i = 0; i < suites.size(); ++i) {
    auto suite = suites[i];
    auto test_case = cases[i];

    KeyChain chain(suite);
    chain.start(LeafIndex{ 0 }, tv.application_secret);
    for (uint32_t j = 0; j < tv.n_members; ++j) {
      test_case->emplace_back();

      for (uint32_t k = 0; k < tv.n_generations; ++k) {
        auto kn = chain.get(LeafIndex{ j }, k);
        test_case->at(j).push_back({ kn.secret, kn.key, kn.nonce });
      }
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

      tree.add_leaf(LeafIndex{ j }, tv.leaf_secrets[j], cred);
      tree.set_path(LeafIndex{ j }, tv.leaf_secrets[j]);
      test_case->trees.push_back(tree_to_case(tree));
    }

    // Blank out even-numbered leaves
    for (uint32_t j = 0; j < n_leaves; j += 2) {
      tree.blank_path(LeafIndex{ j });
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
    auto dh_priv = DHPrivateKey::derive(suite, tv.dh_seed);
    auto dh_key = dh_priv.public_key();
    auto sig_priv = SignaturePrivateKey::derive(scheme, tv.sig_seed);
    auto sig_key = sig_priv.public_key();
    auto cred = Credential::basic(tv.user_id, sig_priv);

    auto ratchet_tree =
      RatchetTree{ suite,
                   { tv.random, tv.random, tv.random, tv.random },
                   { cred, cred, cred, cred } };
    ratchet_tree.blank_path(LeafIndex{ 2 });

    DirectPath direct_path(ratchet_tree.cipher_suite());
    bytes dummy;
    std::tie(direct_path, dummy) =
      ratchet_tree.encrypt(LeafIndex{ 0 }, tv.random);

    // Construct CIK
    auto client_init_key = ClientInitKey{ dh_priv, cred };
    client_init_key.signature = tv.random;

    // Construct Welcome
    auto group_info =
      GroupInfo{ tv.group_id, tv.epoch,    ratchet_tree, tv.random,
                 tv.random,   direct_path, tv.random };
    group_info.signer_index = tv.signer_index;
    group_info.signature = tv.random;

    auto key_package = KeyPackage{ tv.random };
    auto encrypted_key_package =
      EncryptedKeyPackage{ tv.random, dh_key.encrypt(tv.random) };

    Welcome welcome;
    welcome.version = ProtocolVersion::mls10;
    welcome.cipher_suite = suite;
    welcome.key_packages = { encrypted_key_package, encrypted_key_package };
    welcome.encrypted_group_info = tv.random;

    // Construct Proposals
    auto add_prop = Proposal{ AddProposal{ client_init_key } };
    auto add_hs =
      MLSPlaintext{ tv.group_id, tv.epoch, tv.signer_index, add_prop };
    add_hs.signature = tv.random;

    auto update_prop = Proposal{ UpdateProposal{ dh_key } };
    auto update_hs =
      MLSPlaintext{ tv.group_id, tv.epoch, tv.signer_index, update_prop };
    update_hs.signature = tv.random;

    auto remove_prop = Proposal{ RemoveProposal{ tv.signer_index } };
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

    // Construct handshake messages
    auto add_op = Add{ tv.removed, client_init_key };
    auto update_op = Update{ direct_path };
    auto remove_op = Remove{ tv.removed, direct_path };

    auto add = MLSPlaintext{ tv.group_id, tv.epoch, tv.signer_index, add_op };
    auto update =
      MLSPlaintext{ tv.group_id, tv.epoch, tv.signer_index, update_op };
    auto remove =
      MLSPlaintext{ tv.group_id, tv.epoch, tv.signer_index, remove_op };
    add.signature = tv.random;
    update.signature = tv.random;
    remove.signature = tv.random;

    // Construct an MLSCiphertext
    auto ciphertext = MLSCiphertext{
      tv.group_id,
      tv.epoch,
      ContentType::handshake, // XXX(rlb@ipv.sx): Make a parameter
      tv.random,
      tv.random,
      tv.random,
    };

    *cases[i] = {
      suite,
      scheme,
      tls::marshal(client_init_key),
      tls::marshal(group_info),
      tls::marshal(key_package),
      tls::marshal(encrypted_key_package),
      tls::marshal(welcome),
      tls::marshal(add),
      tls::marshal(update),
      tls::marshal(remove),
      tls::marshal(add_hs),
      tls::marshal(update_hs),
      tls::marshal(remove_hs),
      tls::marshal(commit),
      tls::marshal(ciphertext),
    };
  }

  return tv;
}

BasicSessionTestVectors
generate_basic_session()
{
  BasicSessionTestVectors tv;

  std::vector<CipherSuite> suites{
    CipherSuite::P256_SHA256_AES128GCM,
    CipherSuite::X25519_SHA256_AES128GCM,
  };

  std::vector<SignatureScheme> schemes{
    SignatureScheme::P256_SHA256,
    SignatureScheme::Ed25519,
  };

  std::vector<SessionTestVectors::TestCase*> cases{
    &tv.case_p256_p256,
    &tv.case_x25519_ed25519,
  };

  tv.group_size = 5;
  tv.group_id = bytes(16, 0xA0);

  DeterministicHPKE lock;
  for (size_t i = 0; i < suites.size(); ++i) {
    auto suite = suites[i];
    auto scheme = schemes[i];
    const bytes client_init_key_id = { 0, 1, 2, 3 };

    std::vector<SessionTestVectors::Epoch> transcript;

    // Initialize empty sessions
    std::vector<ClientInitKey> client_init_keys;
    std::vector<TestSession> sessions;
    std::vector<bytes> seeds;
    auto ciphersuites = std::vector<CipherSuite>{ suite };
    for (size_t j = 0; j < tv.group_size; ++j) {
      bytes seed = { uint8_t(j), 0 };
      seeds.push_back(seed);

      auto identity_priv = SignaturePrivateKey::derive(scheme, seed);
      auto cred = Credential::basic(seed, identity_priv);
      auto init = HPKEPrivateKey::derive(suite, seed);
      client_init_keys.emplace_back(init, cred);
    }

    // Add everyone
    for (size_t j = 1; j < tv.group_size; ++j) {
      Welcome welcome;
      bytes add;
      if (j == 1) {
        auto session_welcome_add = Session::start(
          tv.group_id, { client_init_keys[0] }, { client_init_keys[1] });
        sessions.push_back(std::get<0>(session_welcome_add));
        welcome = std::get<1>(session_welcome_add);
        add = std::get<2>(session_welcome_add);
      } else {
        std::tie(welcome, add) = sessions[j - 1].add(client_init_keys[j]);
        for (size_t k = 0; k < j; ++k) {
          sessions[k].handle(add);
        }
      }

      auto joiner = Session::join({ client_init_keys[j] }, welcome);
      sessions.push_back(joiner);

      transcript.emplace_back(welcome, add, sessions[0]);
    }

    // Update everyone (L->R)
    for (size_t j = 0; j < tv.group_size; ++j) {
      seeds[j][1] += 1;
      auto update = sessions[j].update(seeds[j]);
      for (auto& session : sessions) {
        session.handle(update);
      }

      transcript.emplace_back(std::nullopt, update, sessions[0]);
    }

    // Remove everyone (R->L)
    for (int j = tv.group_size - 2; j >= 0; --j) {
      seeds[j][1] += 1;
      auto remove = sessions[j].remove(seeds[j], j + 1);
      for (int k = 0; k <= j; ++k) {
        sessions[k].handle(remove);
      }

      for (int k = 0; k <= j; ++k) {
        if (!(sessions[k] == sessions[0])) {
          throw std::runtime_error("bad session during remove");
        }
      }

      transcript.emplace_back(std::nullopt, remove, sessions[0]);
    }

    // Construct the test case
    *cases[i] = { suite, scheme, client_init_keys, transcript };
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

  ResolutionTestVectors resolution = generate_resolution();
  write_test_vectors(resolution);

  CryptoTestVectors crypto = generate_crypto();
  write_test_vectors(crypto);

  KeyScheduleTestVectors key_schedule = generate_key_schedule();
  write_test_vectors(key_schedule);

  AppKeyScheduleTestVectors app_key_schedule = generate_app_key_schedule();
  write_test_vectors(app_key_schedule);

  TreeTestVectors tree = generate_tree();
  write_test_vectors(tree);

  MessagesTestVectors messages = generate_messages();
  write_test_vectors(messages);

  BasicSessionTestVectors basic_session = generate_basic_session();
  write_test_vectors(basic_session);

  // Verify that the test vectors are reproducible (to the extent
  // possible)
  verify_reproducible(generate_tree_math);
  verify_reproducible(generate_resolution);
  verify_reproducible(generate_crypto);
  verify_reproducible(generate_key_schedule);
  verify_reproducible(generate_app_key_schedule);
  verify_reproducible(generate_tree);
  verify_reproducible(generate_messages);
  verify_session_repro(generate_basic_session);

  // Verify that the test vectors load
  try {
    TestLoader<TreeMathTestVectors>::get();
    TestLoader<ResolutionTestVectors>::get();
    TestLoader<CryptoTestVectors>::get();
    TestLoader<KeyScheduleTestVectors>::get();
    TestLoader<AppKeyScheduleTestVectors>::get();
    TestLoader<TreeTestVectors>::get();
    TestLoader<MessagesTestVectors>::get();
    TestLoader<BasicSessionTestVectors>::get();
  } catch (...) {
    std::cerr << "Error: Generated test vectors failed to load" << std::endl;
  }

  return 0;
}
