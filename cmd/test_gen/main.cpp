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
  auto n_cases = (1 << width.val);

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
  for (int i = 0; i < suites.size(); ++i) {
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
    test::DeterministicHPKE lock;
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
  GroupState base_group_state(base_suite);
  base_group_state.group_id = { 0xA0, 0xA0, 0xA0, 0xA0 };
  base_group_state.transcript_hash = zero;

  tv.n_epochs = 100;
  tv.base_group_state = tls::marshal(base_group_state);

  // Construct a test case for each suite
  for (int i = 0; i < suites.size(); ++i) {
    auto suite = suites[i];
    auto test_case = cases[i];
    auto secret_size = Digest(suite).output_size();

    test_case->suite = suite;

    auto group_state = base_group_state;
    group_state.transcript_hash = zero;
    bytes init_secret(secret_size, 0);
    bytes update_secret(secret_size, 0);

    for (int j = 0; j < tv.n_epochs; ++j) {
      auto secrets = State::derive_epoch_secrets(
        suite, init_secret, update_secret, group_state);

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
      group_state.epoch += 1;
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

  for (int i = 0; i < suites.size(); ++i) {
    auto suite = suites[i];
    auto test_case = cases[i];

    for (uint32_t j = 0; j < tv.n_members; ++j) {
      ApplicationKeyChain chain(suite, j, tv.application_secret);
      test_case->emplace_back();

      for (uint32_t k = 0; k < tv.n_generations; ++k) {
        auto kn = chain.get(k);
        test_case->at(j).push_back({ kn.secret, kn.key, kn.nonce });
      }
    }
  }

  return tv;
}

TreeTestVectors::TreeCase
tree_to_case(const test::TestRatchetTree& tree)
{
  auto nodes = tree.nodes();
  TreeTestVectors::TreeCase tc(nodes.size());
  for (int i = 0; i < nodes.size(); ++i) {
    tc[i].hash = nodes[i].hash();
    if (!nodes[i].blank()) {
      tc[i].secret = nodes[i]->secret();
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

  std::vector<TreeTestVectors::TestCase*> cases{
    &tv.case_p256,
    &tv.case_x25519,
  };

  int n_leaves = 2;
  tv.leaf_secrets.resize(n_leaves);
  for (int i = 0; i < n_leaves; ++i) {
    tv.leaf_secrets[i] = { uint8_t(i) };
  }

  for (int i = 0; i < suites.size(); ++i) {
    auto suite = suites[i];
    auto test_case = cases[i];

    test::TestRatchetTree tree{ suite };

    // Add the leaves
    for (uint32_t j = 0; j < n_leaves; ++j) {
      tree.add_leaf(LeafIndex{ j }, tv.leaf_secrets[j]);
      tree.set_path(LeafIndex{ j }, tv.leaf_secrets[j]);
      test_case->push_back(tree_to_case(tree));
    }

    // Blank out even-numbered leaves
    for (uint32_t j = 0; j < n_leaves; j += 2) {
      tree.blank_path(LeafIndex{ j });
      test_case->push_back(tree_to_case(tree));
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
  tv.uik_id = bytes(16, 0xD3);
  tv.dh_seed = bytes(32, 0xD4);
  tv.sig_seed = bytes(32, 0xD5);
  tv.random = bytes(32, 0xD6);
  tv.uik_all_scheme = SignatureScheme::Ed25519;

  // Construct a UIK with all the ciphersuites
  auto uik_all = UserInitKey{};
  uik_all.user_init_key_id = tv.uik_id;
  for (const auto& suite : suites) {
    auto priv = DHPrivateKey::derive(suite, tv.dh_seed);
    uik_all.add_init_key(priv.public_key());
  }

  auto identity_priv =
    SignaturePrivateKey::derive(tv.uik_all_scheme, tv.sig_seed);
  uik_all.credential = Credential::basic(tv.user_id, identity_priv);
  uik_all.signature = tv.random;

  tv.user_init_key_all = tls::marshal(uik_all);

  // Construct a test case for each suite
  test::DeterministicHPKE lock;
  for (int i = 0; i < suites.size(); ++i) {
    auto suite = suites[i];
    auto scheme = schemes[i];

    // Miscellaneous data items we need to construct messages
    auto dh_priv = DHPrivateKey::derive(suite, tv.dh_seed);
    auto dh_key = dh_priv.public_key();
    auto sig_priv = SignaturePrivateKey::derive(scheme, tv.sig_seed);
    auto sig_key = sig_priv.public_key();

    auto ratchet_tree =
      RatchetTree{ suite, { tv.random, tv.random, tv.random, tv.random } };
    ratchet_tree.blank_path(LeafIndex{ 2 });
    auto direct_path = ratchet_tree.encrypt(LeafIndex{ 0 }, tv.random);

    auto cred = Credential::basic(tv.user_id, sig_key);
    auto roster = Roster{};
    roster.add(0, cred);

    // Construct UIK
    auto user_init_key = UserInitKey{};
    user_init_key.user_init_key_id = tv.uik_id;
    user_init_key.add_init_key(dh_key);
    user_init_key.credential = cred;
    user_init_key.signature = tv.random;

    // Construct WelcomeInfo and Welcome
    auto welcome_info = WelcomeInfo{
      tv.group_id,  tv.epoch,  tv.removed, roster,
      ratchet_tree, tv.random, tv.random,
    };
    auto welcome = Welcome{ tv.uik_id, dh_key, welcome_info };

    // Construct Handshake messages
    auto add_op = Add{ tv.removed, user_init_key };
    auto update_op = Update{ direct_path };
    auto remove_op = Remove{ tv.removed, direct_path };
    auto add =
      Handshake{ tv.epoch, add_op, tv.signer_index, tv.random, tv.random };
    auto update =
      Handshake{ tv.epoch, update_op, tv.signer_index, tv.random, tv.random };
    auto remove =
      Handshake{ tv.epoch, remove_op, tv.signer_index, tv.random, tv.random };

    *cases[i] = {
      suite,
      scheme,
      tls::marshal(user_init_key),
      tls::marshal(welcome_info),
      tls::marshal(welcome),
      tls::marshal(add),
      tls::marshal(update),
      tls::marshal(remove),
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

  test::DeterministicHPKE lock;
  for (int i = 0; i < suites.size(); ++i) {
    auto suite = suites[i];
    auto scheme = schemes[i];

    std::vector<SessionTestVectors::Epoch> transcript;

    // Initialize empty sessions
    std::vector<test::TestSession> sessions;
    std::vector<bytes> seeds;
    auto ciphersuites = CipherList{ suite };
    for (int j = 0; j < tv.group_size; ++j) {
      bytes seed = { uint8_t(j), 0 };
      auto identity_priv = SignaturePrivateKey::derive(scheme, seed);
      auto cred = Credential::basic(seed, identity_priv);
      seeds.push_back(seed);
      sessions.emplace_back(ciphersuites, seed, identity_priv, cred);
    }

    std::vector<tls::opaque<4>> uiks;
    for (const auto& session : sessions) {
      uiks.push_back(session.user_init_key());
    }

    // Add everyone
    for (int j = 1; j < tv.group_size; ++j) {
      auto uik = sessions[j].user_init_key();

      std::pair<bytes, bytes> welcome_add;
      if (j == 1) {
        welcome_add = sessions[0].start(tv.group_id, uik);
      } else {
        welcome_add = sessions[j - 1].add(uik);
        for (int k = 0; k < j; ++k) {
          sessions[k].handle(welcome_add.second);
        }
      }

      sessions[j].join(welcome_add.first, welcome_add.second);

      transcript.emplace_back(
        welcome_add.first, welcome_add.second, sessions[0]);
    }

    // Update everyone (L->R)
    for (int j = 0; j < tv.group_size; ++j) {
      seeds[j][1] += 1;
      auto update = sessions[j].update(seeds[j]);
      for (auto& session : sessions) {
        session.handle(update);
      }

      transcript.emplace_back(bytes{}, update, sessions[0]);
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

      transcript.emplace_back(bytes{}, remove, sessions[0]);
    }

    // Construct the test case
    *cases[i] = { suite, scheme, uiks, transcript };
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
  /*
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
  */

  TreeTestVectors tree = generate_tree();
  write_test_vectors(tree);

  /*
  MessagesTestVectors messages = generate_messages();
  write_test_vectors(messages);

  BasicSessionTestVectors basic_session = generate_basic_session();
  write_test_vectors(basic_session);
  */

  // Verify that the test vectors are reproducible (to the extent
  // possible)
  /*
  verify_reproducible(generate_tree_math);
  verify_reproducible(generate_resolution);
  verify_reproducible(generate_crypto);
  verify_reproducible(generate_key_schedule);
  verify_reproducible(generate_app_key_schedule);
  */
  verify_reproducible(generate_tree);
  /*
  verify_reproducible(generate_messages);
  verify_session_repro(generate_basic_session);
  */

  // Verify that the test vectors load
  try {
    /*
    TestLoader<TreeMathTestVectors>::get();
    TestLoader<ResolutionTestVectors>::get();
    TestLoader<CryptoTestVectors>::get();
    TestLoader<KeyScheduleTestVectors>::get();
    TestLoader<AppKeyScheduleTestVectors>::get();
    */
    TestLoader<TreeTestVectors>::get();
    /*
    TestLoader<MessagesTestVectors>::get();
    TestLoader<BasicSessionTestVectors>::get();
    */
  } catch (...) {
    std::cerr << "Error: Generated test vectors failed to load" << std::endl;
  }

  return 0;
}
