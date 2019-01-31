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

  for (int n = 1; n <= TreeMathTestVectors::tree_size; ++n) {
    auto val = mls::tree_math::root(n);
    tv.root.push_back(val);
  }

  auto n = TreeMathTestVectors::tree_size;
  for (int x = 0; x < TreeMathTestVectors::tree_size; ++x) {
    auto left = mls::tree_math::left(x);
    tv.left.push_back(left);

    auto right = mls::tree_math::right(x, n);
    tv.right.push_back(right);

    auto parent = mls::tree_math::parent(x, n);
    tv.parent.push_back(parent);

    auto sibling = mls::tree_math::sibling(x, n);
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
    CipherSuite::P521_SHA512_AES256GCM,
    CipherSuite::X448_SHA512_AES256GCM,
  };

  std::vector<CryptoTestVectors::TestCase*> cases{
    &tv.case_p256,
    &tv.case_x25519,
    &tv.case_p521,
    &tv.case_x448,
  };

  std::string derive_secret_label_string = "test";
  bytes derive_secret_label_bytes(derive_secret_label_string.begin(),
                                  derive_secret_label_string.end());

  tv.hkdf_extract_salt = { 0, 1, 2, 3 };
  tv.hkdf_extract_ikm = { 4, 5, 6, 7 };

  tv.derive_secret_secret = bytes(32, 0xA0);
  tv.derive_secret_label = derive_secret_label_bytes;
  tv.derive_secret_length = 32;

  tv.derive_key_pair_seed = { 0, 1, 2, 3 };

  tv.ecies_plaintext = bytes(128, 0xB1);

  // Construct a test case for each suite
  for (int i = 0; i < suites.size(); ++i) {
    auto suite = suites[i];
    auto test_case = cases[i];

    // HKDF-Extract
    test_case->hkdf_extract_out =
      mls::hkdf_extract(suite, tv.hkdf_extract_salt, tv.hkdf_extract_ikm);

    // Derive-Secret
    // TODO(rlb@ipv.sx): Populate some actual state
    test_case->derive_secret_state = GroupState{ suite };
    test_case->derive_secret_out =
      mls::derive_secret(suite,
                         tv.derive_secret_secret,
                         derive_secret_label_string,
                         test_case->derive_secret_state,
                         tv.derive_secret_length);

    // Derive-Key-Pair
    auto priv = DHPrivateKey::derive(suite, tv.derive_key_pair_seed);
    auto pub = priv.public_key();
    test_case->derive_key_pair_pub = pub;

    // ECIES
    mls::test::DeterministicECIES lock;
    test_case->ecies_out = pub.encrypt(tv.ecies_plaintext);
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
    CipherSuite::P521_SHA512_AES256GCM,
    CipherSuite::X448_SHA512_AES256GCM,
  };

  std::vector<SignatureScheme> schemes{
    SignatureScheme::P256_SHA256,
    SignatureScheme::Ed25519,
    SignatureScheme::P521_SHA512,
    SignatureScheme::Ed448,
  };

  std::vector<MessagesTestVectors::TestCase*> cases{
    &tv.case_p256_p256,
    &tv.case_x25519_ed25519,
    &tv.case_p521_p521,
    &tv.case_x448_ed448,
  };

  // Set the inputs
  tv.epoch = 0xA0A1A2A3;
  tv.signer_index = 0xB0B1B2B3;
  tv.removed = 0xC0C1C2C3;
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
  mls::test::DeterministicECIES lock;
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
    ratchet_tree.blank_path(2);
    auto direct_path = ratchet_tree.encrypt(0, tv.random);

    auto cred = Credential::basic(tv.user_id, sig_key);
    auto roster = Roster{};
    roster.add(cred);

    // Construct UIK
    auto user_init_key = UserInitKey{};
    user_init_key.user_init_key_id = tv.uik_id;
    user_init_key.add_init_key(dh_key);
    user_init_key.credential = cred;
    user_init_key.signature = tv.random;

    // Construct WelcomeInfo and Welcome
    auto welcome_info = WelcomeInfo{
      tv.group_id, tv.epoch, roster, ratchet_tree, tv.random, tv.random,
    };
    auto welcome = Welcome{ tv.uik_id, dh_key, welcome_info };

    // Construct Handshake messages
    auto add_op = Add{ user_init_key };
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
    CipherSuite::P521_SHA512_AES256GCM,
    CipherSuite::X448_SHA512_AES256GCM,
  };

  std::vector<SignatureScheme> schemes{
    SignatureScheme::P256_SHA256,
    SignatureScheme::Ed25519,
    SignatureScheme::P521_SHA512,
    SignatureScheme::Ed448,
  };

  std::vector<SessionTestVectors::TestCase*> cases{
    &tv.case_p256_p256,
    &tv.case_x25519_ed25519,
    &tv.case_p521_p521,
    &tv.case_x448_ed448,
  };

  tv.group_size = 5;
  tv.group_id = bytes(16, 0xA0);

  mls::test::DeterministicECIES lock;
  for (int i = 0; i < suites.size(); ++i) {
    auto suite = suites[i];
    auto scheme = schemes[i];

    std::vector<SessionTestVectors::Epoch> transcript;

    // Initialize empty sessions
    std::vector<mls::test::TestSession> sessions;
    std::vector<bytes> seeds;
    auto ciphersuites = CipherList{ suite };
    for (int j = 0; j < tv.group_size; ++j) {
      bytes seed = { uint8_t(i), 0 };
      auto identity_priv = SignaturePrivateKey::derive(scheme, seed);
      auto cred = Credential::basic(seed, identity_priv);
      seeds.push_back(seed);
      sessions.emplace_back(ciphersuites, seed, identity_priv, cred);
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
    *cases[i] = { suite, scheme, transcript };
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

void
verify_tree_math_repro()
{
  auto v0 = generate_tree_math();
  auto v1 = generate_tree_math();
  verify_equal_marshaled(v0, v1);
}

void
verify_crypto_repro()
{
  auto v0 = generate_tree_math();
  auto v1 = generate_tree_math();
  verify_equal_marshaled(v0, v1);
}

void
verify_messages_repro()
{
  auto v0 = generate_messages();
  auto v1 = generate_messages();

  // Inputs shouldn't have any variation
  verify_equal_marshaled(v0.epoch, v1.epoch);
  verify_equal_marshaled(v0.signer_index, v1.signer_index);
  verify_equal_marshaled(v0.removed, v1.removed);
  verify_equal_marshaled(v0.user_id, v1.user_id);
  verify_equal_marshaled(v0.group_id, v1.group_id);
  verify_equal_marshaled(v0.uik_id, v1.uik_id);
  verify_equal_marshaled(v0.dh_seed, v1.dh_seed);
  verify_equal_marshaled(v0.sig_seed, v1.sig_seed);
  verify_equal_marshaled(v0.random, v1.random);

  // EdDSA-based ciphersuites should be reproducible
  verify_equal_marshaled(v0.case_x25519_ed25519, v1.case_x25519_ed25519);
  verify_equal_marshaled(v0.case_x448_ed448, v1.case_x448_ed448);

  // ECDSA-based ciphersuites should be reproducible except for the
  // signature on the UIK
}

void
verify_session_repro()
{}

int
main()
{
  TreeMathTestVectors tree_math = generate_tree_math();
  write_test_vectors(tree_math);

  CryptoTestVectors crypto = generate_crypto();
  write_test_vectors(crypto);

  MessagesTestVectors messages = generate_messages();
  write_test_vectors(messages);

  BasicSessionTestVectors basic_session = generate_basic_session();
  write_test_vectors(basic_session);

  // Verify that the test vectors are reproducible (to the extent
  // possible)
  if (true) {
    verify_tree_math_repro();
    verify_crypto_repro();
    verify_messages_repro();
    verify_session_repro();
  }

  // Verify that the test vectors load
  try {
    TestLoader<TreeMathTestVectors>::get();
    TestLoader<CryptoTestVectors>::get();
    TestLoader<MessagesTestVectors>::get();
    TestLoader<BasicSessionTestVectors>::get();
  } catch (...) {
    std::cerr << "Error: Generated test vectors failed to load" << std::endl;
  }

  return 0;
}
