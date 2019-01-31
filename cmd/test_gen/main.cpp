#include "crypto.h"
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
  auto credential_all = Credential::basic(tv.user_id, identity_priv);
  uik_all.sign(identity_priv, credential_all);

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
    user_init_key.sign(sig_priv, cred);

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

int
main()
{
  TreeMathTestVectors tree_math = generate_tree_math();
  write_test_vectors(tree_math);

  CryptoTestVectors crypto = generate_crypto();
  write_test_vectors(crypto);

  MessagesTestVectors messages = generate_messages();
  write_test_vectors(messages);

  // Verify that the test vectors load
  try {
    TestLoader<TreeMathTestVectors>::get();
    TestLoader<CryptoTestVectors>::get();
    TestLoader<MessagesTestVectors>::get();
  } catch (...) {
    std::cerr << "Error: Generated test vectors failed to load" << std::endl;
  }

  return 0;
}
