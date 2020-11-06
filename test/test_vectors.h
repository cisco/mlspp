#include <mls/common.h>
#include <mls/messages.h>
#include <mls/session.h>
#include <mls/state.h>
#include <mls/tree_math.h>
#include <string>
#include <tls/tls_syntax.h>

using namespace mls;

/////

struct TreeMathTestVectors
{
  static const std::string file_name;

  struct NodeVector
  {
    std::vector<NodeIndex> nodes;
    TLS_SERIALIZABLE(nodes)
    TLS_TRAITS(tls::vector<4>)
  };

  LeafCount n_leaves{ 255 };
  std::vector<NodeIndex> root;
  std::vector<NodeIndex> left;
  std::vector<NodeIndex> right;
  std::vector<NodeIndex> parent;
  std::vector<NodeIndex> sibling;
  std::vector<NodeVector> dirpath;
  std::vector<NodeVector> copath;
  std::vector<NodeVector> ancestor;

  TLS_SERIALIZABLE(n_leaves,
                   root,
                   left,
                   right,
                   parent,
                   sibling,
                   dirpath,
                   copath,
                   ancestor)
  TLS_TRAITS(tls::pass,
             tls::vector<4>,
             tls::vector<4>,
             tls::vector<4>,
             tls::vector<4>,
             tls::vector<4>,
             tls::vector<4>,
             tls::vector<4>,
             tls::vector<4>)
};

/////

struct CryptoTestVectors
{
  static const std::string file_name;

  bytes kdf_extract_salt;
  bytes kdf_extract_ikm;

  bytes derive_key_pair_seed;

  bytes hpke_aad;
  bytes hpke_plaintext;

  struct TestCase
  {
    CipherSuite cipher_suite;

    // kdf-Extract
    bytes kdf_extract_out;

    // Derive-Key-Pair
    HPKEPublicKey derive_key_pair_pub;

    // HPKE
    HPKECiphertext hpke_out;

    TLS_SERIALIZABLE(cipher_suite,
                     kdf_extract_out,
                     derive_key_pair_pub,
                     hpke_out)
    TLS_TRAITS(tls::pass, tls::vector<1>, tls::pass, tls::pass)
  };

  std::vector<TestCase> cases;

  TLS_SERIALIZABLE(kdf_extract_salt,
                   kdf_extract_ikm,
                   derive_key_pair_seed,
                   hpke_aad,
                   hpke_plaintext,
                   cases)
  TLS_TRAITS(tls::vector<1>,
             tls::vector<1>,
             tls::vector<1>,
             tls::vector<1>,
             tls::vector<1>,
             tls::vector<4>)
};

/////

struct HashRatchetTestVectors
{
  static const std::string file_name;

  struct Step
  {
    bytes key;
    bytes nonce;

    TLS_SERIALIZABLE(key, nonce)
    TLS_TRAITS(tls::vector<1>, tls::vector<1>)
  };

  struct KeySequence
  {
    std::vector<Step> steps;
    TLS_SERIALIZABLE(steps)
    TLS_TRAITS(tls::vector<4>)
  };

  struct TestCase
  {
    CipherSuite cipher_suite;
    std::vector<KeySequence> key_sequences;

    TLS_SERIALIZABLE(cipher_suite, key_sequences)
    TLS_TRAITS(tls::pass, tls::vector<4>)
  };

  uint32_t n_members;
  uint32_t n_generations;
  bytes base_secret;

  std::vector<TestCase> cases;

  TLS_SERIALIZABLE(n_members, n_generations, base_secret, cases)
  TLS_TRAITS(tls::pass, tls::pass, tls::vector<1>, tls::vector<4>)
};

/////

struct KeyScheduleTestVectors
{
  static const std::string file_name;

  struct KeyAndNonce
  {
    bytes key;
    bytes nonce;

    TLS_SERIALIZABLE(key, nonce)
    TLS_TRAITS(tls::vector<1>, tls::vector<1>)
  };

  struct Epoch
  {
    LeafCount n_members;
    bytes commit_secret;

    bytes epoch_secret;

    bytes sender_data_secret;
    bytes encryption_secret;
    bytes exporter_secret;
    bytes authentication_secret;
    bytes external_secret;
    bytes confirmation_key;
    bytes membership_key;
    bytes resumption_secret;
    bytes init_secret;

    HPKEPublicKey external_pub;

    std::vector<KeyAndNonce> handshake_keys;
    std::vector<KeyAndNonce> application_keys;

    bytes sender_data_key;
    bytes sender_data_nonce;

    TLS_SERIALIZABLE(n_members,
                     commit_secret,
                     epoch_secret,
                     sender_data_secret,
                     encryption_secret,
                     exporter_secret,
                     authentication_secret,
                     external_secret,
                     confirmation_key,
                     membership_key,
                     resumption_secret,
                     init_secret,
                     external_pub,
                     handshake_keys,
                     application_keys,
                     sender_data_key,
                     sender_data_nonce)
    TLS_TRAITS(tls::pass,
               tls::vector<1>,
               tls::vector<1>,
               tls::vector<1>,
               tls::vector<1>,
               tls::vector<1>,
               tls::vector<1>,
               tls::vector<1>,
               tls::vector<1>,
               tls::vector<1>,
               tls::vector<1>,
               tls::vector<1>,
               tls::pass,
               tls::vector<4>,
               tls::vector<4>,
               tls::vector<1>,
               tls::vector<1>)
  };

  struct TestCase
  {
    CipherSuite cipher_suite;
    std::vector<Epoch> epochs;

    TLS_SERIALIZABLE(cipher_suite, epochs)
    TLS_TRAITS(tls::pass, tls::vector<2>)
  };

  uint32_t n_epochs;
  uint32_t target_generation;
  bytes base_init_secret;
  bytes base_group_context;
  bytes ciphertext;

  std::vector<TestCase> cases;

  TLS_SERIALIZABLE(n_epochs,
                   target_generation,
                   base_init_secret,
                   base_group_context,
                   ciphertext,
                   cases)
  TLS_TRAITS(tls::pass,
             tls::pass,
             tls::vector<1>,
             tls::vector<1>,
             tls::vector<4>,
             tls::vector<4>)
};

/////

struct TestTreeKEMPublicKey : public TreeKEMPublicKey
{
  using TreeKEMPublicKey::TreeKEMPublicKey;

  TestTreeKEMPublicKey(CipherSuite suite_in, const std::vector<bytes>& secrets)
    : TreeKEMPublicKey(suite_in)
  {
    for (const auto& secret : secrets) {
      add_leaf_secret(secret);
    }

    for (uint32_t i = 0; i < secrets.size() - 1; i += 1) {
      auto secret = secrets[i];
      secret.push_back(0);
      auto pub = HPKEPrivateKey::derive(suite, secret).public_key;
      nodes.at(2 * i + 1).node = Node{ ParentNode{ pub, {}, {} } };
    }
  }

  void add_leaf_secret(const bytes& secret)
  {
    auto init_pub = HPKEPrivateKey::derive(suite, secret).public_key;
    auto sig_priv = SignaturePrivateKey::derive(suite, secret);
    auto cred = Credential::basic({ 0, 1, 2, 3 }, sig_priv.public_key);
    auto kp = KeyPackage{ suite, init_pub, cred, sig_priv, std::nullopt };

    // Correct for non-determinism in the signature algorithm
    kp.signature = secret;

    add_leaf(kp);
  }
};

struct TreeKEMTestVectors
{
  static const std::string file_name;

  struct Bytes1
  {
    bytes data;
    TLS_SERIALIZABLE(data)
    TLS_TRAITS(tls::vector<1>)
  };

  struct TestCase
  {
    CipherSuite cipher_suite;
    std::vector<TreeKEMPublicKey> trees;

    TLS_SERIALIZABLE(cipher_suite, trees)
    TLS_TRAITS(tls::pass, tls::vector<4>)
  };

  std::vector<Bytes1> init_secrets;
  std::vector<Bytes1> leaf_secrets;
  std::vector<TestCase> cases;

  TLS_SERIALIZABLE(init_secrets, leaf_secrets, cases)
  TLS_TRAITS(tls::vector<4>, tls::vector<4>, tls::vector<4>)
};

/////

bool
deterministic_signature_scheme(const CipherSuite& suite);

struct MessagesTestVectors
{
  static const std::string file_name;

  struct TestCase
  {
    CipherSuite cipher_suite;

    bytes key_package;
    bytes update_path;
    bytes group_info;
    bytes group_secrets;
    bytes encrypted_group_secrets;
    bytes welcome;
    bytes add_proposal;
    bytes update_proposal;
    bytes remove_proposal;
    bytes commit;
    bytes ciphertext;

    TLS_SERIALIZABLE(cipher_suite,
                     key_package,
                     update_path,
                     group_info,
                     group_secrets,
                     encrypted_group_secrets,
                     welcome,
                     add_proposal,
                     update_proposal,
                     remove_proposal,
                     commit,
                     ciphertext)
    TLS_TRAITS(tls::pass,
               tls::vector<4>,
               tls::vector<4>,
               tls::vector<4>,
               tls::vector<4>,
               tls::vector<4>,
               tls::vector<4>,
               tls::vector<4>,
               tls::vector<4>,
               tls::vector<4>,
               tls::vector<4>,
               tls::vector<4>)
  };

  epoch_t epoch;
  Sender sender;
  LeafIndex removed;
  bytes user_id;
  bytes group_id;
  bytes key_package_id;
  bytes dh_seed;
  bytes sig_seed;
  bytes random;

  std::vector<TestCase> cases;

  TLS_SERIALIZABLE(epoch,
                   sender,
                   removed,
                   user_id,
                   group_id,
                   key_package_id,
                   dh_seed,
                   sig_seed,
                   random,
                   cases)
  TLS_TRAITS(tls::pass,
             tls::pass,
             tls::pass,
             tls::vector<1>,
             tls::vector<1>,
             tls::vector<1>,
             tls::vector<1>,
             tls::vector<1>,
             tls::vector<1>,
             tls::vector<4>)
};

/////

template<typename T>
struct TestLoader
{
  static const T& get();

private:
  static bool _initialized;
  static T _vectors;
};
