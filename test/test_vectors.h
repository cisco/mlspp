#include "common.h"
#include "messages.h"
#include "ratchet_tree.h"
#include "session.h"
#include "state.h"
#include "tls_syntax.h"
#include "tree_math.h"
#include <string>

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

  bytes hkdf_extract_salt;
  bytes hkdf_extract_ikm;

  bytes derive_key_pair_seed;

  bytes hpke_aad;
  bytes hpke_plaintext;

  struct TestCase
  {
    CipherSuite cipher_suite;

    // HKDF-Extract
    bytes hkdf_extract_out;

    // Derive-Key-Pair
    HPKEPublicKey derive_key_pair_pub;

    // HPKE
    HPKECiphertext hpke_out;

    TLS_SERIALIZABLE(cipher_suite,
                     hkdf_extract_out,
                     derive_key_pair_pub,
                     hpke_out)
    TLS_TRAITS(tls::pass, tls::vector<1>, tls::pass, tls::pass)
  };

  std::vector<TestCase> cases;

  TLS_SERIALIZABLE(hkdf_extract_salt,
                   hkdf_extract_ikm,
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
    bytes update_secret;

    bytes epoch_secret;

    bytes sender_data_secret;
    bytes sender_data_key;

    bytes handshake_secret;
    std::vector<KeyAndNonce> handshake_keys;

    bytes application_secret;
    std::vector<KeyAndNonce> application_keys;

    bytes confirmation_key;
    bytes init_secret;

    TLS_SERIALIZABLE(n_members,
                     update_secret,
                     epoch_secret,
                     sender_data_secret,
                     sender_data_key,
                     handshake_secret,
                     handshake_keys,
                     application_secret,
                     application_keys,
                     confirmation_key,
                     init_secret);
    TLS_TRAITS(tls::pass,
               tls::vector<1>,
               tls::vector<1>,
               tls::vector<1>,
               tls::vector<1>,
               tls::vector<1>,
               tls::vector<4>,
               tls::vector<1>,
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

  std::vector<TestCase> cases;

  TLS_SERIALIZABLE(n_epochs,
                   target_generation,
                   base_init_secret,
                   base_group_context,
                   cases);
  TLS_TRAITS(tls::pass,
             tls::pass,
             tls::vector<1>,
             tls::vector<4>,
             tls::vector<4>)
};

/////

struct TestTreeKEMPublicKey : public TreeKEMPublicKey
{
  using TreeKEMPublicKey::TreeKEMPublicKey;

  SignatureScheme scheme;

  TestTreeKEMPublicKey(CipherSuite suite_in,
                       SignatureScheme scheme_in,
                       const std::vector<bytes>& secrets)
    : TreeKEMPublicKey(suite_in)
  {
    scheme = scheme_in;

    for (const auto& secret : secrets) {
      add_leaf_secret(secret);
    }

    for (uint32_t i = 0; i < secrets.size() - 1; i += 1) {
      auto secret = secrets[i];
      secret.push_back(0);
      auto pub = HPKEPrivateKey::derive(suite, secret).public_key();
      nodes.at(2 * i + 1).node = Node{ ParentNode{ pub, {}, {} } };
    }
  }

  void add_leaf_secret(const bytes& secret)
  {
    auto init_pub = HPKEPrivateKey::derive(suite, secret).public_key();
    auto sig_priv = SignaturePrivateKey::derive(scheme, secret);
    auto cred = Credential::basic({ 0, 1, 2, 3 }, sig_priv.public_key());
    auto kp = KeyPackage{ suite, init_pub, sig_priv, cred };

    // Correct for non-determinism in the signature algorithm
    kp.signature = secret;

    add_leaf(kp);
  }
};

class TestRatchetTree : public RatchetTree
{
public:
  using RatchetTree::RatchetTree;

  TestRatchetTree(CipherSuite suite,
                  const std::vector<bytes>& secrets,
                  const std::vector<Credential>& creds)
    : RatchetTree(suite)
  {
    if (secrets.size() != creds.size()) {
      throw InvalidParameterError("Incorrect tree initialization data");
    }

    for (uint32_t i = 0; i < secrets.size(); i += 1) {
      auto ix = LeafIndex{ i };
      auto priv = HPKEPrivateKey::derive(suite, secrets[i]);
      add_leaf(ix, priv.public_key(), creds[i]);
      merge(ix, priv);
      encap(ix, {}, secrets[i]);
    }
  }

  const RatchetTreeNodeVector& nodes() const { return _nodes; }

  bool check_credentials() const
  {
    for (LeafIndex i{ 0 }; i.val < size(); i.val += 1) {
      auto& node = _nodes[NodeIndex{ i }];
      if (node.has_value() && !node.value().credential().has_value()) {
        return false;
      }
    }
    return true;
  }

  bool check_invariant(LeafIndex from) const
  {
    std::vector<bool> in_dirpath(_nodes.size(), false);

    // Ensure that we have private keys for everything in the direct
    // path...
    auto dirpath = tree_math::dirpath(NodeIndex{ from }, node_size());
    dirpath.insert(dirpath.begin(), NodeIndex{ from });

    for (const auto& node : dirpath) {
      in_dirpath[node.val] = true;
      if (_nodes[node].has_value() && !_nodes[node].has_private()) {
        return false;
      }
    }

    // ... and nothing else
    for (size_t i = 0; i < _nodes.size(); ++i) {
      if (in_dirpath[i]) {
        continue;
      }

      if (_nodes[i].has_private()) {
        throw std::runtime_error("unexpected private key");
        return false;
      }
    }

    return true;
  }
};

struct TreeTestVectors
{
  static const std::string file_name;

  struct Bytes1
  {
    bytes data;
    TLS_SERIALIZABLE(data)
    TLS_TRAITS(tls::vector<1>)
  };

  struct TreeNode
  {
    std::optional<Bytes1> public_key;
    bytes hash;

    TLS_SERIALIZABLE(public_key, hash)
    TLS_TRAITS(tls::pass, tls::vector<1>)
  };

  struct TreeCase
  {
    std::vector<TreeNode> nodes;
    TLS_SERIALIZABLE(nodes)
    TLS_TRAITS(tls::vector<4>)
  };

  struct TestCase
  {
    CipherSuite cipher_suite;
    SignatureScheme signature_scheme;
    std::vector<Credential> credentials;
    std::vector<TreeCase> trees;

    TLS_SERIALIZABLE(cipher_suite, signature_scheme, credentials, trees)
    TLS_TRAITS(tls::pass, tls::pass, tls::vector<4>, tls::vector<4>)
  };

  std::vector<Bytes1> leaf_secrets;
  std::vector<Credential> credentials;
  std::vector<TestCase> cases;

  TLS_SERIALIZABLE(leaf_secrets, credentials, cases)
  TLS_TRAITS(tls::vector<4>, tls::vector<4>, tls::vector<4>)
};

/////

bool
deterministic_signature_scheme(SignatureScheme scheme);

struct MessagesTestVectors
{
  static const std::string file_name;

  struct TestCase
  {
    CipherSuite cipher_suite;
    SignatureScheme signature_scheme;

    bytes key_package;
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
                     signature_scheme,
                     key_package,
                     group_info,
                     group_secrets,
                     encrypted_group_secrets,
                     welcome,
                     add_proposal,
                     update_proposal,
                     remove_proposal,
                     commit,
                     ciphertext);
    TLS_TRAITS(tls::pass,
               tls::pass,
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
  LeafIndex signer_index;
  LeafIndex removed;
  bytes user_id;
  bytes group_id;
  bytes key_package_id;
  bytes dh_seed;
  bytes sig_seed;
  bytes random;

  std::vector<TestCase> cases;

  TLS_SERIALIZABLE(epoch,
                   signer_index,
                   removed,
                   user_id,
                   group_id,
                   key_package_id,
                   dh_seed,
                   sig_seed,
                   random,
                   cases);
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

namespace mls {

class TestState : public State
{
public:
  TestState(const State& other)
    : State(other)
  {}

  KeyScheduleEpoch keys() const { return _keys; }
};

class TestSession : public Session
{
public:
  using Session::Session;
  TestSession(const Session& other)
    : Session(other)
  {}

  uint32_t index() const { return current_state().index().val; }

  epoch_t current_epoch() const { return _current_epoch; }

  CipherSuite cipher_suite() const { return current_state().cipher_suite(); }

  bytes current_epoch_secret() const
  {
    return TestState(current_state()).keys().epoch_secret;
  }

  bytes current_application_secret() const
  {
    return TestState(current_state()).keys().application_secret;
  }

  bytes current_confirmation_key() const
  {
    return TestState(current_state()).keys().confirmation_key;
  }

  bytes current_init_secret() const
  {
    return TestState(current_state()).keys().init_secret;
  }
};

} // namespace mls

// Splitting the test data from the file definition here allows us
// to have a consistent struct for different scenarios that live in
// different files.
struct SessionTestVectors
{
  struct Epoch
  {
    std::optional<Welcome> welcome;
    bytes handshake;
    bytes commit_secret;

    epoch_t epoch;
    bytes epoch_secret;
    bytes application_secret;
    bytes confirmation_key;
    bytes init_secret;

    Epoch() = default;

    Epoch(const std::optional<Welcome>& welcome_in,
          const bytes& handshake_in,
          const bytes& commit_secret_in,
          const TestSession& session)
      : welcome(welcome_in)
      , handshake(handshake_in)
      , commit_secret(commit_secret_in)
      , epoch(session.current_epoch())
      , epoch_secret(session.current_epoch_secret())
      , application_secret(session.current_application_secret())
      , confirmation_key(session.current_confirmation_key())
      , init_secret(session.current_init_secret())
    {}

    TLS_SERIALIZABLE(welcome,
                     handshake,
                     commit_secret,
                     epoch,
                     epoch_secret,
                     application_secret,
                     confirmation_key,
                     init_secret);
    TLS_TRAITS(tls::pass,
               tls::vector<4>,
               tls::vector<1>,
               tls::pass,
               tls::vector<1>,
               tls::vector<1>,
               tls::vector<1>,
               tls::vector<1>)
  };

  struct TestCase
  {
    CipherSuite cipher_suite;
    SignatureScheme signature_scheme;
    bool encrypt;
    std::vector<KeyPackage> key_packages;
    std::vector<Epoch> transcript;

    TLS_SERIALIZABLE(cipher_suite,
                     signature_scheme,
                     encrypt,
                     key_packages,
                     transcript);
    TLS_TRAITS(tls::pass, tls::pass, tls::pass, tls::vector<4>, tls::vector<4>)
  };

  uint32_t group_size;
  bytes group_id;

  std::vector<TestCase> cases;

  TLS_SERIALIZABLE(group_size, group_id, cases)
  TLS_TRAITS(tls::pass, tls::vector<1>, tls::vector<4>)
};

struct BasicSessionTestVectors : SessionTestVectors
{
  static const std::string file_name;
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
