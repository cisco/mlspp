#include "common.h"
#include "messages.h"
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

  LeafCount n_leaves{ 255 };
  tls::vector<NodeIndex, 4> root;
  tls::vector<NodeIndex, 4> left;
  tls::vector<NodeIndex, 4> right;
  tls::vector<NodeIndex, 4> parent;
  tls::vector<NodeIndex, 4> sibling;

  TLS_SERIALIZABLE(n_leaves, root, left, right, parent, sibling)
};

/////

struct CryptoTestVectors
{
  static const std::string file_name;

  tls::opaque<1> hkdf_extract_salt;
  tls::opaque<1> hkdf_extract_ikm;

  tls::opaque<1> derive_key_pair_seed;

  tls::opaque<1> hpke_aad;
  tls::opaque<1> hpke_plaintext;

  struct TestCase
  {
    CipherSuite cipher_suite;

    // HKDF-Extract
    tls::opaque<1> hkdf_extract_out;

    // Derive-Key-Pair
    HPKEPublicKey derive_key_pair_pub;

    // HPKE
    HPKECiphertext hpke_out;

    TLS_SERIALIZABLE(cipher_suite,
                     hkdf_extract_out,
                     derive_key_pair_pub,
                     hpke_out)
  };

  tls::vector<TestCase, 4> cases;

  TLS_SERIALIZABLE(hkdf_extract_salt,
                   hkdf_extract_ikm,
                   derive_key_pair_seed,
                   hpke_aad,
                   hpke_plaintext,
                   cases)
};

/////

struct HashRatchetTestVectors
{
  static const std::string file_name;

  struct Step
  {
    tls::opaque<1> key;
    tls::opaque<1> nonce;

    TLS_SERIALIZABLE(key, nonce);
  };

  typedef tls::vector<Step, 4> KeySequence;

  struct TestCase
  {
    CipherSuite cipher_suite;
    tls::vector<KeySequence, 4> key_sequences;

    TLS_SERIALIZABLE(cipher_suite, key_sequences);
  };

  uint32_t n_members;
  uint32_t n_generations;
  tls::opaque<1> base_secret;

  tls::vector<TestCase, 4> cases;

  TLS_SERIALIZABLE(n_members, n_generations, base_secret, cases);
};

/////

struct KeyScheduleTestVectors
{
  static const std::string file_name;

  struct KeyAndNonce
  {
    tls::opaque<1> key;
    tls::opaque<1> nonce;

    TLS_SERIALIZABLE(key, nonce);
  };

  struct Epoch
  {
    LeafCount n_members;
    tls::opaque<1> update_secret;

    tls::opaque<1> epoch_secret;

    tls::opaque<1> sender_data_secret;
    tls::opaque<1> sender_data_key;

    tls::opaque<1> handshake_secret;
    tls::vector<KeyAndNonce, 4> handshake_keys;

    tls::opaque<1> application_secret;
    tls::vector<KeyAndNonce, 4> application_keys;

    tls::opaque<1> confirmation_key;
    tls::opaque<1> init_secret;

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
  };

  struct TestCase
  {
    CipherSuite cipher_suite;
    tls::vector<Epoch, 2> epochs;

    TLS_SERIALIZABLE(cipher_suite, epochs);
  };

  uint32_t n_epochs;
  uint32_t target_generation;
  tls::opaque<1> base_init_secret;
  tls::opaque<4> base_group_context;

  tls::vector<TestCase, 4> cases;

  TLS_SERIALIZABLE(n_epochs,
                   target_generation,
                   base_init_secret,
                   base_group_context,
                   cases);
};

/////

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
    dirpath.push_back(root_index());
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

  struct TreeNode
  {
    tls::optional<tls::opaque<1>> public_key;
    tls::opaque<1> hash;

    TLS_SERIALIZABLE(public_key, hash);
  };

  typedef tls::vector<TreeNode, 4> TreeCase;

  struct TestCase
  {
    CipherSuite cipher_suite;
    SignatureScheme signature_scheme;
    tls::vector<Credential, 4> credentials;
    tls::vector<TreeCase, 4> trees;

    TLS_SERIALIZABLE(cipher_suite, signature_scheme, credentials, trees);
  };

  tls::vector<tls::opaque<1>, 4> leaf_secrets;
  tls::vector<Credential, 4> credentials;
  tls::vector<TestCase, 4> cases;

  TLS_SERIALIZABLE(leaf_secrets, credentials, cases);
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

    tls::opaque<4> client_init_key;
    tls::opaque<4> group_info;
    tls::opaque<4> key_package;
    tls::opaque<4> encrypted_key_package;
    tls::opaque<4> welcome;
    tls::opaque<4> add_proposal;
    tls::opaque<4> update_proposal;
    tls::opaque<4> remove_proposal;
    tls::opaque<4> commit;
    tls::opaque<4> ciphertext;

    TLS_SERIALIZABLE(cipher_suite,
                     signature_scheme,
                     client_init_key,
                     group_info,
                     key_package,
                     encrypted_key_package,
                     welcome,
                     add_proposal,
                     update_proposal,
                     remove_proposal,
                     commit,
                     ciphertext);
  };

  epoch_t epoch;
  LeafIndex signer_index;
  LeafIndex removed;
  tls::opaque<1> user_id;
  tls::opaque<1> group_id;
  tls::opaque<1> client_init_key_id;
  tls::opaque<1> dh_seed;
  tls::opaque<1> sig_seed;
  tls::opaque<1> random;

  tls::vector<TestCase, 4> cases;

  TLS_SERIALIZABLE(epoch,
                   signer_index,
                   removed,
                   user_id,
                   group_id,
                   client_init_key_id,
                   dh_seed,
                   sig_seed,
                   random,
                   cases);
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
    tls::optional<Welcome> welcome;
    tls::opaque<4> handshake;
    tls::opaque<1> commit_secret;

    epoch_t epoch;
    tls::opaque<1> epoch_secret;
    tls::opaque<1> application_secret;
    tls::opaque<1> confirmation_key;
    tls::opaque<1> init_secret;

    Epoch() = default;

    Epoch(const tls::optional<Welcome>& welcome_in,
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
  };

  struct TestCase
  {
    CipherSuite cipher_suite;
    SignatureScheme signature_scheme;
    bool encrypt;
    tls::vector<ClientInitKey, 4> client_init_keys;
    tls::vector<Epoch, 4> transcript;

    TLS_SERIALIZABLE(cipher_suite,
                     signature_scheme,
                     encrypt,
                     client_init_keys,
                     transcript);
  };

  uint32_t group_size;
  tls::opaque<1> group_id;

  tls::vector<TestCase, 4> cases;

  TLS_SERIALIZABLE(group_size, group_id, cases);
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
