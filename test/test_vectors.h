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

struct ResolutionTestVectors
{
  static const std::string file_name;

  typedef tls::vector<uint8_t, 1> Resolution;
  typedef tls::vector<Resolution, 2> ResolutionCase;

  static std::vector<bool> make_tree(uint32_t t, NodeCount w);
  static std::vector<uint8_t> compact(const std::vector<NodeIndex>& res);

  LeafCount n_leaves;
  tls::vector<ResolutionCase, 4> cases;

  TLS_SERIALIZABLE(n_leaves, cases)
};

/////

struct CryptoTestVectors
{
  static const std::string file_name;

  tls::opaque<1> hkdf_extract_salt;
  tls::opaque<1> hkdf_extract_ikm;

  tls::opaque<1> derive_secret_secret;
  tls::opaque<1> derive_secret_label;
  tls::opaque<1> derive_secret_context;

  tls::opaque<1> derive_key_pair_seed;

  tls::opaque<1> ecies_aad;
  tls::opaque<1> ecies_plaintext;

  struct TestCase
  {
    // HKDF-Extract
    tls::opaque<1> hkdf_extract_out;

    // Derive-Secret
    tls::opaque<1> derive_secret_out;

    // Derive-Key-Pair
    DHPublicKey derive_key_pair_pub;

    // HPKE
    HPKECiphertext ecies_out;

    TestCase(CipherSuite suite)
      : derive_key_pair_pub(suite)
      , ecies_out(suite)
    {}

    TLS_SERIALIZABLE(hkdf_extract_out,
                     derive_secret_out,
                     derive_key_pair_pub,
                     ecies_out)
  };

  CryptoTestVectors()
    : case_p256(CipherSuite::P256_SHA256_AES128GCM)
    , case_x25519(CipherSuite::X25519_SHA256_AES128GCM)
  {}

  TestCase case_p256;
  TestCase case_x25519;

  TLS_SERIALIZABLE(hkdf_extract_salt,
                   hkdf_extract_ikm,
                   derive_secret_secret,
                   derive_secret_label,
                   derive_secret_context,
                   derive_key_pair_seed,
                   ecies_aad,
                   ecies_plaintext,
                   case_p256,
                   case_x25519)
};

/////

struct KeyScheduleTestVectors
{
  static const std::string file_name;

  struct Epoch
  {
    tls::opaque<1> update_secret;

    tls::opaque<1> epoch_secret;
    tls::opaque<1> application_secret;
    tls::opaque<1> confirmation_key;
    tls::opaque<1> init_secret;

    TLS_SERIALIZABLE(update_secret,
                     epoch_secret,
                     application_secret,
                     confirmation_key,
                     init_secret);
  };

  struct TestCase
  {
    CipherSuite suite;
    tls::vector<Epoch, 2> epochs;

    TLS_SERIALIZABLE(suite, epochs);
  };

  uint32_t n_epochs;
  tls::opaque<4> base_group_context;

  TestCase case_p256;
  TestCase case_x25519;

  TLS_SERIALIZABLE(n_epochs, base_group_context, case_p256, case_x25519);
};

/////

struct AppKeyScheduleTestVectors
{
  static const std::string file_name;

  struct Step
  {
    tls::opaque<1> secret;
    tls::opaque<1> key;
    tls::opaque<1> nonce;

    TLS_SERIALIZABLE(secret, key, nonce);
  };

  typedef tls::vector<Step, 4> KeySequence;
  typedef tls::vector<KeySequence, 4> TestCase;

  uint32_t n_members;
  uint32_t n_generations;
  tls::opaque<1> application_secret;

  TestCase case_p256;
  TestCase case_x25519;

  TLS_SERIALIZABLE(n_members,
                   n_generations,
                   application_secret,
                   case_p256,
                   case_x25519);
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
    tls::vector<Credential, 4> credentials;
    tls::vector<TreeCase, 4> trees;

    TLS_SERIALIZABLE(credentials, trees);
  };

  tls::vector<tls::opaque<1>, 4> leaf_secrets;
  tls::vector<Credential, 4> credentials;
  TestCase case_p256_p256;
  TestCase case_x25519_ed25519;

  TLS_SERIALIZABLE(leaf_secrets,
                   credentials,
                   case_p256_p256,
                   case_x25519_ed25519);
};

/////

struct MessagesTestVectors
{
  static const std::string file_name;

  struct TestCase
  {
    CipherSuite cipher_suite;
    SignatureScheme sig_scheme;

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
                     sig_scheme,
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

  TestCase case_p256_p256;
  TestCase case_x25519_ed25519;

  TLS_SERIALIZABLE(epoch,
                   signer_index,
                   removed,
                   user_id,
                   group_id,
                   client_init_key_id,
                   dh_seed,
                   sig_seed,
                   random,
                   case_p256_p256,
                   case_x25519_ed25519);
};

/////

namespace mls {

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

  bytes current_epoch_secret() const { return current_state().epoch_secret(); }

  bytes current_application_secret() const
  {
    return current_state().application_secret();
  }

  bytes current_confirmation_key() const
  {
    return current_state().confirmation_key();
  }

  bytes current_init_secret() const { return current_state().init_secret(); }
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
    SignatureScheme sig_scheme;
    tls::vector<ClientInitKey, 4> client_init_keys;
    tls::vector<Epoch, 4> transcript;

    TLS_SERIALIZABLE(cipher_suite, sig_scheme, client_init_keys, transcript);
  };

  uint32_t group_size;
  tls::opaque<1> group_id;

  TestCase case_p256_p256;
  TestCase case_x25519_ed25519;

  TLS_SERIALIZABLE(group_size, group_id, case_p256_p256, case_x25519_ed25519);
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
