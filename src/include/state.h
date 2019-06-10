#pragma once

#include "crypto.h"
#include "messages.h"
#include "ratchet_tree.h"
#include <optional>
#include <set>
#include <vector>

namespace mls {

// struct {
//   opaque group_id<0..255>;
//   uint32 epoch;
//   opaque tree_hash<0..255>;
//   opaque transcript_hash<0..255>;
// } GroupContext;
struct GroupContext
{
  tls::opaque<1> group_id;
  epoch_t epoch;
  tls::opaque<1> tree_hash;
  tls::opaque<1> transcript_hash;
};

tls::ostream&
operator<<(tls::ostream& out, const GroupContext& obj);
tls::istream&
operator>>(tls::istream& out, GroupContext& obj);

// XXX(rlb@ipv.sx): This is implemented in "const mode", where we
// never ratchet forward the base secret.  This allows for maximal
// out-of-order delivery, but provides no forward secrecy within an
// epoch.
class KeyChain
{
public:
  KeyChain(CipherSuite suite)
    : _suite(suite)
    , _secret_size(Digest(suite).output_size())
    , _key_size(AESGCM::key_size(suite))
    , _nonce_size(AESGCM::nonce_size)
  {}

  struct Generation
  {
    uint32_t generation;
    bytes secret;
    bytes key;
    bytes nonce;
  };

  void start(LeafIndex my_index, const bytes& root_secret);
  Generation next();
  Generation get(LeafIndex sender, uint32_t generation) const;

private:
  CipherSuite _suite;
  LeafIndex _my_sender;
  uint32_t _my_generation;
  bytes _root_secret;

  size_t _secret_size;
  size_t _key_size;
  size_t _nonce_size;

  // XXX(rlb@ipv.sx) Using char* here instead of std::string because
  // the linter complains about static objects and objects with
  // global scope.
  static const char* _secret_label;
  static const char* _nonce_label;
  static const char* _key_label;

  bytes derive(const bytes& secret,
               const std::string& label,
               const bytes& context,
               const size_t size) const;
};

class State
{
public:
  ///
  /// Constructors
  ///

  // Initialize an empty group
  State(bytes group_id,
        CipherSuite suite,
        const bytes& leaf_secret,
        SignaturePrivateKey identity_priv,
        const Credential& credential);

  // Initialize a group from a Add (for group-initiated join)
  State(SignaturePrivateKey identity_priv,
        const Credential& credential,
        const bytes& init_secret,
        const Welcome& welcome_info,
        const MLSPlaintext& handshake);

  // Negotiate an initial state with another peer based on their
  // ClientInitKey
  typedef std::tuple<Welcome, MLSPlaintext, State> InitialInfo;
  static InitialInfo negotiate(
    const bytes& group_id,
    const std::vector<CipherSuite> supported_ciphersuites,
    const bytes& leaf_secret,
    const SignaturePrivateKey& identity_priv,
    const Credential& credential,
    const ClientInitKey& client_init_key);

  ///
  /// Message factories
  ///

  // Generate a Add message
  std::tuple<Welcome, MLSPlaintext, State> add(
    const ClientInitKey& client_init_key) const;

  // Generate an Add message at a specific location
  std::tuple<Welcome, MLSPlaintext, State> add(
    uint32_t index,
    const ClientInitKey& client_init_key) const;

  // Generate an Update message (for post-compromise security)
  std::tuple<MLSPlaintext, State> update(const bytes& leaf_secret);

  // Generate a Remove message (to remove another participant)
  std::tuple<MLSPlaintext, State> remove(const bytes& leaf_secret,
                                         uint32_t index);

  ///
  /// Generic handshake message handler
  ///
  State handle(const MLSPlaintext& handshake) const;

  ///
  /// Accessors
  ///
  epoch_t epoch() const { return _epoch; }
  LeafIndex index() const { return _index; }
  CipherSuite cipher_suite() const { return _suite; }
  bytes epoch_secret() const { return _epoch_secret; }
  bytes application_secret() const { return _application_secret; }
  bytes confirmation_key() const { return _confirmation_key; }
  bytes init_secret() const { return _init_secret; }

  ///
  /// Encryption and decryption
  ///
  MLSCiphertext protect(const bytes& pt);
  bytes unprotect(const MLSCiphertext& ct);

  ///
  /// Static access to the key schedule
  ///
  struct EpochSecrets
  {
    bytes epoch_secret;
    bytes application_secret;
    bytes handshake_secret;
    bytes sender_data_secret;
    bytes confirmation_key;
    bytes init_secret;
  };
  static EpochSecrets derive_epoch_secrets(CipherSuite suite,
                                           const bytes& init_secret,
                                           const bytes& update_secret,
                                           const bytes& state);

private:
  // Shared confirmed state
  // XXX(rlb@ipv.sx): Can these be made const?
  CipherSuite _suite;
  bytes _group_id;
  epoch_t _epoch;
  RatchetTree _tree;
  bytes _confirmed_transcript_hash;
  bytes _interim_transcript_hash;
  bytes _group_context;

  // Shared secret state
  tls::opaque<1> _epoch_secret;
  tls::opaque<1> _sender_data_secret;
  tls::opaque<1> _handshake_secret;
  tls::opaque<1> _application_secret;
  tls::opaque<1> _confirmation_key;
  tls::opaque<1> _init_secret;

  // Message protection keys
  tls::opaque<1> _sender_data_key;
  std::set<LeafIndex> _handshake_key_used;
  KeyChain _application_keys;

  // Per-participant state
  LeafIndex _index;
  SignaturePrivateKey _identity_priv;
  bytes _cached_leaf_secret;

  // A zero vector, for convenience
  bytes _zero;

  // Apply a group operation (without verification)
  State apply(const MLSPlaintext& handshake) const;

  // Handle an Add (for existing participants only)
  bytes handle(const Add& add);

  // Handle an Update (for the participant that sent the update)
  bytes handle(LeafIndex index, const Update& update);

  // Handle a Remove (for the remaining participants, obviously)
  bytes handle(LeafIndex index, const Remove& remove);

  // Compare the **shared** attributes of the states
  friend bool operator==(const State& lhs, const State& rhs);
  friend bool operator!=(const State& lhs, const State& rhs);

  // Generate a WelcomeInfo object describing this state
  WelcomeInfo welcome_info() const;

  // Add a new group operation into the transcript hash
  void update_transcript_hash(const MLSPlaintext& plaintext);

  // Inner logic shared by Update, self-Update, and Remove handlers
  bytes update_leaf(LeafIndex index,
                    const DirectPath& path,
                    const std::optional<bytes>& leaf_secret);

  // Derive the secrets for an epoch, given some new entropy
  void update_epoch_secrets(const bytes& update_secret);

  // Signing of handshake messages (including creation of the
  // confirmation MAC)
  std::tuple<MLSPlaintext, State> sign(const GroupOperation& operation) const;

  // Signature verification over a handshake message
  bool verify(const MLSPlaintext& pt) const;

  // Verification of the confirmation MAC
  bool verify_confirmation(const bytes& confirmation) const;

  // Generate handshake keys
  KeyChain::Generation generate_handshake_keys(const LeafIndex& sender,
                                               bool encrypt);

  // Encrypt and decrypt MLS framed objects
  MLSCiphertext encrypt(const MLSPlaintext& pt);
  MLSPlaintext decrypt(const MLSCiphertext& ct);
};

} // namespace mls
