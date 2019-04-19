#pragma once

#include "crypto.h"
#include "messages.h"
#include "ratchet_tree.h"
#include "roster.h"
#include <optional>
#include <vector>

namespace mls {

// struct {
//   opaque group_id<0..255>;
//   uint32 epoch;
//   optional<Credential> roster<1..2^32-1>;
//   optional<PublicKey> tree<1..2^32-1>;
//   opaque transcript_hash<0..255>;
// } GroupState;
struct GroupState
{
  tls::opaque<1> group_id;
  uint32_t epoch;
  Roster roster;
  RatchetTree tree;
  tls::opaque<1> transcript_hash;

  GroupState(const bytes& group_id,
             CipherSuite suite,
             const bytes& leaf_secret,
             const Credential& credential);

  GroupState(const WelcomeInfo& info);

  GroupState(CipherSuite suite);

  friend tls::ostream& operator<<(tls::ostream& out, const GroupState& obj);
  friend tls::istream& operator>>(tls::istream& out, GroupState& obj);
  friend bool operator==(const GroupState& lhs, const GroupState& rhs);
};

// XXX(rlb@ipv.sx): This is implemented in "const mode", where we
// never ratchet forward the base secret.  This allows for maximal
// out-of-order delivery, but provides no forward secrecy within an
// epoch.
class ApplicationKeyChain
{
public:
  ApplicationKeyChain(CipherSuite suite,
                      uint32_t sender,
                      const bytes& app_secret)
    : _suite(suite)
    , _sender(tls::marshal(sender))
    , _secret_size(Digest(suite).output_size())
    , _key_size(AESGCM::key_size(suite))
    , _nonce_size(AESGCM::nonce_size)
  {
    _base_secret = derive(app_secret, _secret_label, _secret_size);
  }

  struct KeyAndNonce
  {
    bytes secret;
    bytes key;
    bytes nonce;
  };

  KeyAndNonce get(uint32_t generation) const;

private:
  CipherSuite _suite;
  bytes _sender;
  bytes _base_secret;

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
               const size_t size) const;
};

class State
{
public:
  ///
  /// Constructors
  ///

  // Initialize an empty group
  State(const bytes& group_id,
        CipherSuite suite,
        const bytes& leaf_secret,
        SignaturePrivateKey identity_priv,
        const Credential& credential);

  // Initialize a group from a Add (for group-initiated join)
  State(SignaturePrivateKey identity_priv,
        const Credential& credential,
        const bytes& init_secret,
        const Welcome& welcome_info,
        const Handshake& handshake);

  // Negotiate an initial state with another peer based on their
  // UserInitKey
  typedef std::pair<State, std::pair<Welcome, Handshake>> InitialInfo;
  static InitialInfo negotiate(
    const bytes& group_id,
    const std::vector<CipherSuite> supported_ciphersuites,
    const bytes& leaf_secret,
    const SignaturePrivateKey& identity_priv,
    const Credential& credential,
    const UserInitKey& user_init_key);

  ///
  /// Message factories
  ///

  // Generate a Add message
  std::pair<Welcome, Handshake> add(const UserInitKey& user_init_key) const;

  // Generate an Add message at a specific location
  std::pair<Welcome, Handshake> add(uint32_t index,
                                    const UserInitKey& user_init_key) const;

  // Generate an Update message (for post-compromise security)
  Handshake update(const bytes& leaf_secret);

  // Generate a Remove message (to remove another participant)
  Handshake remove(const bytes& evict_secret, uint32_t index) const;

  ///
  /// Generic handshake message handler
  ///
  State handle(const Handshake& handshake) const;

  ///
  /// Accessors
  ///
  epoch_t epoch() const { return _state.epoch; }
  LeafIndex index() const { return _index; }
  CipherSuite cipher_suite() const { return _suite; }
  bytes epoch_secret() const { return _epoch_secret; }
  bytes application_secret() const { return _application_secret; }
  bytes confirmation_key() const { return _confirmation_key; }
  bytes init_secret() const { return _init_secret; }

  ///
  /// Static access to the key schedule
  ///
  struct EpochSecrets
  {
    bytes epoch_secret;
    bytes application_secret;
    bytes confirmation_key;
    bytes init_secret;
  };
  static EpochSecrets derive_epoch_secrets(CipherSuite suite,
                                           const bytes& init_secret,
                                           const bytes& update_secret,
                                           const GroupState& state);

private:
  // Shared confirmed state:
  CipherSuite _suite;
  GroupState _state;

  // Shared secret state
  tls::opaque<1> _epoch_secret;
  tls::opaque<1> _application_secret;
  tls::opaque<1> _confirmation_key;
  tls::opaque<1> _init_secret;

  // Per-participant state
  LeafIndex _index;
  SignaturePrivateKey _identity_priv;
  bytes _cached_leaf_secret;

  // A zero vector, for convenience
  bytes _zero;

  // Specific operation handlers
  State handle(LeafIndex signer_index, const GroupOperation& operation) const;

  // Handle a Add (for existing participants only)
  bytes handle(const Add& add);

  // Handle an Update (for the participant that sent the update)
  bytes handle(LeafIndex index, const Update& update);

  // Handle a Remove (for the remaining participants, obviously)
  bytes handle(const Remove& remove);

  // Compare the **shared** attributes of the states
  friend bool operator==(const State& lhs, const State& rhs);
  friend bool operator!=(const State& lhs, const State& rhs);

  // Generate a WelcomeInfo object describing this state
  WelcomeInfo welcome_info() const;

  // Add a new group operation into the transcript hash
  void update_transcript_hash(const GroupOperation& operation);

  // Inner logic shared by Update, self-Update, and Remove handlers
  bytes update_leaf(LeafIndex index,
                    const DirectPath& path,
                    const std::optional<bytes>& leaf_secret);

  // Derive the secrets for an epoch, given some new entropy
  void update_epoch_secrets(const bytes& update_secret);

  // Sign this state with the associated private key
  Handshake sign(const GroupOperation& operation) const;

  // Verify this state with the indicated public key
  bool verify(const Handshake& handshake) const;
};

} // namespace mls
