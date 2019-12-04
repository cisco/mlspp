#pragma once

#include "crypto.h"
#include "messages.h"
#include "ratchet_tree.h"
#include <optional>
#include <set>
#include <vector>
#include <list>

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

  TLS_SERIALIZABLE(group_id, epoch, tree_hash, transcript_hash)
};

// XXX(rlb@ipv.sx): This is implemented in "const mode", where we
// never ratchet forward the base secret.  This allows for maximal
// out-of-order delivery, but provides no forward secrecy within an
// epoch.
class KeyChain
{
public:
  KeyChain(CipherSuite suite);

  struct Generation
  {
    uint32_t generation;
    bytes secret;
    bytes key;
    bytes nonce;
  };

  void start(LeafIndex my_sender, const bytes& root_secret);
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
        const DHPrivateKey& leaf_priv,
        const Credential& credential);

  // Initialize a group from a Welcome
  State(const std::vector<ClientInitKey>& my_client_init_keys,
        const Welcome& welcome);

  // Negotiate an initial state with another peer based on their
  // ClientInitKey
  static std::tuple<Welcome, MLSPlaintext, State> negotiate(
    const bytes& group_id,
    const std::vector<ClientInitKey>& my_client_init_keys,
    const std::vector<ClientInitKey>& client_init_keys);

  ///
  /// Message factories
  ///

  // Generate a Add message
  std::tuple<Welcome, MLSPlaintext, State> add(
    const ClientInitKey& client_init_key) const;

  // Generate an Add message at a specific location
  std::tuple<Welcome, MLSPlaintext, State> add(
    LeafIndex index,
    const ClientInitKey& client_init_key) const;

  // Generate an Update message (for post-compromise security)
  std::tuple<MLSPlaintext, State> update(const bytes& leaf_secret) const;

  // Generate a Remove message (to remove another participant)
  std::tuple<MLSPlaintext, State> remove(const bytes& leaf_secret,
                                         LeafIndex index) const;

  // Generate an Add proposal
  MLSPlaintext propose_add(const ClientInitKey& client_init_key) const;

  // Generate an Update proposal
  MLSPlaintext propose_update(const bytes& leaf_secret);

  // Generate a Remove proposal
  MLSPlaintext propose_remove(LeafIndex removed) const;

  // Generate a Commit
  std::tuple<MLSPlaintext, Welcome, State> commit(const bytes& leaf_secret) const;

  ///
  /// Generic handshake message handler
  ///
  std::optional<State> handle(const MLSPlaintext& pt);

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
  static bytes next_epoch_secret(CipherSuite suite,
                                 const bytes& init_secret,
                                 const bytes& update_secret);
  static EpochSecrets derive_epoch_secrets(CipherSuite suite,
                                           const bytes& epoch_secret,
                                           const GroupContext& group_context);

private:
  // Shared confirmed state
  // XXX(rlb@ipv.sx): Can these be made const?
  CipherSuite _suite;
  bytes _group_id;
  epoch_t _epoch;
  RatchetTree _tree;
  bytes _confirmed_transcript_hash;
  bytes _interim_transcript_hash;

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

  // Cache of Proposals and update secrets
  std::list<MLSPlaintext> _pending_proposals;
  std::map<ProposalID, bytes> _update_secrets;

  // A zero vector, for convenience
  bytes _zero;

  // Ratchet the key schedule forward and sign the commit that caused the
  // transition
  MLSPlaintext
  ratchet_and_sign_commit(const Commit& op, const bytes& update_secret);

  // Ratchet the key schedule forward and sign the operation that
  // caused the transition
  MLSPlaintext ratchet_and_sign(const GroupOperation& op,
                                const bytes& update_secret);

  // Create an MLSPlaintext with a signature over some content
  MLSPlaintext sign_proposal(const Proposal& proposal) const;

  // Handle an Add (for existing participants only)
  bytes handle(LeafIndex sender, const Add& add);

  // Handle an Update (for the participant that sent the update)
  bytes handle(LeafIndex sender, const Update& update);

  // Handle a Remove (for the remaining participants, obviously)
  bytes handle(LeafIndex sender, const Remove& remove);

  // Handle a Handshake message
  State handle_handshake(const MLSPlaintext& handshake) const;

  // Apply an Add
  void apply(const AddProposal& add);

  // Apply an Update
  void apply(LeafIndex target, const UpdateProposal& update);

  // Apply a self-Update
  void apply(LeafIndex target, const bytes& leaf_secret);

  // Apply a Remove
  void apply(const RemoveProposal& remove);

  // Compute a proposal ID
  bytes proposal_id(const MLSPlaintext& pt) const;

  // Extract a proposal from the cache
  std::optional<MLSPlaintext> find_proposal(const ProposalID& id);

  // Apply a list of proposals, by ID
  void apply(const std::vector<ProposalID>& ids);

  // Apply a Commit
  void apply(const Commit& commit);

  // Compare the **shared** attributes of the states
  friend bool operator==(const State& lhs, const State& rhs);
  friend bool operator!=(const State& lhs, const State& rhs);

  // Construct the group context
  GroupContext group_context() const;

  // Add a new group operation into the transcript hash
  void update_transcript_hash(const MLSPlaintext& plaintext);

  // Inner logic shared by Update, self-Update, and Remove handlers
  bytes update_leaf(LeafIndex index,
                    const DirectPath& path,
                    const std::optional<bytes>& leaf_secret);

  // Derive and set the secrets for an epoch, given some new entropy
  void update_epoch_secrets(const bytes& update_secret);

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
