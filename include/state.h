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
  static std::tuple<Welcome, State> negotiate(
    const bytes& group_id,
    const std::vector<ClientInitKey>& my_client_init_keys,
    const std::vector<ClientInitKey>& client_init_keys,
    const bytes& commit_secret);

  ///
  /// Message factories
  ///

  MLSPlaintext add(const ClientInitKey& client_init_key) const;
  MLSPlaintext update(const bytes& leaf_secret);
  MLSPlaintext remove(LeafIndex removed) const;

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
  ratchet_and_sign(const Commit& op, const bytes& update_secret);

  // Create an MLSPlaintext with a signature over some content
  MLSPlaintext sign(const Proposal& proposal) const;

  // Apply the changes requested by various messages
  void apply(const Add& add);
  void apply(LeafIndex target, const Update& update);
  void apply(LeafIndex target, const bytes& leaf_secret);
  void apply(const Remove& remove);
  void apply(const std::vector<ProposalID>& ids);
  void apply(const Commit& commit);

  // Compute a proposal ID
  bytes proposal_id(const MLSPlaintext& pt) const;

  // Extract a proposal from the cache
  std::optional<MLSPlaintext> find_proposal(const ProposalID& id);

  // Compare the **shared** attributes of the states
  friend bool operator==(const State& lhs, const State& rhs);
  friend bool operator!=(const State& lhs, const State& rhs);

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
