#pragma once

#include "crypto.h"
#include "messages.h"
#include "key_schedule.h"
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
  tls::opaque<1> confirmed_transcript_hash;

  TLS_SERIALIZABLE(group_id, epoch, tree_hash, confirmed_transcript_hash)
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
        const HPKEPrivateKey& leaf_priv,
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

  ///
  /// General encryption and decryption
  ///
  MLSCiphertext encrypt(const MLSPlaintext& pt);
  MLSPlaintext decrypt(const MLSCiphertext& ct);

  ///
  /// Application encryption and decryption
  ///
  MLSCiphertext protect(const bytes& pt);
  bytes unprotect(const MLSCiphertext& ct);

protected:
  // Shared confirmed state
  // XXX(rlb@ipv.sx): Can these be made const?
  CipherSuite _suite;
  bytes _group_id;
  epoch_t _epoch;
  RatchetTree _tree;
  bytes _confirmed_transcript_hash;
  bytes _interim_transcript_hash;

  // Shared secret state
  KeyScheduleEpoch _keys;

  // Per-participant state
  LeafIndex _index;
  SignaturePrivateKey _identity_priv;

  // Cache of Proposals and update secrets
  std::list<MLSPlaintext> _pending_proposals;
  std::map<ProposalID, bytes> _update_secrets;

  // Assemble a group context for this state
  GroupContext group_context() const;

  // Ratchet the key schedule forward and sign the commit that caused the
  // transition
  MLSPlaintext
  ratchet_and_sign(const Commit& op, const bytes& update_secret, const GroupContext& prev_ctx);

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
};

} // namespace mls
