#pragma once

#include "mls/crypto.h"
#include "mls/key_schedule.h"
#include "mls/messages.h"
#include "mls/treekem.h"
#include <list>
#include <optional>
#include <set>
#include <vector>

namespace mls {

// struct {
//     opaque group_id<0..255>;
//     uint64 epoch;
//     opaque tree_hash<0..255>;
//     opaque confirmed_transcript_hash<0..255>;
//     Extension extensions<0..2^16-1>;
// } GroupContext;
struct GroupContext
{
  bytes group_id;
  epoch_t epoch;
  bytes tree_hash;
  bytes confirmed_transcript_hash;
  ExtensionList extensions;

  TLS_SERIALIZABLE(group_id,
                   epoch,
                   tree_hash,
                   confirmed_transcript_hash,
                   extensions)
  TLS_TRAITS(tls::vector<1>,
             tls::pass,
             tls::vector<1>,
             tls::vector<1>,
             tls::pass)
};

// Index into the session roster
struct RosterIndex : public UInt32
{
  using UInt32::UInt32;
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
        const HPKEPrivateKey& init_priv,
        SignaturePrivateKey sig_priv,
        const KeyPackage& key_package);

  // Initialize a group from a Welcome
  State(const HPKEPrivateKey& init_priv,
        SignaturePrivateKey sig_priv,
        const KeyPackage& kp,
        const Welcome& welcome);

  ///
  /// Message factories
  ///

  MLSPlaintext add(const KeyPackage& key_package) const;
  MLSPlaintext update(const bytes& leaf_secret);
  MLSPlaintext remove(RosterIndex index) const;
  MLSPlaintext remove(LeafIndex removed) const;

  std::tuple<MLSPlaintext, Welcome, State> commit(
    const bytes& leaf_secret) const;

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
  bytes do_export(const std::string& label,
                  const bytes& context,
                  size_t size) const;
  // Ordered list of credentials from non-blank leaves
  std::vector<KeyPackage> roster() const;

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
  TreeKEMPublicKey _tree;
  TreeKEMPrivateKey _tree_priv;
  bytes _confirmed_transcript_hash;
  bytes _interim_transcript_hash;
  ExtensionList _extensions;

  // Shared secret state
  KeyScheduleEpoch _keys;

  // Per-participant state
  LeafIndex _index;
  SignaturePrivateKey _identity_priv;

  // Cache of Proposals and update secrets
  std::list<MLSPlaintext> _pending_proposals;
  std::map<bytes, bytes> _update_secrets;

  // Assemble a group context for this state
  GroupContext group_context() const;

  // Ratchet the key schedule forward and sign the commit that caused the
  // transition
  MLSPlaintext ratchet_and_sign(const Commit& op,
                                const bytes& update_secret,
                                const GroupContext& prev_ctx);

  // Create an MLSPlaintext with a signature over some content
  MLSPlaintext sign(const Proposal& proposal) const;

  // Apply the changes requested by various messages
  LeafIndex apply(const Add& add);
  void apply(LeafIndex target, const Update& update);
  void apply(LeafIndex target, const Update& update, const bytes& leaf_secret);
  void apply(const Remove& remove);
  std::vector<LeafIndex> apply(const std::vector<MLSPlaintext>& pts,
                               ProposalType::selector required_type);
  std::tuple<bool, bool, std::vector<LeafIndex>> apply(const Commit& commit);

  // Compute a proposal ID
  ProposalID proposal_id(const MLSPlaintext& pt) const;

  // Extract a proposal from the cache
  std::optional<MLSPlaintext> find_proposal(const ProposalID& id);

  // Compare the **shared** attributes of the states
  friend bool operator==(const State& lhs, const State& rhs);
  friend bool operator!=(const State& lhs, const State& rhs);

  // Derive and set the secrets for an epoch, given some new entropy
  void update_epoch_secrets(const bytes& commit_secret);

  // Signature verification over a handshake message
  bool verify(const MLSPlaintext& pt) const;

  // Verification of the confirmation MAC
  bool verify_confirmation(const bytes& confirmation) const;

  // Convert a Roster entry into LeafIndex
  LeafIndex leaf_for_roster_entry(RosterIndex index) const;
};

} // namespace mls
