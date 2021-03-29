#pragma once

#include "mls/crypto.h"
#include "mls/key_schedule.h"
#include "mls/messages.h"
#include "mls/treekem.h"
#include <list>
#include <optional>
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

struct CommitOpts
{
  std::vector<Proposal> extra_proposals;
  bool inline_tree;
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
        const KeyPackage& key_package,
        ExtensionList extensions);

  // Initialize a group from a Welcome
  State(const HPKEPrivateKey& init_priv,
        SignaturePrivateKey sig_priv,
        const KeyPackage& kp,
        const Welcome& welcome,
        const std::optional<TreeKEMPublicKey>& tree);

  // Join a group from outside
  // XXX(RLB) For full generality, this should be capable of covering other
  // proposals, and would need to return a Welcome as well as an MLSPlaintext,
  // to cover any additional participants added in the Commit.
  static std::tuple<MLSPlaintext, State> external_join(
    const bytes& leaf_secret,
    SignaturePrivateKey sig_priv,
    const KeyPackage& kp,
    const PublicGroupState& pgs,
    const std::optional<TreeKEMPublicKey>& tree);

  ///
  /// Message factories
  ///

  Proposal add_proposal(const KeyPackage& key_package) const;
  Proposal update_proposal(const bytes& leaf_secret);
  Proposal remove_proposal(RosterIndex index) const;
  Proposal remove_proposal(LeafIndex removed) const;

  MLSPlaintext add(const KeyPackage& key_package) const;
  MLSPlaintext update(const bytes& leaf_secret);
  MLSPlaintext remove(RosterIndex index) const;
  MLSPlaintext remove(LeafIndex removed) const;

  std::tuple<MLSPlaintext, Welcome, State> commit(
    const bytes& leaf_secret,
    const std::optional<CommitOpts>& opts) const;

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
  const ExtensionList& extensions() const { return _extensions; }
  const TreeKEMPublicKey& tree() const { return _tree; }

  bytes do_export(const std::string& label,
                  const bytes& context,
                  size_t size) const;
  PublicGroupState public_group_state() const;

  // Ordered list of credentials from non-blank leaves
  std::vector<KeyPackage> roster() const;

  bytes authentication_secret() const;

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
  TranscriptHash _transcript_hash;
  ExtensionList _extensions;

  // Shared secret state
  KeyScheduleEpoch _key_schedule;
  GroupKeySource _keys;

  // Per-participant state
  LeafIndex _index;
  SignaturePrivateKey _identity_priv;

  // Cache of Proposals and update secrets
  struct CachedProposal
  {
    bytes ref;
    Proposal proposal;
    LeafIndex sender;
  };
  std::list<CachedProposal> _pending_proposals;
  std::map<bytes, bytes> _update_secrets;

  // Assemble a group context for this state
  GroupContext group_context() const;

  // Assemble a preliminary, unjoined group state
  State(SignaturePrivateKey sig_priv,
        const PublicGroupState& pgs,
        const std::optional<TreeKEMPublicKey>& tree);

  // Import a tree from an externally-provided tree or an extension
  TreeKEMPublicKey import_tree(const bytes& tree_hash,
                               const std::optional<TreeKEMPublicKey>& external,
                               const ExtensionList& extensions);

  // Form a commit that can be either internal or external
  std::tuple<MLSPlaintext, Welcome, State> commit(
    const bytes& leaf_secret,
    const std::optional<CommitOpts>& opts,
    const std::optional<KeyPackage>& joiner_key_package,
    const std::optional<HPKEPublicKey>& external_pub) const;

  // Ratchet the key schedule forward and sign the commit that caused the
  // transition
  MLSPlaintext ratchet_and_sign(const Sender& sender,
                                const Commit& op,
                                const bytes& update_secret,
                                const std::optional<bytes>& force_init_secret,
                                const GroupContext& prev_ctx);

  // Create an MLSPlaintext with a signature over some content
  MLSPlaintext sign(const Proposal& proposal) const;

  // Apply the changes requested by various messages
  LeafIndex apply(const Add& add);
  void apply(LeafIndex target, const Update& update);
  void apply(LeafIndex target, const Update& update, const bytes& leaf_secret);
  void apply(const Remove& remove);
  std::vector<LeafIndex> apply(const std::vector<CachedProposal>& proposals,
                               ProposalType required_type);
  std::tuple<bool, bool, std::vector<LeafIndex>> apply(
    const std::vector<CachedProposal>& proposals);

  // Extract a proposal from the cache
  void cache_proposal(const MLSPlaintext& pt);
  std::optional<CachedProposal> resolve(const ProposalOrRef& id,
                                        LeafIndex sender_index) const;
  std::vector<CachedProposal> must_resolve(
    const std::vector<ProposalOrRef>& ids,
    LeafIndex sender_index) const;

  // Compare the **shared** attributes of the states
  friend bool operator==(const State& lhs, const State& rhs);
  friend bool operator!=(const State& lhs, const State& rhs);

  // Derive and set the secrets for an epoch, given some new entropy
  void update_epoch_secrets(const bytes& commit_secret,
                            const std::optional<bytes>& force_init_secret);

  // Signature verification over a handshake message
  bool verify_internal(const MLSPlaintext& pt) const;
  bool verify_external_commit(const MLSPlaintext& pt) const;
  bool verify(const MLSPlaintext& pt) const;

  // Verification of the confirmation MAC
  bool verify_confirmation(const bytes& confirmation) const;

  // Convert a Roster entry into LeafIndex
  LeafIndex leaf_for_roster_entry(RosterIndex index) const;

  // Create a draft successor state
  State successor() const;
};

} // namespace mls
