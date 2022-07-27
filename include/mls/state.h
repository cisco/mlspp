#pragma once

#include "mls/crypto.h"
#include "mls/key_schedule.h"
#include "mls/messages.h"
#include "mls/treekem.h"
#include <list>
#include <optional>
#include <vector>

namespace mls {

// Index into the session roster
struct RosterIndex : public UInt32
{
  using UInt32::UInt32;
};

struct CommitOpts
{
  std::vector<Proposal> extra_proposals;
  bool inline_tree;
  bool encrypt_handshake;
  LeafNodeOptions leaf_node_opts;
};

struct MessageOpts
{
  bool encrypt = false;
  bytes authenticated_data;
  size_t padding_size = 0;
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
        const LeafNode& leaf_node,
        ExtensionList extensions);

  // Initialize a group from a Welcome
  State(const HPKEPrivateKey& init_priv,
        HPKEPrivateKey leaf_priv,
        SignaturePrivateKey sig_priv,
        const KeyPackage& kp,
        const Welcome& welcome,
        const std::optional<TreeKEMPublicKey>& tree);

  // Join a group from outside
  // XXX(RLB) To be fully general, we would need a few more options here, e.g.,
  // whether to include PSKs or evict our prior appearance.
  static std::tuple<MLSMessage, State> external_join(
    const bytes& leaf_secret,
    SignaturePrivateKey sig_priv,
    const KeyPackage& kp,
    const GroupInfo& group_info,
    const std::optional<TreeKEMPublicKey>& tree,
    const MessageOpts& msg_opts);

  // Propose that a new member be added a group
  static MLSMessage new_member_add(const bytes& group_id,
                                   epoch_t epoch,
                                   const KeyPackage& new_member,
                                   const SignaturePrivateKey& sig_priv);

  ///
  /// Message factories
  ///

  Proposal add_proposal(const KeyPackage& key_package) const;
  Proposal update_proposal(const bytes& leaf_secret,
                           const LeafNodeOptions& opts);
  Proposal remove_proposal(RosterIndex index) const;
  Proposal remove_proposal(LeafIndex removed) const;
  Proposal group_context_extensions_proposal(ExtensionList exts) const;

  MLSMessage add(const KeyPackage& key_package, const MessageOpts& msg_opts);
  MLSMessage update(const bytes& leaf_secret,
                    const LeafNodeOptions& opts,
                    const MessageOpts& msg_opts);
  MLSMessage remove(RosterIndex index, const MessageOpts& msg_opts);
  MLSMessage remove(LeafIndex removed, const MessageOpts& msg_opts);
  MLSMessage group_context_extensions(ExtensionList exts,
                                      const MessageOpts& msg_opts);

  std::tuple<MLSMessage, Welcome, State> commit(
    const bytes& leaf_secret,
    const std::optional<CommitOpts>& opts,
    const MessageOpts& msg_opts);

  ///
  /// Generic handshake message handler
  ///
  std::optional<State> handle(const MLSMessage& msg);
  std::optional<State> handle(const MLSMessage& msg,
                              std::optional<State> cached);

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
  GroupInfo group_info() const;

  // Ordered list of credentials from non-blank leaves
  std::vector<LeafNode> roster() const;

  bytes authentication_secret() const;

  ///
  /// Application encryption and decryption
  ///
  MLSMessage protect(const bytes& authenticated_data,
                     const bytes& pt,
                     size_t padding_size);
  std::tuple<bytes, bytes> unprotect(const MLSMessage& ct);

  // Assemble a group context for this state
  GroupContext group_context() const;

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
    ProposalRef ref;
    Proposal proposal;
    std::optional<LeafIndex> sender;
  };
  std::list<CachedProposal> _pending_proposals;

  struct CachedUpdate
  {
    bytes update_secret;
    Update proposal;
  };
  std::optional<CachedUpdate> _cached_update;

  // Assemble a preliminary, unjoined group state
  State(SignaturePrivateKey sig_priv,
        const GroupInfo& group_info,
        const std::optional<TreeKEMPublicKey>& tree);

  // Import a tree from an externally-provided tree or an extension
  TreeKEMPublicKey import_tree(const bytes& tree_hash,
                               const std::optional<TreeKEMPublicKey>& external,
                               const ExtensionList& extensions);

  std::tuple<MLSMessage, Welcome, State> commit(
    const bytes& leaf_secret,
    const std::optional<CommitOpts>& opts,
    const MessageOpts& msg_opts,
    const std::optional<KeyPackage>& joiner_key_package,
    const std::optional<HPKEPublicKey>& external_pub);

  // Create an MLSMessage encapsulating some content
  template<typename Inner>
  MLSAuthenticatedContent sign(const Sender& sender,
                               Inner&& content,
                               const bytes& authenticated_data,
                               bool encrypt) const;

  MLSMessage protect(MLSAuthenticatedContent&& content_auth,
                     size_t padding_size);

  template<typename Inner>
  MLSMessage protect_full(Inner&& content, const MessageOpts& msg_opts);

  MLSAuthenticatedContent unprotect_to_content_auth(const MLSMessage& msg);

  // Apply the changes requested by various messages
  void check_add_leaf_node(const LeafNode& leaf,
                           std::optional<LeafIndex> except) const;
  void check_update_leaf_node(LeafIndex target,
                              const LeafNode& leaf,
                              LeafNodeSource required_source) const;
  LeafIndex apply(const Add& add);
  void apply(LeafIndex target, const Update& update);
  void apply(LeafIndex target, const Update& update, const bytes& leaf_secret);
  LeafIndex apply(const Remove& remove);
  void apply(const GroupContextExtensions& gce);
  std::vector<LeafIndex> apply(const std::vector<CachedProposal>& proposals,
                               Proposal::Type required_type);
  std::tuple<bool, bool, std::vector<LeafIndex>> apply(
    const std::vector<CachedProposal>& proposals);

  // Verify that a specific key package or all members support a given set of
  // extensions
  bool extensions_supported(const ExtensionList& exts) const;

  // Extract a proposal from the cache
  void cache_proposal(MLSAuthenticatedContent content_auth);
  std::optional<CachedProposal> resolve(
    const ProposalOrRef& id,
    std::optional<LeafIndex> sender_index) const;
  std::vector<CachedProposal> must_resolve(
    const std::vector<ProposalOrRef>& ids,
    std::optional<LeafIndex> sender_index) const;

  // Compare the **shared** attributes of the states
  friend bool operator==(const State& lhs, const State& rhs);
  friend bool operator!=(const State& lhs, const State& rhs);

  // Derive and set the secrets for an epoch, given some new entropy
  void update_epoch_secrets(const bytes& commit_secret,
                            const std::vector<PSKWithSecret>& psks,
                            const std::optional<bytes>& force_init_secret);

  // Signature verification over a handshake message
  bool verify_internal(const MLSAuthenticatedContent& content_auth) const;
  bool verify_external(const MLSAuthenticatedContent& content_auth) const;
  bool verify_new_member_proposal(
    const MLSAuthenticatedContent& content_auth) const;
  bool verify_new_member_commit(
    const MLSAuthenticatedContent& content_auth) const;
  bool verify(const MLSAuthenticatedContent& content_auth) const;

  // Convert a Roster entry into LeafIndex
  LeafIndex leaf_for_roster_entry(RosterIndex index) const;

  // Create a draft successor state
  State successor() const;
};

} // namespace mls
