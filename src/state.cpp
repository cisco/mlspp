#include <mls/state.h>
#include <set>

#include <iostream> // XXX

namespace mls {

///
/// Constructors
///

State::State(bytes group_id,
             CipherSuite suite,
             const HPKEPrivateKey& init_priv,
             SignaturePrivateKey sig_priv,
             const LeafNode& leaf_node,
             ExtensionList extensions)
  : _suite(suite)
  , _group_id(std::move(group_id))
  , _epoch(0)
  , _tree(suite)
  , _transcript_hash(suite)
  , _extensions(std::move(extensions))
  , _index(0)
  , _identity_priv(std::move(sig_priv))
{
  // Verify that the client supports the proposed group extensions
  if (!leaf_node.verify_extension_support(_extensions)) {
    throw InvalidParameterError("Client doesn't support required extensions");
  }

  _index = _tree.add_leaf(leaf_node);
  _tree.set_hash_all();
  _tree_priv = TreeKEMPrivateKey::solo(suite, _index, init_priv);
  if (!_tree_priv.consistent(_tree)) {
    throw InvalidParameterError("LeafNode inconsistent with private key");
  }

  // XXX(RLB): Convert KeyScheduleEpoch to take GroupContext?
  auto ctx = tls::marshal(group_context());
  _key_schedule =
    KeyScheduleEpoch(_suite, random_bytes(_suite.secret_size()), ctx);
  _keys = _key_schedule.encryption_keys(_tree.size);

  // Update the interim transcript hash with a virtual confirmation tag
  _transcript_hash.update_interim(
    _key_schedule.confirmation_tag(_transcript_hash.confirmed));
}

TreeKEMPublicKey
State::import_tree(const bytes& tree_hash,
                   const std::optional<TreeKEMPublicKey>& external,
                   const ExtensionList& extensions)
{
  auto tree = TreeKEMPublicKey(_suite);
  auto maybe_tree_extn = extensions.find<RatchetTreeExtension>();
  if (external) {
    tree = opt::get(external);
  } else if (maybe_tree_extn) {
    tree = opt::get(maybe_tree_extn).tree;
  } else {
    throw InvalidParameterError("No tree available");
  }

  tree.suite = _suite;

  tree.set_hash_all();
  if (tree.root_hash() != tree_hash) {
    throw InvalidParameterError("Tree does not match GroupInfo");
  }

  if (!tree.parent_hash_valid()) {
    throw InvalidParameterError("Invalid tree");
  }

  return tree;
}

State::State(SignaturePrivateKey sig_priv,
             const GroupInfo& group_info,
             const std::optional<TreeKEMPublicKey>& tree)
  : _suite(group_info.group_context.cipher_suite)
  , _group_id(group_info.group_context.group_id)
  , _epoch(group_info.group_context.epoch)
  , _tree(import_tree(group_info.group_context.tree_hash,
                      tree,
                      group_info.extensions))
  , _transcript_hash(_suite,
                     group_info.group_context.confirmed_transcript_hash,
                     group_info.confirmation_tag)
  , _extensions(group_info.group_context.extensions)
  , _key_schedule(_suite)
  , _index(0)
  , _identity_priv(std::move(sig_priv))
{
  // The following are not set:
  //    _index
  //    _tree_priv
  //
  // This ctor should only be used within external_commit, in which case these
  // fields are populated by the subsequent commit()
}

// Initialize a group from a Welcome
State::State(const HPKEPrivateKey& init_priv,
             HPKEPrivateKey leaf_priv,
             SignaturePrivateKey sig_priv,
             const KeyPackage& key_package,
             const Welcome& welcome,
             const std::optional<TreeKEMPublicKey>& tree,
             std::map<bytes, bytes> external_psks)
  : _suite(welcome.cipher_suite)
  , _epoch(0)
  , _tree(welcome.cipher_suite)
  , _transcript_hash(welcome.cipher_suite)
  , _identity_priv(std::move(sig_priv))
  , _external_psks(std::move(external_psks))
{
  auto maybe_kpi = welcome.find(key_package);
  if (!maybe_kpi) {
    throw InvalidParameterError("Welcome not intended for key package");
  }
  auto kpi = opt::get(maybe_kpi);

  if (key_package.cipher_suite != welcome.cipher_suite) {
    throw InvalidParameterError("Ciphersuite mismatch");
  }

  // Decrypt the GroupSecrets
  auto secrets = welcome.decrypt_secrets(kpi, init_priv);

  // Look up PSKs
  auto psks =
    stdx::transform<PSKWithSecret>(secrets.psks.psks, [&](const auto& psk_id) {
      if (!var::holds_alternative<ExternalPSK>(psk_id.content)) {
        throw ProtocolError("Illegal resumption PSK");
      }

      const auto& ext_psk = var::get<ExternalPSK>(psk_id.content);
      if (_external_psks.count(ext_psk.psk_id) == 0) {
        throw ProtocolError("Unknown PSK");
      }

      const auto& secret = _external_psks.at(ext_psk.psk_id);
      return PSKWithSecret{ psk_id, secret };
    });

  // Decrypt the GroupInfo
  auto group_info = welcome.decrypt(secrets.joiner_secret, psks);
  if (group_info.group_context.cipher_suite != _suite) {
    throw InvalidParameterError("GroupInfo and Welcome ciphersuites disagree");
  }

  // Import the tree from the argument or from the extension
  _tree = import_tree(
    group_info.group_context.tree_hash, tree, group_info.extensions);

  // Verify the signature on the GroupInfo
  if (!group_info.verify(_tree)) {
    throw InvalidParameterError("Invalid GroupInfo");
  }

  // Ingest the GroupSecrets and GroupInfo
  _epoch = group_info.group_context.epoch;
  _group_id = group_info.group_context.group_id;

  _transcript_hash.confirmed =
    group_info.group_context.confirmed_transcript_hash;
  _transcript_hash.update_interim(group_info.confirmation_tag);

  _extensions = group_info.group_context.extensions;

  // Construct TreeKEM private key from parts provided
  auto maybe_index = _tree.find(key_package.leaf_node);
  if (!maybe_index) {
    throw InvalidParameterError("New joiner not in tree");
  }

  _index = opt::get(maybe_index);

  auto ancestor = _index.ancestor(group_info.signer);
  auto path_secret = std::optional<bytes>{};
  if (secrets.path_secret) {
    path_secret = opt::get(secrets.path_secret).secret;
  }

  _tree_priv = TreeKEMPrivateKey::joiner(
    _tree, _index, std::move(leaf_priv), ancestor, path_secret);

  // Ratchet forward into the current epoch
  auto group_ctx = tls::marshal(group_context());
  _key_schedule =
    KeyScheduleEpoch::joiner(_suite, secrets.joiner_secret, psks, group_ctx);
  _keys = _key_schedule.encryption_keys(_tree.size);

  // Verify the confirmation
  const auto confirmation_tag =
    _key_schedule.confirmation_tag(_transcript_hash.confirmed);
  if (confirmation_tag != group_info.confirmation_tag) {
    throw ProtocolError("Confirmation failed to verify");
  }
}

std::tuple<MLSMessage, State>
State::external_join(const bytes& leaf_secret,
                     SignaturePrivateKey sig_priv,
                     const KeyPackage& key_package,
                     const GroupInfo& group_info,
                     const std::optional<TreeKEMPublicKey>& tree,
                     const MessageOpts& msg_opts)
{

  // Look up the external public key for the group
  const auto maybe_external_pub =
    group_info.extensions.find<ExternalPubExtension>();
  if (!maybe_external_pub) {
    throw InvalidParameterError("No external pub in GroupInfo");
  }

  const auto& external_pub = opt::get(maybe_external_pub).external_pub;

  // Create an initial state that contains the joiner and use it to ommit
  auto initial_state = State(std::move(sig_priv), group_info, tree);
  auto [commit_msg, welcome, state] =
    initial_state.commit(leaf_secret, {}, msg_opts, key_package, external_pub);
  silence_unused(welcome);
  return { commit_msg, state };
}

MLSMessage
State::new_member_add(const bytes& group_id,
                      epoch_t epoch,
                      const KeyPackage& new_member,
                      const SignaturePrivateKey& sig_priv)
{
  const auto suite = new_member.cipher_suite;
  auto proposal = Proposal{ Add{ new_member } };
  auto content = GroupContent{ group_id,
                               epoch,
                               { NewMemberProposalSender{} },
                               { /* no authenticated data */ },
                               { std::move(proposal) } };
  auto content_auth = AuthenticatedContent::sign(
    WireFormat::mls_plaintext, std::move(content), suite, sig_priv, {});

  return PublicMessage::protect(std::move(content_auth), suite, {}, {});
}

///
/// Proposal and commit factories
///
template<typename Inner>
MLSMessage
State::protect_full(Inner&& inner_content, const MessageOpts& msg_opts)
{
  auto content_auth = sign({ MemberSender{ _index } },
                           inner_content,
                           msg_opts.authenticated_data,
                           msg_opts.encrypt);
  return protect(std::move(content_auth), msg_opts.padding_size);
}

template<typename Inner>
AuthenticatedContent
State::sign(const Sender& sender,
            Inner&& inner_content,
            const bytes& authenticated_data,
            bool encrypt) const
{
  auto content = GroupContent{
    _group_id, _epoch, sender, authenticated_data, { inner_content }
  };

  auto wire_format =
    (encrypt) ? WireFormat::mls_ciphertext : WireFormat::mls_plaintext;

  auto content_auth = AuthenticatedContent::sign(
    wire_format, std::move(content), _suite, _identity_priv, group_context());

  return content_auth;
}

MLSMessage
State::protect(AuthenticatedContent&& content_auth, size_t padding_size)
{
  switch (content_auth.wire_format) {
    case WireFormat::mls_plaintext:
      return PublicMessage::protect(std::move(content_auth),
                                    _suite,
                                    _key_schedule.membership_key,
                                    group_context());

    case WireFormat::mls_ciphertext:
      return PrivateMessage::protect(std::move(content_auth),
                                     _suite,
                                     _keys,
                                     _key_schedule.sender_data_secret,
                                     padding_size);

    default:
      throw InvalidParameterError("Malformed AuthenticatedContent");
  }
}

AuthenticatedContent
State::unprotect_to_content_auth(const MLSMessage& msg)
{
  const auto unprotect = overloaded{
    [&](const PublicMessage& pt) -> AuthenticatedContent {
      auto maybe_content_auth =
        pt.unprotect(_suite, _key_schedule.membership_key, group_context());
      if (!maybe_content_auth) {
        throw ProtocolError("Membership tag failed to verify");
      }
      return opt::get(maybe_content_auth);
    },

    [&](const PrivateMessage& ct) -> AuthenticatedContent {
      auto maybe_content_auth =
        ct.unprotect(_suite, _keys, _key_schedule.sender_data_secret);
      if (!maybe_content_auth) {
        throw ProtocolError("PrivateMessage decryption failure");
      }
      return opt::get(maybe_content_auth);
    },

    [](const auto& /* unused */) -> AuthenticatedContent {
      throw ProtocolError("Invalid wire format");
    },
  };

  return var::visit(unprotect, msg.message);
}

Proposal
State::add_proposal(const KeyPackage& key_package) const
{
  // Check that the key package is validly signed
  if (!key_package.verify()) {
    throw InvalidParameterError("Invalid signature on key package");
  }

  // Check that the group's basic properties are supported
  auto now = seconds_since_epoch();
  if (!key_package.leaf_node.verify_expiry(now)) {
    throw InvalidParameterError("Expired key package");
  }

  // Check that the group's extensions are supported
  if (!key_package.leaf_node.verify_extension_support(_extensions)) {
    throw InvalidParameterError(
      "Key package does not support group's extensions");
  }

  return { Add{ key_package } };
}

Proposal
State::update_proposal(HPKEPrivateKey leaf_priv, const LeafNodeOptions& opts)
{
  if (_cached_update) {
    return { opt::get(_cached_update).proposal };
  }

  auto leaf = opt::get(_tree.leaf_node(_index));

  auto new_leaf = leaf.for_update(
    _suite, _group_id, _index, leaf_priv.public_key, opts, _identity_priv);

  auto update = Update{ new_leaf };
  _cached_update = CachedUpdate{ std::move(leaf_priv), update };
  return { update };
}

Proposal
State::remove_proposal(RosterIndex index) const
{
  return remove_proposal(leaf_for_roster_entry(index));
}

Proposal
State::remove_proposal(LeafIndex removed) const
{
  if (!_tree.has_leaf(removed)) {
    throw InvalidParameterError("Remove on blank leaf");
  }

  return { Remove{ removed } };
}

Proposal
State::group_context_extensions_proposal(ExtensionList exts) const
{
  if (!extensions_supported(exts)) {
    throw InvalidParameterError("Unsupported extensions");
  }

  return { GroupContextExtensions{ std::move(exts) } };
}

Proposal
State::pre_shared_key_proposal(const bytes& external_psk_id) const
{
  if (_external_psks.count(external_psk_id) == 0) {
    throw InvalidParameterError("Unknown PSK");
  }

  auto psk_id = PreSharedKeyID{
    { ExternalPSK{ external_psk_id } },
    random_bytes(_suite.secret_size()),
  };
  return { PreSharedKey{ psk_id } };
}

MLSMessage
State::add(const KeyPackage& key_package, const MessageOpts& msg_opts)
{
  return protect_full(add_proposal(key_package), msg_opts);
}

MLSMessage
State::update(HPKEPrivateKey leaf_priv,
              const LeafNodeOptions& opts,
              const MessageOpts& msg_opts)
{
  return protect_full(update_proposal(std::move(leaf_priv), opts), msg_opts);
}

MLSMessage
State::remove(RosterIndex index, const MessageOpts& msg_opts)
{
  return protect_full(remove_proposal(index), msg_opts);
}

MLSMessage
State::remove(LeafIndex removed, const MessageOpts& msg_opts)
{
  return protect_full(remove_proposal(removed), msg_opts);
}

MLSMessage
State::group_context_extensions(ExtensionList exts, const MessageOpts& msg_opts)
{
  return protect_full(group_context_extensions_proposal(std::move(exts)),
                      msg_opts);
}

MLSMessage
State::pre_shared_key(const bytes& external_psk_id, const MessageOpts& msg_opts)
{
  return protect_full(pre_shared_key_proposal(external_psk_id), msg_opts);
}

std::tuple<MLSMessage, Welcome, State>
State::commit(const bytes& leaf_secret,
              const std::optional<CommitOpts>& opts,
              const MessageOpts& msg_opts)
{
  return commit(leaf_secret, opts, msg_opts, std::nullopt, std::nullopt);
}

std::tuple<MLSMessage, Welcome, State>
State::commit(const bytes& leaf_secret,
              const std::optional<CommitOpts>& opts,
              const MessageOpts& msg_opts,
              const std::optional<KeyPackage>& joiner_key_package,
              const std::optional<HPKEPublicKey>& external_pub)
{
  // Construct a commit from cached proposals
  // TODO(rlb) ignore some proposals:
  // * Update after Update
  // * Update after Remove
  // * Remove after Remove
  Commit commit;
  auto joiners = std::vector<KeyPackage>{};
  for (const auto& cached : _pending_proposals) {
    if (var::holds_alternative<Add>(cached.proposal.content)) {
      const auto& add = var::get<Add>(cached.proposal.content);
      joiners.push_back(add.key_package);
    }

    commit.proposals.push_back({ cached.ref });
  }

  // Add the extra proposals to those we had cached
  if (opts) {
    const auto& extra_proposals = opt::get(opts).extra_proposals;
    for (const auto& proposal : extra_proposals) {
      if (var::holds_alternative<Add>(proposal.content)) {
        const auto& add = var::get<Add>(proposal.content);
        joiners.push_back(add.key_package);
      }

      commit.proposals.push_back({ proposal });
    }
  }

  // If this is an external commit, insert an ExternalInit proposal
  auto external_commit = bool(joiner_key_package) && bool(external_pub);
  if (bool(joiner_key_package) != bool(external_pub)) {
    throw InvalidParameterError("Malformed external commit parameters");
  }

  auto force_init_secret = std::optional<bytes>{};
  if (external_commit) {
    auto [enc, exported] =
      KeyScheduleEpoch::external_init(_suite, opt::get(external_pub));
    force_init_secret = exported;
    commit.proposals.push_back({ Proposal{ ExternalInit{ enc } } });
  }

  // Apply proposals
  State next = successor();

  const auto proposals = must_resolve(commit.proposals, _index);
  if (!external_commit && !valid(proposals, _index)) {
    throw ProtocolError("Invalid proposal list");
  }
  if (external_commit && !valid_external(proposals)) {
    throw ProtocolError("Invalid proposal list for external commit");
  }

  const auto [joiner_locations, psks] = next.apply(proposals);

  if (external_commit) {
    next._index = next._tree.add_leaf(opt::get(joiner_key_package).leaf_node);
  }

  // If this is an external commit, indicate it in the sender field
  auto sender = Sender{ MemberSender{ _index } };
  if (external_commit) {
    sender = Sender{ NewMemberCommitSender{} };
  }

  // KEM new entropy to the group and the new joiners
  auto commit_secret = _suite.zero();
  auto path_secrets =
    std::vector<std::optional<bytes>>(joiner_locations.size());
  if (path_required(proposals)) {
    auto leaf_node_opts = LeafNodeOptions{};
    if (opts) {
      leaf_node_opts = opt::get(opts).leaf_node_opts;
    }

    auto new_priv = next._tree.update(
      next._index, leaf_secret, next._group_id, _identity_priv, leaf_node_opts);

    auto ctx = tls::marshal(GroupContext{
      next._suite,
      next._group_id,
      next._epoch + 1,
      next._tree.root_hash(),
      next._transcript_hash.confirmed,
      next._extensions,
    });
    auto path = next._tree.encap(new_priv, ctx, joiner_locations);

    next._tree_priv = new_priv;
    commit.path = path;
    commit_secret = new_priv.update_secret;

    for (size_t i = 0; i < joiner_locations.size(); i++) {
      auto [overlap, shared_path_secret, ok] =
        new_priv.shared_path_secret(joiner_locations[i]);
      silence_unused(overlap);
      silence_unused(ok);

      path_secrets[i] = shared_path_secret;
    }
  }

  // Create the Commit message and advance the transcripts / key schedule
  auto commit_content_auth =
    sign(sender, commit, msg_opts.authenticated_data, msg_opts.encrypt);

  next._transcript_hash.update_confirmed(commit_content_auth);
  next._epoch += 1;
  next.update_epoch_secrets(commit_secret, psks, force_init_secret);

  const auto confirmation_tag =
    next._key_schedule.confirmation_tag(next._transcript_hash.confirmed);
  commit_content_auth.set_confirmation_tag(confirmation_tag);

  next._transcript_hash.update_interim(commit_content_auth);

  auto commit_message =
    protect(std::move(commit_content_auth), msg_opts.padding_size);

  // Complete the GroupInfo and form the Welcome
  auto group_info = GroupInfo{
    {
      next._suite,
      next._group_id,
      next._epoch,
      next._tree.root_hash(),
      next._transcript_hash.confirmed,
      next._extensions,
    },
    { /* No other extensions */ },
    { confirmation_tag },
  };
  if (opts && opt::get(opts).inline_tree) {
    group_info.extensions.add(RatchetTreeExtension{ next._tree });
  }
  group_info.sign(next._tree, next._index, next._identity_priv);

  auto welcome =
    Welcome{ _suite, next._key_schedule.joiner_secret, psks, group_info };
  for (size_t i = 0; i < joiners.size(); i++) {
    welcome.encrypt(joiners[i], path_secrets[i]);
  }

  return std::make_tuple(commit_message, welcome, next);
}

///
/// Message handlers
///

GroupContext
State::group_context() const
{
  return GroupContext{
    _suite,
    _group_id,
    _epoch,
    _tree.root_hash(),
    _transcript_hash.confirmed,
    _extensions,
  };
}

std::optional<State>
State::handle(const MLSMessage& msg)
{
  return handle(msg, std::nullopt);
}

std::optional<State>
State::handle(const MLSMessage& msg, std::optional<State> cached_state)
{
  // Check the version
  if (msg.version != ProtocolVersion::mls10) {
    throw InvalidParameterError("Unsupported version");
  }

  // Verify the signature on the message
  auto content_auth = unprotect_to_content_auth(msg);
  if (!verify(content_auth)) {
    throw InvalidParameterError("Message signature failed to verify");
  }

  // Validate the GroupContent
  const auto& content = content_auth.content;
  if (content.group_id != _group_id) {
    throw InvalidParameterError("GroupID mismatch");
  }

  if (content.epoch != _epoch) {
    throw InvalidParameterError("Epoch mismatch");
  }

  // Dispatch on content type
  switch (content.content_type()) {
    // Proposals get queued, do not result in a state transition
    case ContentType::proposal:
      cache_proposal(content_auth);
      return std::nullopt;

    // Commits are handled in the remainder of this method
    case ContentType::commit:
      break;

    // Any other content type in this method is an error
    default:
      throw InvalidParameterError("Invalid content type");
  }

  switch (content.sender.sender_type()) {
    case SenderType::member:
    case SenderType::new_member_commit:
      break;

    default:
      throw ProtocolError("Invalid commit sender type");
  }

  auto external_commit =
    content.sender.sender_type() == SenderType::new_member_commit;

  auto sender = std::optional<LeafIndex>();
  if (content.sender.sender_type() == SenderType::member) {
    sender = var::get<MemberSender>(content.sender.sender).sender;
  }

  if (sender == _index) {
    if (cached_state) {
      // Verify that the cached state is a plausible successor to this state
      const auto& next = opt::get(cached_state);
      if (next._group_id != _group_id || next._epoch != _epoch + 1 ||
          next._index != _index) {
        throw InvalidParameterError("Invalid successor state");
      }

      return next;
    }

    throw InvalidParameterError("Handle own commits with caching");
  }

  // Apply the commit
  const auto& commit = var::get<Commit>(content.content);
  const auto proposals = must_resolve(commit.proposals, sender);

  if (!external_commit && !valid(proposals, opt::get(sender))) {
    throw ProtocolError("Invalid proposal list");
  }

  if (external_commit && !valid_external(proposals)) {
    throw ProtocolError("Invalid proposal list for external commit");
  }

  if (path_required(proposals) && !commit.path) {
    throw ProtocolError("Path required but not present");
  }

  auto next = successor();
  auto [joiner_locations, psks] = next.apply(proposals);

  // If this is an external commit, add the joiner to the tree and note the
  // location where they were added.  Also, compute the "externally forced"
  // value that we will use for the init_secret (as opposed to the init_secret
  // from the key schedule).
  auto force_init_secret = std::optional<bytes>{};
  auto sender_location = LeafIndex{ 0 };
  if (!external_commit) {
    sender_location = opt::get(sender);
  } else {
    // Add the joiner
    const auto& path = opt::get(commit.path);
    sender_location = next._tree.add_leaf(path.leaf_node);

    // Extract the forced init secret
    auto kem_output = commit.valid_external();
    if (!kem_output) {
      throw ProtocolError("Invalid external commit");
    }

    force_init_secret =
      _key_schedule.receive_external_init(opt::get(kem_output));
  }

  // Decapsulate and apply the UpdatePath, if provided
  auto commit_secret = _suite.zero();
  if (commit.path) {
    const auto& path = opt::get(commit.path);

    if (!valid(path.leaf_node, LeafNodeSource::commit, sender_location)) {
      throw ProtocolError("Commit path has invalid leaf node");
    }

    if (!next._tree.parent_hash_valid(sender_location, path)) {
      throw ProtocolError("Commit path has invalid parent hash");
    }

    next._tree.merge(sender_location, path);

    auto ctx = tls::marshal(GroupContext{
      next._suite,
      next._group_id,
      next._epoch + 1,
      next._tree.root_hash(),
      next._transcript_hash.confirmed,
      next._extensions,
    });
    next._tree_priv.decap(
      sender_location, next._tree, ctx, path, joiner_locations);

    commit_secret = next._tree_priv.update_secret;
  }

  // Update the transcripts and advance the key schedule
  next._transcript_hash.update(content_auth);
  next._epoch += 1;
  next.update_epoch_secrets(commit_secret, { psks }, force_init_secret);

  // Verify the confirmation MAC
  const auto confirmation_tag =
    next._key_schedule.confirmation_tag(next._transcript_hash.confirmed);
  if (!content_auth.check_confirmation_tag(confirmation_tag)) {
    throw ProtocolError("Confirmation failed to verify");
  }

  return next;
}

LeafIndex
State::apply(const Add& add)
{
  return _tree.add_leaf(add.key_package.leaf_node);
}

void
State::apply(LeafIndex target, const Update& update)
{
  _tree.update_leaf(target, update.leaf_node);
}

void
State::apply(LeafIndex target,
             const Update& update,
             const HPKEPrivateKey& leaf_priv)
{
  _tree.update_leaf(target, update.leaf_node);
  _tree_priv.set_leaf_priv(leaf_priv);
}

LeafIndex
State::apply(const Remove& remove)
{
  if (!_tree.has_leaf(remove.removed)) {
    throw ProtocolError("Attempt to remove non-member");
  }

  _tree.blank_path(remove.removed);
  return remove.removed;
}

void
State::apply(const GroupContextExtensions& gce)
{
  // TODO(RLB): Update spec to clarify that you MUST verify that the new
  // extensions are compatible with all members.
  if (!extensions_supported(gce.group_context_extensions)) {
    throw ProtocolError("Unsupported extensions in GroupContextExtensions");
  }

  _extensions = gce.group_context_extensions;
}

bool
State::extensions_supported(const ExtensionList& exts) const
{
  for (LeafIndex i{ 0 }; i < _tree.size; i.val++) {
    const auto& maybe_leaf = _tree.leaf_node(i);
    if (!maybe_leaf) {
      continue;
    }

    const auto& leaf = opt::get(maybe_leaf);
    if (!leaf.verify_extension_support(exts)) {
      return false;
    }
  }

  return true;
}

void
State::cache_proposal(AuthenticatedContent content_auth)
{
  auto sender_location = std::optional<LeafIndex>();
  if (content_auth.content.sender.sender_type() == SenderType::member) {
    const auto& sender = content_auth.content.sender.sender;
    sender_location = var::get<MemberSender>(sender).sender;
  }

  const auto& proposal = var::get<Proposal>(content_auth.content.content);
  if (!valid(sender_location, proposal)) {
    throw ProtocolError("Invalid proposal");
  }

  _pending_proposals.push_back({
    _suite.ref(content_auth),
    proposal,
    sender_location,
  });
}

std::optional<State::CachedProposal>
State::resolve(const ProposalOrRef& id,
               std::optional<LeafIndex> sender_index) const
{
  if (var::holds_alternative<Proposal>(id.content)) {
    return CachedProposal{
      {},
      var::get<Proposal>(id.content),
      sender_index,
    };
  }

  const auto& ref = var::get<ProposalRef>(id.content);
  for (const auto& cached : _pending_proposals) {
    if (cached.ref == ref) {
      return cached;
    }
  }

  return std::nullopt;
}

std::vector<State::CachedProposal>
State::must_resolve(const std::vector<ProposalOrRef>& ids,
                    std::optional<LeafIndex> sender_index) const
{
  auto must_resolve = [&](const auto& id) {
    return opt::get(resolve(id, sender_index));
  };
  return stdx::transform<CachedProposal>(ids, must_resolve);
}

std::vector<LeafIndex>
State::apply(const std::vector<CachedProposal>& proposals,
             Proposal::Type required_type)
{
  auto locations = std::vector<LeafIndex>{};
  for (const auto& cached : proposals) {
    auto proposal_type = cached.proposal.proposal_type();
    if (proposal_type != required_type) {
      continue;
    }

    switch (proposal_type) {
      case ProposalType::add: {
        locations.push_back(apply(var::get<Add>(cached.proposal.content)));
        break;
      }

      case ProposalType::update: {
        const auto& update = var::get<Update>(cached.proposal.content);

        if (!cached.sender) {
          throw ProtocolError("Update without target leaf");
        }

        auto target = opt::get(cached.sender);
        if (target != _index) {
          apply(target, update);
          break;
        }

        if (!_cached_update) {
          throw ProtocolError("Self-update with no cached secret");
        }

        const auto& cached_update = opt::get(_cached_update);
        if (update != cached_update.proposal) {
          throw ProtocolError("Self-update does not match cached data");
        }

        apply(target, update, cached_update.update_priv);
        locations.push_back(target);
        break;
      }

      case ProposalType::remove: {
        const auto& remove = var::get<Remove>(cached.proposal.content);
        locations.push_back(apply(remove));
        break;
      }

      case ProposalType::group_context_extensions: {
        const auto& gce =
          var::get<GroupContextExtensions>(cached.proposal.content);
        apply(gce);
        break;
      }

      default:
        throw ProtocolError("Unsupported proposal type");
    }
  }

  return locations;
}

std::tuple<std::vector<LeafIndex>, std::vector<PSKWithSecret>>
State::apply(const std::vector<CachedProposal>& proposals)
{
  apply(proposals, ProposalType::update);
  apply(proposals, ProposalType::remove);
  auto joiner_locations = apply(proposals, ProposalType::add);
  apply(proposals, ProposalType::group_context_extensions);

  // Extract the PSK proposals and look up the secrets
  // TODO(RLB): Factor this out, and also factor the above methods into
  // apply_update, apply_remove, etc.
  auto psks = std::vector<PSKWithSecret>{};
  for (const auto& cached : proposals) {
    if (cached.proposal.proposal_type() != ProposalType::psk) {
      continue;
    }

    const auto& proposal = var::get<PreSharedKey>(cached.proposal.content);
    const auto& ext_psk = var::get<ExternalPSK>(proposal.psk.content);
    const auto secret = _external_psks.at(ext_psk.psk_id);

    psks.push_back({ proposal.psk, secret });
  }

  _tree.truncate();
  _tree_priv.truncate(_tree.size);
  _tree.set_hash_all();
  return { joiner_locations, psks };
}

///
/// Message protection
///

MLSMessage
State::protect(const bytes& authenticated_data,
               const bytes& pt,
               size_t padding_size)
{
  auto msg_opts = MessageOpts{ true, authenticated_data, padding_size };
  return protect_full(ApplicationData{ pt }, msg_opts);
}

std::tuple<bytes, bytes>
State::unprotect(const MLSMessage& ct)
{
  auto content_auth = unprotect_to_content_auth(ct);

  if (!verify(content_auth)) {
    throw InvalidParameterError("Message signature failed to verify");
  }

  if (content_auth.content.content_type() != ContentType::application) {
    throw ProtocolError("Unprotect of handshake message");
  }

  if (content_auth.wire_format != WireFormat::mls_ciphertext) {
    throw ProtocolError("Application data not sent as PrivateMessage");
  }

  return {
    std::move(content_auth.content.authenticated_data),
    std::move(var::get<ApplicationData>(content_auth.content.content).data),
  };
}

///
/// Properties of a proposal list
///

bool
State::valid(const LeafNode& leaf_node,
             LeafNodeSource required_source,
             std::optional<LeafIndex> index) const
{
  // Verify that the credential in the LeafNode is valid as described in Section
  // 5.3.1.
  // XXX(RLB) N/A, no credential validation in the library right now

  // Verify the leaf_node_source field:
  const auto correct_source = (leaf_node.source() == required_source);

  // Verify that the signature on the LeafNode is valid using signature_key.
  auto binding = std::optional<LeafNode::MemberBinding>{};
  switch (required_source) {
    case LeafNodeSource::commit:
    case LeafNodeSource::update:
      binding = LeafNode::MemberBinding{ _group_id, opt::get(index) };
      break;

    default:
      // Nothing to do
      break;
  }

  const auto signature_valid = leaf_node.verify(_suite, binding);

  // Verify that the LeafNode is compatible with the group's parameters. If the
  // GroupContext has a required_capabilities extension, then the required
  // extensions, proposals, and credential types MUST be listed in the
  // LeafNode's capabilities field.
  const auto supports_group_extensions =
    leaf_node.verify_extension_support(_extensions);

  // TODO(RLB) Verify the lifetime field

  // Verify that the credential type is supported by all members of the group,
  // as specified by the capabilities field of each member's LeafNode, and that
  // the capabilities field of this LeafNode indicates support for all the
  // credential types currently in use by other members.
  //
  // Verify that the following fields are unique among the members of the group:
  // signature_key
  // encryption_key
  const auto& signature_key = leaf_node.signature_key;
  const auto& encryption_key = leaf_node.encryption_key;
  auto unique_signature_key = true;
  auto unique_encryption_key = true;
  auto mutual_credential_support = true;
  for (auto i = LeafIndex{ 0 }; i < _tree.size; i.val++) {
    const auto maybe_leaf = _tree.leaf_node(i);
    if (!maybe_leaf) {
      continue;
    }

    const auto& leaf = opt::get(maybe_leaf);

    // Signature keys are allowed to repeat within a leaf
    unique_signature_key =
      unique_signature_key &&
      ((i == index) || (signature_key != leaf.signature_key));
    unique_encryption_key =
      unique_encryption_key && (encryption_key != leaf.encryption_key);
    mutual_credential_support =
      mutual_credential_support &&
      leaf.capabilities.credential_supported(leaf_node.credential) &&
      leaf_node.capabilities.credential_supported(leaf.credential);
  }

  return (signature_valid && supports_group_extensions && correct_source &&
          mutual_credential_support && unique_signature_key &&
          unique_encryption_key);
}

bool
State::valid(const KeyPackage& key_package) const
{
  // Verify that the ciphersuite and protocol version of the KeyPackage match
  // those in the GroupContext.
  const auto correct_ciphersuite = (key_package.cipher_suite == _suite);

  // Verify that the signature on the KeyPackage is valid using the public key
  // in leaf_node.credential.
  const auto valid_signature = key_package.verify();

  // Verify that the leaf_node of the KeyPackage is valid for a KeyPackage
  // according to Section 7.3.
  const auto leaf_node_valid =
    valid(key_package.leaf_node, LeafNodeSource::key_package, std::nullopt);

  // Verify that the value of leaf_node.encryption_key is different from the
  // value of the init_key field.
  const auto distinct_keys =
    (key_package.init_key != key_package.leaf_node.encryption_key);

  return (correct_ciphersuite && valid_signature && leaf_node_valid &&
          distinct_keys);
}

bool
State::valid(const Add& add) const
{
  return valid(add.key_package);
}

bool
State::valid(LeafIndex sender, const Update& update) const
{
  const auto maybe_leaf = _tree.leaf_node(sender);
  if (!maybe_leaf) {
    return false;
  }

  return valid(update.leaf_node, LeafNodeSource::update, sender);
}

bool
State::valid(const Remove& remove) const
{
  return remove.removed < _tree.size && _tree.leaf_node(remove.removed);
}

bool
State::valid(const PreSharedKey& psk) const
{
  // Verify that it's an external PSK (we don't support any others)
  if (!var::holds_alternative<ExternalPSK>(psk.psk.content)) {
    return false;
  }

  // Verify that we have the appropriate PSK
  const auto& ext_psk = var::get<ExternalPSK>(psk.psk.content);
  return _external_psks.count(ext_psk.psk_id) > 0;
}

bool
State::valid(const ReInit& /* reinit */)
{
  // No validation to be done
  return true;
}

bool
State::valid(const ExternalInit& external_init) const
{
  return external_init.kem_output.size() == _suite.hpke().kem.enc_size;
}

bool
State::valid(const GroupContextExtensions& gce) const
{
  // Verify that each extension is supported by all members
  for (auto i = LeafIndex{ 0 }; i < _tree.size; i.val++) {
    const auto maybe_leaf = _tree.leaf_node(i);
    if (!maybe_leaf) {
      continue;
    }

    const auto& leaf = opt::get(maybe_leaf);
    if (!leaf.verify_extension_support(gce.group_context_extensions)) {
      return false;
    }
  }
  return true;
}

bool
State::valid(std::optional<LeafIndex> sender, const Proposal& proposal) const
{
  const auto specifically_valid = overloaded{
    [&](const Update& update) { return valid(opt::get(sender), update); },

    [&](const auto& proposal) { return valid(proposal); },
  };
  return var::visit(specifically_valid, proposal.content);
}

// NB(RLB) We handle the normal case separately from the ReInit case, because I
// expect that we will end up with a different API for the ReInit case.
bool
// NB(RLB): clang-tidy thinks this can be static, but it can't.
// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
State::valid(const std::vector<CachedProposal>& proposals,
             LeafIndex commit_sender) const
{
  // It contains an individual proposal that is invalid as specified in Section
  // 12.1.
  const auto has_invalid_proposal =
    stdx::any_of(proposals, [&](const auto& cached) {
      return !valid(cached.sender, cached.proposal);
    });

  // It contains an Update proposal generated by the committer.
  const auto has_self_update = stdx::any_of(proposals, [&](const auto& cached) {
    return cached.proposal.proposal_type() == ProposalType::update &&
           cached.sender == commit_sender;
  });

  // It contains a Remove proposal that removes the committer.
  const auto has_self_remove = stdx::any_of(proposals, [&](const auto& cached) {
    return cached.proposal.proposal_type() == ProposalType::remove &&
           var::get<Remove>(cached.proposal.content).removed == commit_sender;
  });

  // It contains multiple Update and/or Remove proposals that apply to the same
  // leaf. If the committer has received multiple such proposals they SHOULD
  // prefer any Remove received, or the most recent Update if there are no
  // Removes.
  auto updated_or_removed = std::set<LeafIndex>{};
  const auto has_dup_update_remove =
    stdx::any_of(proposals, [&](const auto& cached) {
      auto index = LeafIndex{ 0 };
      switch (cached.proposal.proposal_type()) {
        case ProposalType::update:
          index = opt::get(cached.sender);
          break;

        case ProposalType::remove:
          index = var::get<Remove>(cached.proposal.content).removed;
          break;

        default:
          return false;
      }

      if (stdx::contains(updated_or_removed, index)) {
        return true;
      }

      updated_or_removed.insert(index);
      return false;
    });

  // It contains multiple Add proposals that contain KeyPackages that represent
  // the same client according to the application (for example, identical
  // signature keys).
  auto signature_keys = std::vector<SignaturePublicKey>{};
  const auto has_dup_signature_key =
    stdx::any_of(proposals, [&](const auto& cached) {
      if (cached.proposal.proposal_type() != ProposalType::add) {
        return false;
      }

      auto key_package = var::get<Add>(cached.proposal.content).key_package;
      auto signature_key = key_package.leaf_node.signature_key;
      if (stdx::contains(signature_keys, signature_key)) {
        return true;
      }

      signature_keys.push_back(signature_key);
      return false;
    });

  // It contains an Add proposal with a KeyPackage that represents a client
  // already in the group according to the application, unless there is a Remove
  // proposal in the list removing the matching client from the group.
  // TODO(RLB)

  // It contains multiple PreSharedKey proposals that reference the same
  // PreSharedKeyID.
  auto psk_ids = std::vector<PreSharedKeyID>{};
  const auto has_dup_psk_id = stdx::any_of(proposals, [&](const auto& cached) {
    if (cached.proposal.proposal_type() != ProposalType::psk) {
      return false;
    }

    auto psk_id = var::get<PreSharedKey>(cached.proposal.content).psk;
    if (stdx::contains(psk_ids, psk_id)) {
      return true;
    }

    psk_ids.push_back(psk_id);
    return false;
  });

  // It contains multiple GroupContextExtensions proposals.
  const auto gce_count = stdx::count_if(proposals, [](const auto& cached) {
    return cached.proposal.proposal_type() ==
           ProposalType::group_context_extensions;
  });
  const auto has_multiple_gce = (gce_count > 1);

  // It contains a ReInit proposal together with any other proposal. If the
  // committer has received other proposals during the epoch, they SHOULD prefer
  // them over the ReInit proposal, allowing the ReInit to be resent and applied
  // in a subsequent epoch.
  const auto has_reinit = stdx::any_of(proposals, [](const auto& cached) {
    return cached.proposal.proposal_type() == ProposalType::reinit;
  });

  // It contains an ExternalInit proposal.
  const auto has_external_init =
    stdx::any_of(proposals, [](const auto& cached) {
      return cached.proposal.proposal_type() == ProposalType::reinit;
    });

  // It contains a proposal with a non-default proposal type that is not
  // supported by some members of the group that will process the Commit (i.e.,
  // members being added or removed by the Commit do not need to support the
  // proposal type).
  // XXX(RLB): N/A, no non-default proposal types

  // After processing the commit the ratchet tree is invalid, in particular, if
  // it contains any leaf node that is invalid according to Section 7.3.
  //
  // NB(RLB): Leaf nodes are already checked in the individual proposal check at
  // the top.  So the focus here is key uniqueness. We check this by checking
  // uniqueness of encryption keys across the Adds and Updates in this list of
  // proposals.  The keys have already been checked to be distinct from any keys
  // already in the tree.
  auto enc_keys = std::vector<HPKEPublicKey>{};
  const auto has_dup_enc_key = stdx::any_of(proposals, [&](const auto& cached) {
    const auto get_enc_key =
      overloaded{ [](const Add& add) -> std::optional<HPKEPublicKey> {
                   return add.key_package.leaf_node.encryption_key;
                 },
                  [](const Update& update) -> std::optional<HPKEPublicKey> {
                    return update.leaf_node.encryption_key;
                  },

                  [](const auto& /* default */)
                    -> std::optional<HPKEPublicKey> { return std::nullopt; } };
    auto maybe_enc_key = var::visit(get_enc_key, cached.proposal.content);
    if (!maybe_enc_key) {
      return false;
    }

    const auto& enc_key = opt::get(maybe_enc_key);
    if (stdx::contains(enc_keys, enc_key)) {
      return true;
    }

    enc_keys.push_back(enc_key);
    return false;
  });

  return !(has_invalid_proposal || has_self_update || has_self_remove ||
           has_dup_update_remove || has_dup_signature_key || has_dup_psk_id ||
           has_multiple_gce || has_reinit || has_external_init ||
           has_dup_enc_key);
}

bool
State::valid_reinit(const std::vector<CachedProposal>& proposals)
{
  // Check that the list contains a ReInit proposal
  const auto has_reinit = stdx::any_of(proposals, [](const auto& cached) {
    return cached.proposal.proposal_type() == ProposalType::reinit;
  });

  // Check whether the list contains any disallowed proposals
  const auto has_disallowed = stdx::any_of(proposals, [](const auto& cached) {
    return cached.proposal.proposal_type() != ProposalType::reinit;
  });

  return has_reinit && !has_disallowed;
}

bool
State::valid_external(const std::vector<CachedProposal>& proposals)
{
  // Exactly one ExternalInit
  auto ext_init_count = stdx::count_if(proposals, [](const auto& cached) {
    return cached.proposal.proposal_type() == ProposalType::external_init;
  });
  auto one_ext_init = (ext_init_count == 1);

  // At most one Remove proposal, with which the joiner removes an old version
  // of themselves. If a Remove proposal is present, then the LeafNode in the
  // path field of the external commit MUST meet the same criteria as would the
  // LeafNode in an Update for the removed leaf (see Section 12.1.2). In
  // particular, the credential in the LeafNode MUST present a set of
  // identifiers that is acceptable to the application for the removed
  // participant.
  // TODO(RLB) Verify that Remove is properly formed
  auto remove_count = stdx::count_if(proposals, [](const auto& cached) {
    return cached.proposal.proposal_type() == ProposalType::remove;
  });
  auto no_dup_remove = (remove_count <= 1);

  // Zero or more PreSharedKey proposals.
  // No other proposals.
  auto no_disallowed = stdx::all_of(proposals, [](const auto& cached) {
    switch (cached.proposal.proposal_type()) {
      case ProposalType::external_init:
      case ProposalType::remove:
      case ProposalType::psk:
        return true;

      default:
        return false;
    }
  });

  return one_ext_init && no_dup_remove && no_disallowed;
}

bool
State::path_required(const std::vector<CachedProposal>& proposals)
{
  static const auto path_required_types = std::set<Proposal::Type>{
    ProposalType::update,
    ProposalType::remove,
    ProposalType::external_init,
    ProposalType::group_context_extensions,
  };

  if (proposals.empty()) {
    return true;
  }

  return stdx::any_of(proposals, [](const auto& cp) {
    return path_required_types.count(cp.proposal.proposal_type()) != 0;
  });
}

///
/// Inner logic and convenience functions
///

bool
operator==(const State& lhs, const State& rhs)
{
  auto suite = (lhs._suite == rhs._suite);
  auto group_id = (lhs._group_id == rhs._group_id);
  auto epoch = (lhs._epoch == rhs._epoch);
  auto tree = (lhs._tree == rhs._tree);
  auto transcript_hash = (lhs._transcript_hash == rhs._transcript_hash);
  auto key_schedule = (lhs._key_schedule == rhs._key_schedule);
  auto extensions = (lhs._extensions == rhs._extensions);

  return suite && group_id && epoch && tree && transcript_hash &&
         key_schedule && extensions;
}

bool
operator!=(const State& lhs, const State& rhs)
{
  return !(lhs == rhs);
}

void
State::update_epoch_secrets(const bytes& commit_secret,
                            const std::vector<PSKWithSecret>& psks,
                            const std::optional<bytes>& force_init_secret)
{
  auto ctx = tls::marshal(GroupContext{
    _suite,
    _group_id,
    _epoch,
    _tree.root_hash(),
    _transcript_hash.confirmed,
    _extensions,
  });
  _key_schedule =
    _key_schedule.next(commit_secret, psks, force_init_secret, ctx);
  _keys = _key_schedule.encryption_keys(_tree.size);
}

///
/// Message encryption and decryption
///
bool
State::verify_internal(const AuthenticatedContent& content_auth) const
{
  const auto& sender =
    var::get<MemberSender>(content_auth.content.sender.sender).sender;
  auto maybe_leaf = _tree.leaf_node(sender);
  if (!maybe_leaf) {
    throw InvalidParameterError("Signature from blank node");
  }

  const auto& pub = opt::get(maybe_leaf).signature_key;
  return content_auth.verify(_suite, pub, group_context());
}

bool
State::verify_external(const AuthenticatedContent& content_auth) const
{
  const auto& ext_sender =
    var::get<ExternalSenderIndex>(content_auth.content.sender.sender);
  const auto senders_ext = _extensions.find<ExternalSendersExtension>();
  const auto& senders = opt::get(senders_ext).senders;
  const auto& pub = senders.at(ext_sender.sender_index).signature_key;
  return content_auth.verify(_suite, pub, group_context());
}

bool
State::verify_new_member_proposal(
  const AuthenticatedContent& content_auth) const
{
  const auto& proposal = var::get<Proposal>(content_auth.content.content);
  const auto& add = var::get<Add>(proposal.content);
  const auto& pub = add.key_package.leaf_node.signature_key;
  return content_auth.verify(_suite, pub, group_context());
}

bool
State::verify_new_member_commit(const AuthenticatedContent& content_auth) const
{
  const auto& commit = var::get<Commit>(content_auth.content.content);
  const auto& path = opt::get(commit.path);
  const auto& pub = path.leaf_node.signature_key;
  return content_auth.verify(_suite, pub, group_context());
}

bool
State::verify(const AuthenticatedContent& content_auth) const
{
  switch (content_auth.content.sender.sender_type()) {
    case SenderType::member:
      return verify_internal(content_auth);

    case SenderType::external:
      return verify_external(content_auth);

    case SenderType::new_member_proposal:
      return verify_new_member_proposal(content_auth);

    case SenderType::new_member_commit:
      return verify_new_member_commit(content_auth);

    default:
      throw ProtocolError("Invalid sender type");
  }
}

void
State::add_external_psk(const bytes& id, const bytes& secret)
{
  _external_psks.insert_or_assign(id, secret);
}

void
State::remove_external_psk(const bytes& id)
{
  _external_psks.erase(id);
}

bytes
State::do_export(const std::string& label,
                 const bytes& context,
                 size_t size) const
{
  return _key_schedule.do_export(label, context, size);
}

GroupInfo
State::group_info() const
{
  auto group_info = GroupInfo{
    {
      _suite,
      _group_id,
      _epoch,
      _tree.root_hash(),
      _transcript_hash.confirmed,
      _extensions,
    },
    { /* No other extensions */ },
    _key_schedule.confirmation_tag(_transcript_hash.confirmed),
  };

  group_info.extensions.add(
    ExternalPubExtension{ _key_schedule.external_priv.public_key });
  group_info.extensions.add(RatchetTreeExtension{ _tree });
  group_info.sign(_tree, _index, _identity_priv);
  return group_info;
}

std::vector<LeafNode>
State::roster() const
{
  auto leaves = std::vector<LeafNode>(_tree.size.val);
  auto leaf_count = uint32_t(0);

  for (uint32_t i = 0; i < _tree.size.val; i++) {
    const auto& maybe_leaf = _tree.leaf_node(LeafIndex{ i });
    if (!maybe_leaf) {
      continue;
    }
    leaves.at(leaf_count) = opt::get(maybe_leaf);
    leaf_count++;
  }

  leaves.resize(leaf_count);
  return leaves;
}

bytes
State::epoch_authenticator() const
{
  return _key_schedule.epoch_authenticator;
}

LeafIndex
State::leaf_for_roster_entry(RosterIndex index) const
{
  auto non_blank_leaves = uint32_t(0);

  for (auto i = LeafIndex{ 0 }; i < _tree.size; i.val++) {
    const auto& maybe_leaf = _tree.leaf_node(i);
    if (!maybe_leaf) {
      continue;
    }
    if (non_blank_leaves == index.val) {
      return i;
    }
    non_blank_leaves += 1;
  }

  throw InvalidParameterError("Invalid roster index");
}

State
State::successor() const
{
  // Copy everything, then clear things that shouldn't be copied
  auto next = *this;
  next._pending_proposals.clear();
  return next;
}

} // namespace mls
