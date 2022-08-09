#include <mls/state.h>

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
             const KeyPackage& kp,
             const Welcome& welcome,
             const std::optional<TreeKEMPublicKey>& tree)
  : _suite(welcome.cipher_suite)
  , _epoch(0)
  , _tree(welcome.cipher_suite)
  , _transcript_hash(welcome.cipher_suite)
  , _identity_priv(std::move(sig_priv))
{
  auto maybe_kpi = welcome.find(kp);
  if (!maybe_kpi) {
    throw InvalidParameterError("Welcome not intended for key package");
  }
  auto kpi = opt::get(maybe_kpi);

  if (kp.cipher_suite != welcome.cipher_suite) {
    throw InvalidParameterError("Ciphersuite mismatch");
  }

  // Decrypt the GroupSecrets
  auto secrets_ct = welcome.secrets[kpi].encrypted_group_secrets;
  auto secrets_data = init_priv.decrypt(kp.cipher_suite, {}, {}, secrets_ct);
  auto secrets = tls::get<GroupSecrets>(secrets_data);
  if (!secrets.psks.psks.empty()) {
    throw NotImplementedError(/* PSKs are not supported */);
  }

  // Decrypt the GroupInfo
  auto group_info = welcome.decrypt(secrets.joiner_secret, { /* no PSKs */ });
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
  auto maybe_index = _tree.find(kp.leaf_node);
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
  _key_schedule = KeyScheduleEpoch(
    _suite, secrets.joiner_secret, { /* no PSKs */ }, group_ctx);
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
                     const KeyPackage& kp,
                     const GroupInfo& group_info,
                     const std::optional<TreeKEMPublicKey>& tree,
                     const MessageOpts& msg_opts)
{
  auto initial_state = State(std::move(sig_priv), group_info, tree);

  const auto maybe_external_pub =
    group_info.extensions.find<ExternalPubExtension>();
  if (!maybe_external_pub) {
    throw InvalidParameterError("No external pub in GroupInfo");
  }

  const auto& external_pub = opt::get(maybe_external_pub).external_pub;

  auto add = initial_state.add_proposal(kp);
  auto opts = CommitOpts{ { add }, false, false, {} };
  auto [commit_msg, welcome, state] =
    initial_state.commit(leaf_secret, opts, msg_opts, kp, external_pub);
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
  auto content = MLSContent{ group_id,
                             epoch,
                             { NewMemberProposalSender{} },
                             { /* no authenticated data */ },
                             { std::move(proposal) } };
  auto content_auth = MLSAuthenticatedContent::sign(
    WireFormat::mls_plaintext, std::move(content), suite, sig_priv, {});

  return MLSPlaintext::protect(std::move(content_auth), suite, {}, {});
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
MLSAuthenticatedContent
State::sign(const Sender& sender,
            Inner&& inner_content,
            const bytes& authenticated_data,
            bool encrypt) const
{
  auto content = MLSContent{
    _group_id, _epoch, sender, authenticated_data, { inner_content }
  };

  auto wire_format =
    (encrypt) ? WireFormat::mls_ciphertext : WireFormat::mls_plaintext;

  auto content_auth = MLSAuthenticatedContent::sign(
    wire_format, std::move(content), _suite, _identity_priv, group_context());

  return content_auth;
}

MLSMessage
State::protect(MLSAuthenticatedContent&& content_auth, size_t padding_size)
{
  switch (content_auth.wire_format) {
    case WireFormat::mls_plaintext:
      return MLSPlaintext::protect(std::move(content_auth),
                                   _suite,
                                   _key_schedule.membership_key,
                                   group_context());

    case WireFormat::mls_ciphertext:
      return MLSCiphertext::protect(std::move(content_auth),
                                    _suite,
                                    _index,
                                    _keys,
                                    _key_schedule.sender_data_secret,
                                    padding_size);

    default:
      throw InvalidParameterError("Malformed MLSAuthenticatedContent");
  }
}

MLSAuthenticatedContent
State::unprotect_to_content_auth(const MLSMessage& msg)
{
  const auto unprotect = overloaded{
    [&](const MLSPlaintext& pt) -> MLSAuthenticatedContent {
      auto maybe_content_auth =
        pt.unprotect(_suite, _key_schedule.membership_key, group_context());
      if (!maybe_content_auth) {
        throw ProtocolError("Membership tag failed to verify");
      }
      return opt::get(maybe_content_auth);
    },

    [&](const MLSCiphertext& ct) -> MLSAuthenticatedContent {
      auto maybe_content_auth =
        ct.unprotect(_suite, _tree, _keys, _key_schedule.sender_data_secret);
      if (!maybe_content_auth) {
        throw ProtocolError("MLSCiphertext decryption failure");
      }
      return opt::get(maybe_content_auth);
    },

    [](const auto& /* unused */) -> MLSAuthenticatedContent {
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
State::update_proposal(const bytes& leaf_secret, const LeafNodeOptions& opts)
{
  if (_cached_update) {
    return { opt::get(_cached_update).proposal };
  }

  auto leaf = opt::get(_tree.leaf_node(_index));

  auto public_key = HPKEPrivateKey::derive(_suite, leaf_secret).public_key;
  auto new_leaf =
    leaf.for_update(_suite, _group_id, public_key, opts, _identity_priv);

  auto update = Update{ new_leaf };
  _cached_update = CachedUpdate{ leaf_secret, update };
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

MLSMessage
State::add(const KeyPackage& key_package, const MessageOpts& msg_opts)
{
  return protect_full(add_proposal(key_package), msg_opts);
}

MLSMessage
State::update(const bytes& leaf_secret,
              const LeafNodeOptions& opts,
              const MessageOpts& msg_opts)
{
  return protect_full(update_proposal(leaf_secret, opts), msg_opts);
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
  auto proposals = must_resolve(commit.proposals, _index);
  auto [has_updates, has_removes, joiner_locations] = next.apply(proposals);

  // If this is an external commit, see where the new joiner ended up
  auto sender = Sender{ MemberSender{ _index } };
  if (external_commit) {
    const auto& kp = opt::get(joiner_key_package);
    const auto it = std::find(joiners.begin(), joiners.end(), kp);
    if (it == joiners.end()) {
      throw InvalidParameterError("Joiner not added");
    }

    const auto pos = it - joiners.begin();
    next._index = joiner_locations[pos];
    sender = Sender{ NewMemberCommitSender{} };
  }

  // KEM new entropy to the group and the new joiners
  auto no_proposals = commit.proposals.empty();
  auto path_required =
    has_updates || has_removes || no_proposals || external_commit;
  auto commit_secret = _suite.zero();
  auto path_secrets =
    std::vector<std::optional<bytes>>(joiner_locations.size());
  if (path_required) {
    auto ctx = tls::marshal(GroupContext{
      next._suite,
      next._group_id,
      next._epoch + 1,
      next._tree.root_hash(),
      next._transcript_hash.confirmed,
      next._extensions,
    });

    auto leaf_node_opts = LeafNodeOptions{};
    if (opts) {
      leaf_node_opts = opt::get(opts).leaf_node_opts;
    }

    auto [new_priv, path] = next._tree.encap(next._index,
                                             next._group_id,
                                             ctx,
                                             leaf_secret,
                                             _identity_priv,
                                             joiner_locations,
                                             leaf_node_opts);
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
  next.update_epoch_secrets(
    commit_secret, { /* no PSKs */ }, force_init_secret);

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

  auto welcome = Welcome{
    _suite, next._key_schedule.joiner_secret, { /* no PSKs */ }, group_info
  };
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

  // Validate the MLSContent
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
    // TODO(RLB): We should validate that the proposal makes sense here, e.g.,
    // that an Add KeyPackage is for the right CipherSuite or that a Remove
    // target is actually in the group.
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

  auto next = successor();
  auto [_has_updates, _has_removes, joiner_locations] = next.apply(proposals);
  silence_unused(_has_updates);
  silence_unused(_has_removes);

  // If this is an external Commit, then its direct proposals must meet certain
  // constraints, and we need to identify the sender's location in the new tree.
  auto force_init_secret = std::optional<bytes>{};
  auto sender_location = LeafIndex{ 0 };
  if (sender) {
    sender_location = opt::get(sender);
  }

  if (content.sender.sender_type() == SenderType::new_member_commit) {
    // Extract the forced init secret
    auto kem_output = commit.valid_external();
    if (!kem_output) {
      throw ProtocolError("Invalid external commit");
    }

    force_init_secret =
      _key_schedule.receive_external_init(opt::get(kem_output));

    // Figure out where the new joiner was added by identifying the Add by value
    // in the proposals vector
    auto add_index = size_t(0);
    for (size_t i = 0; i < commit.proposals.size(); i++) {
      if (proposals[i].proposal.proposal_type() != ProposalType::add) {
        continue;
      }

      if (var::holds_alternative<ProposalRef>(commit.proposals[i].content)) {
        add_index += 1;
      } else {
        sender_location = joiner_locations[add_index];
        break;
      }

      if (i == commit.proposals.size() - 1) {
        // If we make it to the end of the loop, we're missing a sender location
        throw ProtocolError("Unable to locate external joiner");
      }
    }
  }

  // Decapsulate and apply the UpdatePath, if provided
  // TODO(RLB) Verify that path is provided if required
  auto commit_secret = _suite.zero();
  if (commit.path) {
    const auto& path = opt::get(commit.path);

    if (path.leaf_node.source() != LeafNodeSource::commit) {
      throw ProtocolError("Commit path leaf node has invalid source");
    }

    if (!next._tree.parent_hash_valid(sender_location, path)) {
      throw ProtocolError("Commit path has invalid parent hash");
    }

    next.check_update_leaf_node(
      sender_location, path.leaf_node, LeafNodeSource::commit);

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
    next._tree.merge(sender_location, path);
    commit_secret = next._tree_priv.update_secret;
  }

  // Update the transcripts and advance the key schedule
  next._transcript_hash.update(content_auth);
  next._epoch += 1;
  next.update_epoch_secrets(
    commit_secret, { /* no PSKs */ }, force_init_secret);

  // Verify the confirmation MAC
  const auto confirmation_tag =
    next._key_schedule.confirmation_tag(next._transcript_hash.confirmed);
  if (!content_auth.check_confirmation_tag(confirmation_tag)) {
    throw ProtocolError("Confirmation failed to verify");
  }

  return next;
}

// A LeafNode in an Add KeyPackage must not have the same leaf_node.public_key
// or signature_key as any KeyPackage for a current member.  The joiner must
// support all credential types in use by other members, and vice versa.
void
State::check_add_leaf_node(const LeafNode& leaf,
                           std::optional<LeafIndex> except) const
{
  for (LeafIndex i{ 0 }; i < _tree.size; i.val++) {
    if (i == except) {
      continue;
    }

    const auto maybe_tree_leaf = _tree.leaf_node(i);
    if (!maybe_tree_leaf) {
      continue;
    }

    const auto& tree_leaf = opt::get(maybe_tree_leaf);
    const auto hpke_key_eq = tree_leaf.encryption_key == leaf.encryption_key;
    const auto sig_key_eq = tree_leaf.signature_key == leaf.signature_key;
    if (hpke_key_eq || sig_key_eq) {
      throw ProtocolError("Duplicate parameters in new KeyPackage");
    }

    if (!leaf.capabilities.credential_supported(tree_leaf.credential)) {
      throw ProtocolError("Member credential not supported by joiner");
    }

    if (!tree_leaf.capabilities.credential_supported(leaf.credential)) {
      throw ProtocolError("Joiner credential not supported by group member");
    }
  }
}

// A KeyPackage in an Update must meet the same uniqueness criteria as for an
// Add, except with regard to the KeyPackage it replaces.
void
State::check_update_leaf_node(LeafIndex target,
                              const LeafNode& leaf,
                              LeafNodeSource required_source) const
{
  check_add_leaf_node(leaf, target);

  if (leaf.source() != required_source) {
    throw ProtocolError("LeafNode in Update has incorrect LeafNodeSource");
  }

  const auto maybe_tree_leaf = _tree.leaf_node(target);
  if (!maybe_tree_leaf) {
    return;
  }

  const auto& tree_leaf = opt::get(maybe_tree_leaf);
  if (tree_leaf.encryption_key == leaf.encryption_key) {
    throw ProtocolError("Update without a fresh init key");
  }
}

LeafIndex
State::apply(const Add& add)
{
  check_add_leaf_node(add.key_package.leaf_node, std::nullopt);
  return _tree.add_leaf(add.key_package.leaf_node);
}

void
State::apply(LeafIndex target, const Update& update)
{
  check_update_leaf_node(target, update.leaf_node, LeafNodeSource::update);
  _tree.update_leaf(target, update.leaf_node);
}

void
State::apply(LeafIndex target, const Update& update, const bytes& leaf_secret)
{
  _tree.update_leaf(target, update.leaf_node);
  _tree_priv.set_leaf_secret(leaf_secret);
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
State::cache_proposal(MLSAuthenticatedContent content_auth)
{
  auto sender_location = std::optional<LeafIndex>();
  if (content_auth.content.sender.sender_type() == SenderType::member) {
    const auto& sender = content_auth.content.sender.sender;
    sender_location = var::get<MemberSender>(sender).sender;
  }

  _pending_proposals.push_back({
    _suite.ref(content_auth),
    var::get<Proposal>(content_auth.content.content),
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

        apply(target, update, cached_update.update_secret);
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

std::tuple<bool, bool, std::vector<LeafIndex>>
State::apply(const std::vector<CachedProposal>& proposals)
{
  auto update_locations = apply(proposals, ProposalType::update);
  auto remove_locations = apply(proposals, ProposalType::remove);
  auto joiner_locations = apply(proposals, ProposalType::add);
  apply(proposals, ProposalType::group_context_extensions);

  // TODO(RLB) Check for unknown / unhandled proposal types.

  auto has_updates = !update_locations.empty();
  auto has_removes = !remove_locations.empty();

  _tree.truncate();
  _tree_priv.truncate(_tree.size);
  _tree.set_hash_all();
  return std::make_tuple(has_updates, has_removes, joiner_locations);
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
    throw ProtocolError("Application data not sent as MLSCiphertext");
  }

  return {
    std::move(content_auth.content.authenticated_data),
    std::move(var::get<ApplicationData>(content_auth.content.content).data),
  };
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
State::verify_internal(const MLSAuthenticatedContent& content_auth) const
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
State::verify_external(const MLSAuthenticatedContent& content_auth) const
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
  const MLSAuthenticatedContent& content_auth) const
{
  const auto& proposal = var::get<Proposal>(content_auth.content.content);
  const auto& add = var::get<Add>(proposal.content);
  const auto& pub = add.key_package.leaf_node.signature_key;
  return content_auth.verify(_suite, pub, group_context());
}

bool
State::verify_new_member_commit(
  const MLSAuthenticatedContent& content_auth) const
{
  const auto& commit = var::get<Commit>(content_auth.content.content);
  const auto& path = opt::get(commit.path);
  const auto& pub = path.leaf_node.signature_key;
  return content_auth.verify(_suite, pub, group_context());
}

bool
State::verify(const MLSAuthenticatedContent& content_auth) const
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
State::authentication_secret() const
{
  return _key_schedule.authentication_secret;
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
