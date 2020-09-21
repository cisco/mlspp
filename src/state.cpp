#include "mls/state.h"

namespace mls {

///
/// Constructors
///

State::State(bytes group_id,
             CipherSuite suite,
             const HPKEPrivateKey& init_priv,
             SignaturePrivateKey sig_priv,
             const KeyPackage& key_package)
  : _suite(suite)
  , _group_id(std::move(group_id))
  , _epoch(0)
  , _tree(suite)
  , _index(0)
  , _identity_priv(std::move(sig_priv))
{
  _keys.suite = suite;
  _keys.init_secret = bytes(suite.get().digest.hash_size(), 0);

  auto index = _tree.add_leaf(key_package);
  _tree.set_hash_all();
  _tree_priv = TreeKEMPrivateKey::solo(suite, index, init_priv);
}

// Initialize a group from a Welcome
State::State(const HPKEPrivateKey& init_priv,
             SignaturePrivateKey sig_priv,
             const KeyPackage& kp,
             const Welcome& welcome)
  : _suite(welcome.cipher_suite)
  , _tree(welcome.cipher_suite)
  , _identity_priv(std::move(sig_priv))
{
  auto maybe_kpi = welcome.find(kp);
  if (!maybe_kpi.has_value()) {
    throw InvalidParameterError("Welcome not intended for key package");
  }
  auto kpi = maybe_kpi.value();

  if (kp.cipher_suite != welcome.cipher_suite) {
    throw InvalidParameterError("Ciphersuite mismatch");
  }

  // Decrypt the GroupSecrets
  auto secrets_ct = welcome.secrets[kpi].encrypted_group_secrets;
  auto secrets_data = init_priv.decrypt(kp.cipher_suite, {}, secrets_ct);
  auto secrets = tls::get<GroupSecrets>(secrets_data);

  // Decrypt the GroupInfo and fill in details
  auto group_info = welcome.decrypt(secrets.epoch_secret);
  group_info.tree.suite = kp.cipher_suite;
  group_info.tree.set_hash_all();

  // Verify the signature on the GroupInfo
  if (!group_info.verify()) {
    throw InvalidParameterError("Invalid GroupInfo");
  }

  // Ingest the GroupSecrets and GroupInfo
  _epoch = group_info.epoch;
  _group_id = group_info.group_id;
  _tree = group_info.tree;
  _confirmed_transcript_hash = group_info.confirmed_transcript_hash;
  _interim_transcript_hash = group_info.interim_transcript_hash;

  // Construct TreeKEM private key from partrs provided
  auto maybe_index = _tree.find(kp);
  if (!maybe_index.has_value()) {
    throw InvalidParameterError("New joiner not in tree");
  }

  _index = maybe_index.value();

  auto ancestor = tree_math::ancestor(_index, group_info.signer_index);
  auto path_secret = std::optional<bytes>{};
  if (secrets.path_secret.has_value()) {
    path_secret = secrets.path_secret.value().secret;
  }

  _tree_priv = TreeKEMPrivateKey::joiner(
    _suite, _tree.size(), _index, init_priv, ancestor, path_secret);

  // Ratchet forward into the current epoch
  auto group_ctx = tls::marshal(group_context());
  _keys = KeyScheduleEpoch::create(
    _suite, LeafCount(_tree.size()), secrets.epoch_secret, group_ctx);

  // Verify the confirmation
  if (!verify_confirmation(group_info.confirmation)) {
    throw ProtocolError("Confirmation failed to verify");
  }
}

///
/// Proposal and commit factories
///

MLSPlaintext
State::sign(const Proposal& proposal) const
{
  auto sender = Sender{ SenderType::member, _index.val };
  auto pt = MLSPlaintext{ _group_id, _epoch, sender, proposal };
  pt.sign(_suite, group_context(), _identity_priv);
  return pt;
}

MLSPlaintext
State::add(const KeyPackage& key_package) const
{
  // Check that the key package is validly signed
  if (!key_package.verify()) {
    throw InvalidParameterError("Invalid signature on key package");
  }

  // Check that the group's basic properties are supported
  auto now = seconds_since_epoch();
  if (!key_package.verify_expiry(now)) {
    throw InvalidParameterError("Expired key package");
  }

  // Check that the group's extensions are supported
  if (!key_package.verify_extension_support(_extensions)) {
    throw InvalidParameterError(
      "Key package does not support group's extensions");
  }

  return sign({ Add{ key_package } });
}

MLSPlaintext
State::update(const bytes& leaf_secret)
{
  // TODO(RLB) Allow changing the signing key
  auto kp = _tree.key_package(_index).value();
  kp.init_key = HPKEPrivateKey::derive(_suite, leaf_secret).public_key;
  kp.sign(_identity_priv, std::nullopt);

  auto pt = sign({ Update{ kp } });

  auto id = proposal_id(pt);
  _update_secrets[id.id] = leaf_secret;

  return pt;
}

MLSPlaintext
State::remove(LeafIndex removed) const
{
  return sign({ Remove{ removed } });
}

std::tuple<MLSPlaintext, Welcome, State>
State::commit(const bytes& leaf_secret) const
{
  // Construct a commit from cached proposals
  // TODO(rlb) ignore some proposals:
  // * Update after Update
  // * Update after Remove
  // * Remove after Remove
  Commit commit;
  auto joiners = std::vector<KeyPackage>{};
  for (const auto& pt : _pending_proposals) {
    auto id = proposal_id(pt);
    auto proposal = std::get<Proposal>(pt.content).content;
    if (std::holds_alternative<Add>(proposal)) {
      commit.adds.push_back(id);
      auto add = std::get<Add>(proposal);
      joiners.push_back(add.key_package);
    } else if (std::holds_alternative<Update>(proposal)) {
      commit.updates.push_back(id);
    } else if (std::holds_alternative<Remove>(proposal)) {
      commit.removes.push_back(id);
    }
  }

  // Apply proposals
  State next = *this;
  auto joiner_locations = next.apply(commit);
  next._pending_proposals.clear();

  // KEM new entropy to the group and the new joiners
  auto ctx = tls::marshal(GroupContext{
    next._group_id,
    next._epoch + 1,
    next._tree.root_hash(),
    next._confirmed_transcript_hash,
    next._extensions,
  });
  auto [new_priv, path] =
    next._tree.encap(_index, ctx, leaf_secret, _identity_priv, std::nullopt);
  next._tree_priv = new_priv;
  commit.path = path;

  // Create the Commit message and advance the transcripts / key schedule
  auto pt =
    next.ratchet_and_sign(commit, new_priv.update_secret, group_context());

  // Complete the GroupInfo and form the Welcome
  auto group_info = GroupInfo{
    next._group_id,
    next._epoch,
    next._tree,
    next._confirmed_transcript_hash,
    next._interim_transcript_hash,
    next._extensions,
    std::get<CommitData>(pt.content).confirmation,
  };
  group_info.sign(_index, _identity_priv);

  auto welcome = Welcome{ _suite, next._keys.epoch_secret, group_info };
  for (size_t i = 0; i < joiners.size(); i++) {
    auto [overlap, path_secret, ok] =
      new_priv.shared_path_secret(joiner_locations[i]);
    silence_unused(overlap);
    silence_unused(ok);
    welcome.encrypt(joiners[i], path_secret);
  }

  return std::make_tuple(pt, welcome, next);
}

///
/// Message handlers
///

GroupContext
State::group_context() const
{
  return GroupContext{
    _group_id,   _epoch, _tree.root_hash(), _confirmed_transcript_hash,
    _extensions,
  };
}

MLSPlaintext
State::ratchet_and_sign(const Commit& op,
                        const bytes& update_secret,
                        const GroupContext& prev_ctx)
{
  auto sender = Sender{ SenderType::member, _index.val };
  auto pt = MLSPlaintext{ _group_id, _epoch, sender, op };

  auto confirmed_transcript = _interim_transcript_hash + pt.commit_content();
  _confirmed_transcript_hash = _suite.get().digest.hash(confirmed_transcript);
  _epoch += 1;
  update_epoch_secrets(update_secret);

  auto& commit_data = std::get<CommitData>(pt.content);
  commit_data.confirmation = _suite.get().digest.hmac(
    _keys.confirmation_key, _confirmed_transcript_hash);
  pt.sign(_suite, prev_ctx, _identity_priv);

  auto interim_transcript = _confirmed_transcript_hash + pt.commit_auth_data();
  _interim_transcript_hash = _suite.get().digest.hash(interim_transcript);

  return pt;
}

std::optional<State>
State::handle(const MLSPlaintext& pt)
{
  // Pre-validate the MLSPlaintext
  if (pt.group_id != _group_id) {
    throw InvalidParameterError("GroupID mismatch");
  }

  if (pt.epoch != _epoch) {
    throw InvalidParameterError("Epoch mismatch");
  }

  if (!verify(pt)) {
    throw ProtocolError("Invalid handshake message signature");
  }

  // Proposals get queued, do not result in a state transition
  if (std::holds_alternative<Proposal>(pt.content)) {
    _pending_proposals.push_back(pt);
    return std::nullopt;
  }

  if (!std::holds_alternative<CommitData>(pt.content)) {
    throw InvalidParameterError("Incorrect content type");
  }

  if (pt.sender.sender_type != SenderType::member) {
    throw ProtocolError("Commit must originate from within the group");
  }
  auto sender = LeafIndex(pt.sender.sender);

  if (sender == _index) {
    throw InvalidParameterError("Handle own commits with caching");
  }

  // Apply the commit
  const auto& commit_data = std::get<CommitData>(pt.content);
  State next = *this;
  next.apply(commit_data.commit);

  // Decapsulate and apply the DirectPath
  auto ctx = tls::marshal(GroupContext{
    next._group_id,
    next._epoch + 1,
    next._tree.root_hash(),
    next._confirmed_transcript_hash,
    next._extensions,
  });
  next._tree_priv.decap(sender, next._tree, ctx, commit_data.commit.path);
  next._tree.merge(sender, commit_data.commit.path);

  // Update the transcripts and advance the key schedule
  next._confirmed_transcript_hash = _suite.get().digest.hash(
    next._interim_transcript_hash + pt.commit_content());
  next._interim_transcript_hash = _suite.get().digest.hash(
    next._confirmed_transcript_hash + pt.commit_auth_data());

  next._epoch += 1;
  next.update_epoch_secrets(next._tree_priv.update_secret);

  // Verify the confirmation MAC
  if (!next.verify_confirmation(commit_data.confirmation)) {
    throw ProtocolError("Confirmation failed to verify");
  }

  return next;
}

LeafIndex
State::apply(const Add& add)
{
  return _tree.add_leaf(add.key_package);
}

void
State::apply(LeafIndex target, const Update& update)
{
  _tree.update_leaf(target, update.key_package);
}

void
State::apply(LeafIndex target, const Update& update, const bytes& leaf_secret)
{
  _tree.update_leaf(target, update.key_package);
  _tree_priv.set_leaf_secret(leaf_secret);
}

void
State::apply(const Remove& remove)
{
  _tree.blank_path(remove.removed);
}

ProposalID
State::proposal_id(const MLSPlaintext& pt) const
{
  return ProposalID{ _suite.get().digest.hash(tls::marshal(pt)) };
}

std::optional<MLSPlaintext>
State::find_proposal(const ProposalID& id)
{
  for (auto i = _pending_proposals.begin(); i != _pending_proposals.end();
       i++) {
    auto other_id = proposal_id(*i);
    if (id == other_id) {
      auto pt = *i;
      _pending_proposals.erase(i);
      return pt;
    }
  }

  return std::nullopt;
}

std::vector<LeafIndex>
State::apply(const std::vector<ProposalID>& ids)
{
  auto joiner_locations = std::vector<LeafIndex>{};
  for (const auto& id : ids) {
    auto maybe_pt = find_proposal(id);
    if (!maybe_pt.has_value()) {
      throw ProtocolError("Commit of unknown proposal");
    }

    auto pt = maybe_pt.value();
    auto proposal = std::get<Proposal>(pt.content).content;
    if (std::holds_alternative<Add>(proposal)) {
      joiner_locations.push_back(apply(std::get<Add>(proposal)));
    } else if (std::holds_alternative<Update>(proposal)) {
      auto& update = std::get<Update>(proposal);
      auto sender = LeafIndex(pt.sender.sender);
      if (sender != _index) {
        apply(sender, update);
        break;
      }

      if (_update_secrets.count(id.id) == 0) {
        throw ProtocolError("Self-update with no cached secret");
      }

      apply(sender, update, _update_secrets[id.id]);
    } else if (std::holds_alternative<Remove>(proposal)) {
      apply(std::get<Remove>(proposal));
    } else {
      throw InvalidParameterError("Invalid proposal type");
    }
  }

  return joiner_locations;
}

std::vector<LeafIndex>
State::apply(const Commit& commit)
{
  apply(commit.updates);
  apply(commit.removes);
  auto joiner_locations = apply(commit.adds);

  _tree.truncate();
  _tree_priv.truncate(_tree.size());
  _tree.set_hash_all();
  return joiner_locations;
}

///
/// Message protection
///

MLSCiphertext
State::protect(const bytes& pt)
{
  auto sender = Sender{ SenderType::member, _index.val };
  MLSPlaintext mpt{ _group_id, _epoch, sender, ApplicationData{ pt } };
  mpt.sign(_suite, group_context(), _identity_priv);
  return encrypt(mpt);
}

bytes
State::unprotect(const MLSCiphertext& ct)
{
  MLSPlaintext pt = decrypt(ct);

  if (!verify(pt)) {
    throw ProtocolError("Invalid message signature");
  }

  if (!std::holds_alternative<ApplicationData>(pt.content)) {
    throw ProtocolError("Unprotect of non-application message");
  }

  // NOLINTNEXTLINE(cppcoreguidelines-slicing)
  return std::get<ApplicationData>(pt.content).data;
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
  auto confirmed_transcript_hash =
    (lhs._confirmed_transcript_hash == rhs._confirmed_transcript_hash);
  auto interim_transcript_hash =
    (lhs._interim_transcript_hash == rhs._interim_transcript_hash);
  auto keys = (lhs._keys == rhs._keys);

  return suite && group_id && epoch && tree && confirmed_transcript_hash &&
         interim_transcript_hash && keys;
}

bool
operator!=(const State& lhs, const State& rhs)
{
  return !(lhs == rhs);
}

void
State::update_epoch_secrets(const bytes& update_secret)
{
  auto ctx = tls::marshal(GroupContext{
    _group_id,
    _epoch,
    _tree.root_hash(),
    _confirmed_transcript_hash,
    _extensions,
  });
  _keys = _keys.next(LeafCount{ _tree.size() }, update_secret, ctx);
}

///
/// Message encryption and decryption
///

// struct {
//     opaque group_id<0..255>;
//     uint32 epoch;
//     ContentType content_type;
//     opaque sender_data_nonce<0..255>;
//     opaque encrypted_sender_data<0..255>;
// } MLSCiphertextContentAAD;
static bytes
content_aad(const bytes& group_id,
            uint32_t epoch,
            ContentType content_type,
            const bytes& authenticated_data,
            const bytes& sender_data_nonce,
            const bytes& encrypted_sender_data)
{
  tls::ostream w;
  tls::vector<1>::encode(w, group_id);
  w << epoch << content_type;
  tls::vector<4>::encode(w, authenticated_data);
  tls::vector<1>::encode(w, sender_data_nonce);
  tls::vector<1>::encode(w, encrypted_sender_data);
  return w.bytes();
}

// struct {
//     opaque group_id<0..255>;
//     uint32 epoch;
//     ContentType content_type;
//     opaque sender_data_nonce<0..255>;
// } MLSCiphertextSenderDataAAD;
static bytes
sender_data_aad(const bytes& group_id,
                uint32_t epoch,
                ContentType content_type,
                const bytes& sender_data_nonce)
{
  tls::ostream w;
  tls::vector<1>::encode(w, group_id);
  w << epoch << content_type;
  tls::vector<1>::encode(w, sender_data_nonce);
  return w.bytes();
}

bool
State::verify(const MLSPlaintext& pt) const
{
  if (pt.sender.sender_type != SenderType::member) {
    // TODO(RLB) Support external senders
    throw InvalidParameterError("External senders not supported");
  }

  auto maybe_kp = _tree.key_package(LeafIndex(pt.sender.sender));
  if (!maybe_kp.has_value()) {
    throw InvalidParameterError("Signature from blank node");
  }

  auto pub = maybe_kp.value().credential.public_key();
  return pt.verify(_suite, group_context(), pub);
}

bool
State::verify_confirmation(const bytes& confirmation) const
{
  auto confirm = _suite.get().digest.hmac(_keys.confirmation_key,
                                          _confirmed_transcript_hash);
  return constant_time_eq(confirm, confirmation);
}

MLSCiphertext
State::encrypt(const MLSPlaintext& pt)
{
  // Pull from the key schedule
  uint32_t generation = 0;
  KeyAndNonce keys;
  ContentType content_type;
  if (std::holds_alternative<ApplicationData>(pt.content)) {
    std::tie(generation, keys) = _keys.application_keys.next(_index);
    content_type = ContentType::application;
  } else if (std::holds_alternative<Proposal>(pt.content)) {
    std::tie(generation, keys) = _keys.handshake_keys.next(_index);
    content_type = ContentType::proposal;
  } else if (std::holds_alternative<CommitData>(pt.content)) {
    std::tie(generation, keys) = _keys.handshake_keys.next(_index);
    content_type = ContentType::commit;
  } else {
    throw InvalidParameterError("Unknown content type");
  }

  // Encrypt the sender data
  tls::ostream sender_data;
  sender_data << Sender{ SenderType::member, _index.val } << generation;

  auto sender_data_nonce = random_bytes(_suite.get().hpke.aead.nonce_size());
  auto sender_data_aad_val =
    sender_data_aad(_group_id, _epoch, content_type, sender_data_nonce);

  auto encrypted_sender_data =
    _suite.get().hpke.aead.seal(_keys.sender_data_key,
                                sender_data_nonce,
                                sender_data_aad_val,
                                sender_data.bytes());

  // Compute the plaintext input and AAD
  // XXX(rlb@ipv.sx): Apply padding?
  auto content = pt.marshal_content(0);
  auto aad = content_aad(_group_id,
                         _epoch,
                         content_type,
                         pt.authenticated_data,
                         sender_data_nonce,
                         encrypted_sender_data);

  // Encrypt the plaintext
  auto ciphertext =
    _suite.get().hpke.aead.seal(keys.key, keys.nonce, aad, content);

  // Assemble the MLSCiphertext
  MLSCiphertext ct;
  ct.group_id = _group_id;
  ct.epoch = _epoch;
  ct.content_type = content_type;
  ct.sender_data_nonce = sender_data_nonce;
  ct.encrypted_sender_data = encrypted_sender_data;
  ct.authenticated_data = pt.authenticated_data;
  ct.ciphertext = ciphertext;
  return ct;
}

MLSPlaintext
State::decrypt(const MLSCiphertext& ct)
{
  // Verify the epoch
  if (ct.group_id != _group_id) {
    throw InvalidParameterError("Ciphertext not from this group");
  }

  if (ct.epoch != _epoch) {
    throw InvalidParameterError("Ciphertext not from this epoch");
  }

  // Decrypt and parse the sender data
  auto sender_data_aad_val = sender_data_aad(
    ct.group_id, ct.epoch, ct.content_type, ct.sender_data_nonce);
  auto sender_data = _suite.get().hpke.aead.open(_keys.sender_data_key,
                                                 ct.sender_data_nonce,
                                                 sender_data_aad_val,
                                                 ct.encrypted_sender_data);
  if (!sender_data.has_value()) {
    throw ProtocolError("Sender data decryption failed");
  }

  tls::istream r(sender_data.value());
  Sender raw_sender;
  uint32_t generation = 0;
  r >> raw_sender >> generation;

  if (raw_sender.sender_type != SenderType::member) {
    throw InvalidParameterError("Encrypted message from non-member");
  }
  auto sender = LeafIndex(raw_sender.sender);

  // Pull from the key schedule
  KeyAndNonce keys;
  switch (ct.content_type) {
    // TODO(rlb) Enable decryption of proposal / commit
    case ContentType::application:
      keys = _keys.application_keys.get(sender, generation);
      _keys.application_keys.erase(sender, generation);
      break;

    case ContentType::proposal:
    case ContentType::commit:
      keys = _keys.handshake_keys.get(sender, generation);
      _keys.handshake_keys.erase(sender, generation);
      break;

    default:
      throw InvalidParameterError("Unknown content type");
  }

  // Compute the plaintext AAD and decrypt
  auto aad = content_aad(ct.group_id,
                         ct.epoch,
                         ct.content_type,
                         ct.authenticated_data,
                         ct.sender_data_nonce,
                         ct.encrypted_sender_data);
  auto content =
    _suite.get().hpke.aead.open(keys.key, keys.nonce, aad, ct.ciphertext);
  if (!content.has_value()) {
    throw ProtocolError("Content decryption failed");
  }

  // Set up a new plaintext based on the content
  return MLSPlaintext{
    _group_id,      _epoch, raw_sender, ct.content_type, ct.authenticated_data,
    content.value()
  };
}

} // namespace mls
