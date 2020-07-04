#include "state.h"

#include <iostream>

namespace mls {

///
/// Constructors
///

State::State(bytes group_id,
             CipherSuite suite,
             const bytes& init_secret,
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
  _keys.init_secret = zero_bytes(Digest(suite).output_size());

  auto index = _tree.add_leaf(key_package);
  _tree.set_hash_all();
  _tree_priv =
    TreeKEMPrivateKey::create(suite, _tree.size(), index, init_secret);
}

// Initialize a group from a Welcome
State::State(const bytes& init_secret,
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
  auto init_priv = HPKEPrivateKey::derive(kp.cipher_suite, init_secret);
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
    _suite, _tree.size(), _index, init_secret, ancestor, path_secret);

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
  auto pt = MLSPlaintext{ _group_id, _epoch, _index, proposal };
  pt.sign(group_context(), _identity_priv);
  return pt;
}

MLSPlaintext
State::add(const KeyPackage& key_package) const
{
  return sign({ Add{ key_package } });
}

MLSPlaintext
State::update(const bytes& leaf_secret)
{
  // TODO(RLB) Allow changing the signing key
  auto kp = _tree.key_package(_index).value();
  kp.init_key = HPKEPrivateKey::derive(_suite, leaf_secret).public_key();
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
    _group_id,
    _epoch,
    _tree.root_hash(),
    _confirmed_transcript_hash,
  };
}

MLSPlaintext
State::ratchet_and_sign(const Commit& op,
                        const bytes& update_secret,
                        const GroupContext& prev_ctx)
{
  auto pt = MLSPlaintext{ _group_id, _epoch, _index, op };

  _confirmed_transcript_hash = Digest(_suite)
                                 .write(_interim_transcript_hash)
                                 .write(pt.commit_content())
                                 .digest();

  _epoch += 1;
  update_epoch_secrets(update_secret);

  auto& commit_data = std::get<CommitData>(pt.content);
  commit_data.confirmation =
    hmac(_suite, _keys.confirmation_key, _confirmed_transcript_hash);
  pt.sign(prev_ctx, _identity_priv);

  _interim_transcript_hash = Digest(_suite)
                               .write(_confirmed_transcript_hash)
                               .write(pt.commit_auth_data())
                               .digest();

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

  if (pt.sender == _index) {
    throw InvalidParameterError("Handle own commits with caching");
  }

  // Apply the commit
  auto& commit_data = std::get<CommitData>(pt.content);
  State next = *this;
  next.apply(commit_data.commit);

  // Decapsulate and apply the DirectPath
  auto ctx = tls::marshal(GroupContext{
    next._group_id,
    next._epoch + 1,
    next._tree.root_hash(),
    next._confirmed_transcript_hash,
  });
  next._tree_priv.decap(pt.sender, next._tree, ctx, commit_data.commit.path);
  next._tree.merge(pt.sender, commit_data.commit.path);

  // Update the transcripts and advance the key schedule
  next._confirmed_transcript_hash = Digest(_suite)
                                      .write(next._interim_transcript_hash)
                                      .write(pt.commit_content())
                                      .digest();
  next._interim_transcript_hash = Digest(_suite)
                                    .write(next._confirmed_transcript_hash)
                                    .write(pt.commit_auth_data())
                                    .digest();
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
  return ProposalID{ Digest(_suite).write(tls::marshal(pt)).digest() };
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
      if (pt.sender != _index) {
        apply(pt.sender, update);
        break;
      }

      if (_update_secrets.count(id.id) == 0) {
        throw ProtocolError("Self-update with no cached secret");
      }

      apply(pt.sender, update, _update_secrets[id.id]);
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
  MLSPlaintext mpt{ _group_id, _epoch, _index, ApplicationData{ pt } };
  mpt.sign(group_context(), _identity_priv);
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
  auto maybe_kp = _tree.key_package(pt.sender);
  if (!maybe_kp.has_value()) {
    throw InvalidParameterError("Signature from blank node");
  }

  auto pub = maybe_kp.value().credential.public_key();
  return pt.verify(group_context(), pub);
}

bool
State::verify_confirmation(const bytes& confirmation) const
{
  auto confirm =
    hmac(_suite, _keys.confirmation_key, _confirmed_transcript_hash);
  return constant_time_eq(confirm, confirmation);
}

MLSCiphertext
State::encrypt(const MLSPlaintext& pt)
{
  // Pull from the key schedule
  uint32_t generation;
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
  sender_data << _index << generation;

  auto sender_data_nonce = random_bytes(suite_nonce_size(_suite));
  auto sender_data_aad_val =
    sender_data_aad(_group_id, _epoch, content_type, sender_data_nonce);

  auto encrypted_sender_data = seal(_suite,
                                    _keys.sender_data_key,
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
  auto ciphertext = seal(_suite, keys.key, keys.nonce, aad, content);

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
  auto sender_data = open(_suite,
                          _keys.sender_data_key,
                          ct.sender_data_nonce,
                          sender_data_aad_val,
                          ct.encrypted_sender_data);

  tls::istream r(sender_data);
  LeafIndex sender;
  uint32_t generation;
  r >> sender >> generation;

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
  auto content = open(_suite, keys.key, keys.nonce, aad, ct.ciphertext);

  // Set up a new plaintext based on the content
  return MLSPlaintext{
    _group_id, _epoch, sender, ct.content_type, ct.authenticated_data, content
  };
}

} // namespace mls
