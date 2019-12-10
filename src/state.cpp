#include "state.h"

#define DUMMY_SIG_SCHEME SignatureScheme::P256_SHA256

namespace mls {

///
/// Constructors
///

State::State(bytes group_id,
             CipherSuite suite,
             const DHPrivateKey& leaf_priv,
             const Credential& credential)
  : _suite(suite)
  , _group_id(std::move(group_id))
  , _epoch(0)
  , _tree(leaf_priv, credential)
  , _index(0)
  , _identity_priv(credential.private_key().value())
{
  _keys.suite = suite;
  _keys.init_secret = zero_bytes(Digest(suite).output_size());
}

// Initialize a group from a Welcome
State::State(const std::vector<ClientInitKey>& my_client_init_keys,
             const Welcome& welcome)
  : _suite(welcome.cipher_suite)
  , _tree(welcome.cipher_suite)
  // XXX: The following line does a bogus key generation
  , _identity_priv(SignaturePrivateKey::generate(DUMMY_SIG_SCHEME))
{
  // Identify and decrypt a KeyPackage
  bool found = false;
  ClientInitKey my_cik;
  KeyPackage key_pkg;
  for (const auto& cik : my_client_init_keys) {
    auto hash = cik.hash();
    for (const auto& enc_pkg : welcome.key_packages) {
      found = (hash == enc_pkg.client_init_key_hash);
      if (!found) {
        continue;
      }

      if (cik.cipher_suite != welcome.cipher_suite) {
        throw InvalidParameterError("Ciphersuite mismatch");
      }

      if (!cik.private_key().has_value()) {
        throw InvalidParameterError("No private key for init key");
      }

      if (!cik.credential.private_key().has_value()) {
        throw InvalidParameterError("No signing key for init key");
      }
      _identity_priv = cik.credential.private_key().value();

      auto key_pkg_data =
        cik.private_key().value().decrypt({}, enc_pkg.encrypted_key_package);
      key_pkg = tls::get<KeyPackage>(key_pkg_data);
      my_cik = cik;
      break;
    }

    if (found) {
      break;
    }
  }

  if (!found) {
    throw InvalidParameterError("Unable to decrypt Welcome message");
  }

  // Decrypt the GroupInfo
  auto first_epoch = FirstEpoch::create(_suite, key_pkg.init_secret);
  auto group_info_data =
    AESGCM(first_epoch.group_info_key, first_epoch.group_info_nonce)
      .decrypt(welcome.encrypted_group_info);
  auto group_info = tls::get<GroupInfo>(group_info_data, _suite);

  // Verify the singature on the GroupInfo
  if (!group_info.verify()) {
    throw InvalidParameterError("Invalid GroupInfo");
  }

  // Ingest the KeyPackage and GroupInfo
  _epoch = group_info.epoch;
  _group_id = group_info.group_id;
  _tree = group_info.tree;
  _confirmed_transcript_hash = group_info.confirmed_transcript_hash;
  _interim_transcript_hash = group_info.interim_transcript_hash;

  // Add self to tree
  auto maybe_index = _tree.find(my_cik);
  if (!maybe_index.has_value()) {
    throw InvalidParameterError("New joiner not in tree");
  }

  _index = maybe_index.value();
  _tree.merge(_index, my_cik.private_key().value());

  // Decapsulate the direct path
  auto decap_ctx = tls::marshal(GroupContext{
    group_info.group_id,
    group_info.epoch,
    group_info.tree.root_hash(),
    group_info.prior_confirmed_transcript_hash,
  });
  auto update_secret =
    _tree.decap(group_info.signer_index, decap_ctx, group_info.path);

  // Ratchet forward into the current epoch
  auto group_ctx = tls::marshal(group_context());
  _keys = first_epoch.next(LeafCount{ _tree.size() }, update_secret, group_ctx);

  // Verify the confirmation
  if (!verify_confirmation(group_info.confirmation)) {
    throw ProtocolError("Confirmation failed to verify");
  }
}

std::tuple<Welcome, State>
State::negotiate(const bytes& group_id,
                 const std::vector<ClientInitKey>& my_client_init_keys,
                 const std::vector<ClientInitKey>& client_init_keys,
                 const bytes& commit_secret)
{
  // Negotiate a ciphersuite with the other party
  auto selected = false;
  const ClientInitKey* my_selected_cik = nullptr;
  const ClientInitKey* other_selected_cik = nullptr;
  for (const auto& my_cik : my_client_init_keys) {
    for (const auto& other_cik : client_init_keys) {
      if (my_cik.cipher_suite == other_cik.cipher_suite) {
        selected = true;
        my_selected_cik = &my_cik;
        other_selected_cik = &other_cik;
        break;
      }
    }

    if (selected) {
      break;
    }
  }

  if (!selected) {
    throw ProtocolError("Negotiation failure");
  }

  auto& suite = my_selected_cik->cipher_suite;
  auto& leaf_priv = my_selected_cik->private_key().value();
  auto& cred = my_selected_cik->credential;

  auto state = State{ group_id, suite, leaf_priv, cred };
  auto add = state.add(*other_selected_cik);
  state.handle(add);
  auto [unused_commit, welcome, new_state] = state.commit(commit_secret);
  silence_unused(unused_commit);

  return std::make_tuple(welcome, new_state);
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
State::add(const ClientInitKey& client_init_key) const
{
  return sign(Add{ client_init_key });
}

MLSPlaintext
State::update(const bytes& leaf_secret)
{
  auto key = HPKEPrivateKey::derive(_suite, leaf_secret);
  auto pt = sign(Update{ key.public_key() });

  auto id = proposal_id(pt);
  _update_secrets[id] = leaf_secret;

  return pt;
}

MLSPlaintext
State::remove(LeafIndex removed) const
{
  return sign(Remove{ removed });
}

std::tuple<MLSPlaintext, Welcome, State>
State::commit(const bytes& leaf_secret) const
{
  // Construct a commit from cached proposals
  auto commit = Commit{ _suite };
  auto joiners = std::vector<ClientInitKey>{};
  for (const auto& pt : _pending_proposals) {
    auto id = proposal_id(pt);
    auto proposal = std::get<Proposal>(pt.content);
    switch (proposal.inner_type()) {
      case ProposalType::add: {
        commit.adds.push_back(id);
        auto add = std::get<Add>(proposal);
        joiners.push_back(add.client_init_key);
        break;
      }

      case ProposalType::update:
        commit.updates.push_back(id);
        break;

      case ProposalType::remove:
        commit.removes.push_back(id);
        break;

      default:
        // TODO(rlb) ignore some proposals:
        // * Update after Update
        // * Update after Remove
        // * Remove after Remove
        break;
    }
  }

  // Apply proposals
  State next = *this;
  next.apply(commit);
  next._pending_proposals.clear();

  // Start a GroupInfo with the prepared state
  auto prev_init_secret = bytes(_keys.init_secret);
  auto group_info = GroupInfo(_suite);
  group_info.group_id = next._group_id;
  group_info.epoch = next._epoch + 1;
  group_info.tree = next._tree;
  group_info.prior_confirmed_transcript_hash = _confirmed_transcript_hash;

  // KEM new entropy to the group and the new joiners
  auto ctx = tls::marshal(GroupContext{
    group_info.group_id,
    group_info.epoch,
    group_info.tree.root_hash(),
    group_info.prior_confirmed_transcript_hash,
  });
  auto [path, update_secret] = next._tree.encap(_index, ctx, leaf_secret);
  commit.path = path;

  // Create the Commit message and advance the transcripts / key schedule
  auto pt = next.ratchet_and_sign(commit, update_secret, group_context());

  // Complete the GroupInfo and form the Welcome
  group_info.confirmed_transcript_hash = next._confirmed_transcript_hash;
  group_info.interim_transcript_hash = next._interim_transcript_hash;
  group_info.path = path;
  group_info.confirmation = std::get<CommitData>(pt.content).confirmation;
  group_info.sign(_index, _identity_priv);

  auto welcome = Welcome{ _suite, prev_init_secret, group_info };
  for (const auto& joiner : joiners) {
    welcome.encrypt(joiner);
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
  auto content_type = pt.content.inner_type();
  if (content_type == ContentType::proposal) {
    _pending_proposals.push_back(pt);
    return std::nullopt;
  }

  if (content_type != ContentType::commit) {
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
  auto update_secret =
    next._tree.decap(pt.sender, ctx, commit_data.commit.path);

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
  next.update_epoch_secrets(update_secret);

  // Verify the confirmation MAC
  if (!next.verify_confirmation(commit_data.confirmation)) {
    throw ProtocolError("Confirmation failed to verify");
  }

  return next;
}

void
State::apply(const Add& add)
{
  auto target = _tree.leftmost_free();
  _tree.add_leaf(
    target, add.client_init_key.init_key, add.client_init_key.credential);
}

void
State::apply(LeafIndex target, const Update& update)
{
  _tree.blank_path(target, false);
  _tree.merge(target, update.leaf_key);
}

void
State::apply(LeafIndex target, const bytes& leaf_secret)
{
  _tree.blank_path(target, false);
  _tree.merge(target, leaf_secret);
}

void
State::apply(const Remove& remove)
{
  _tree.blank_path(remove.removed, true);
}

bytes
State::proposal_id(const MLSPlaintext& pt) const
{
  return Digest(_suite).write(tls::marshal(pt)).digest();
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

void
State::apply(const std::vector<ProposalID>& ids)
{
  for (const auto& id : ids) {
    auto maybe_pt = find_proposal(id);
    if (!maybe_pt.has_value()) {
      throw ProtocolError("Commit of unknown proposal");
    }

    auto pt = maybe_pt.value();
    auto proposal = std::get<Proposal>(pt.content);
    switch (proposal.inner_type()) {
      case ProposalType::add:
        apply(std::get<Add>(proposal));
        break;
      case ProposalType::update:
        if (pt.sender != _index) {
          apply(pt.sender, std::get<Update>(proposal));
          break;
        }

        if (_update_secrets.count(id) == 0) {
          throw ProtocolError("Self-update with no cached secret");
        }

        apply(pt.sender, _update_secrets[id]);
        break;
      case ProposalType::remove:
        apply(std::get<Remove>(proposal));
        break;
      default:
        throw InvalidParameterError("Invalid proposal type");
        break;
    }
  }
}

void
State::apply(const Commit& commit)
{
  apply(commit.updates);
  apply(commit.removes);
  apply(commit.adds);

  _tree.truncate(_tree.leaf_span());
}

///
/// Message protection
///

MLSCiphertext
State::protect(const bytes& pt)
{
  MLSPlaintext mpt{ _group_id, _epoch, _index, pt };
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

  if (pt.content.inner_type() != ContentType::application) {
    throw ProtocolError("Unprotect of non-application message");
  }

  // NOLINTNEXTLINE(cppcoreguidelines-slicing)
  return static_cast<bytes>(std::get<ApplicationData>(pt.content));
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
content_aad(const tls::opaque<1>& group_id,
            uint32_t epoch,
            ContentType content_type,
            const tls::opaque<4>& authenticated_data,
            const tls::opaque<1>& sender_data_nonce,
            const tls::opaque<1>& encrypted_sender_data)
{
  tls::ostream w;
  w << group_id << epoch << content_type << authenticated_data
    << sender_data_nonce << encrypted_sender_data;
  return w.bytes();
}

// struct {
//     opaque group_id<0..255>;
//     uint32 epoch;
//     ContentType content_type;
//     opaque sender_data_nonce<0..255>;
// } MLSCiphertextSenderDataAAD;
static bytes
sender_data_aad(const tls::opaque<1>& group_id,
                uint32_t epoch,
                ContentType content_type,
                const tls::opaque<1>& sender_data_nonce)
{
  tls::ostream w;
  w << group_id << epoch << content_type << sender_data_nonce;
  return w.bytes();
}

bool
State::verify(const MLSPlaintext& pt) const
{
  auto pub = _tree.get_credential(pt.sender).public_key();
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
  switch (pt.content.inner_type()) {
    case ContentType::application:
      std::tie(generation, keys) = _keys.application_keys.next(_index);
      break;

    case ContentType::proposal:
    case ContentType::commit:
      std::tie(generation, keys) = _keys.handshake_keys.next(_index);
      break;

    default:
      throw InvalidParameterError("Unknown content type");
  }

  // Encrypt the sender data
  tls::ostream sender_data;
  sender_data << _index << generation;

  auto sender_data_nonce = random_bytes(AESGCM::nonce_size);
  auto sender_data_aad_val = sender_data_aad(
    _group_id, _epoch, pt.content.inner_type(), sender_data_nonce);

  auto sender_data_gcm = AESGCM(_keys.sender_data_key, sender_data_nonce);
  sender_data_gcm.set_aad(sender_data_aad_val);
  auto encrypted_sender_data = sender_data_gcm.encrypt(sender_data.bytes());

  // Compute the plaintext input and AAD
  // XXX(rlb@ipv.sx): Apply padding?
  auto content = pt.marshal_content(0);
  auto aad = content_aad(_group_id,
                         _epoch,
                         pt.content.inner_type(),
                         pt.authenticated_data,
                         sender_data_nonce,
                         encrypted_sender_data);

  // Encrypt the plaintext
  auto gcm = AESGCM(keys.key, keys.nonce);
  gcm.set_aad(aad);
  auto ciphertext = gcm.encrypt(content);

  // Assemble the MLSCiphertext
  MLSCiphertext ct;
  ct.group_id = _group_id;
  ct.epoch = _epoch;
  ct.content_type = pt.content.inner_type();
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

  auto sender_data_gcm = AESGCM(_keys.sender_data_key, ct.sender_data_nonce);
  sender_data_gcm.set_aad(sender_data_aad_val);
  auto sender_data = sender_data_gcm.decrypt(ct.encrypted_sender_data);

  tls::istream r(sender_data);
  LeafIndex sender;
  uint32_t generation;
  r >> sender >> generation;

  if (!_tree.occupied(sender)) {
    throw ProtocolError("Encryption from unoccupied leaf");
  }

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
  auto gcm = AESGCM(keys.key, keys.nonce);
  gcm.set_aad(aad);
  auto content = gcm.decrypt(ct.ciphertext);

  // Set up a new plaintext based on the content
  return MLSPlaintext{ _suite, _group_id,       _epoch,
                       sender, ct.content_type, ct.authenticated_data,
                       content };
}

} // namespace mls
