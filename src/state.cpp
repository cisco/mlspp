#include "state.h"

#define DUMMY_SIG_SCHEME SignatureScheme::P256_SHA256

namespace mls {

///
/// KeyChain
///

KeyChain::KeyChain(CipherSuite suite)
  : _suite(suite)
  , _my_generation(0)
  , _secret_size(Digest(suite).output_size())
  , _key_size(AESGCM::key_size(suite))
  , _nonce_size(AESGCM::nonce_size)
{}

const char* KeyChain::_secret_label = "sender";
const char* KeyChain::_nonce_label = "nonce";
const char* KeyChain::_key_label = "key";

void
KeyChain::start(LeafIndex my_sender, const bytes& root_secret)
{
  _my_generation = 0;
  _my_sender = my_sender;
  _root_secret = root_secret;
}

KeyChain::Generation
KeyChain::next()
{
  _my_generation += 1;
  return get(_my_sender, _my_generation);
}

KeyChain::Generation
KeyChain::get(LeafIndex sender, uint32_t generation) const
{
  auto sender_bytes = tls::marshal(sender.val);
  auto secret = _root_secret;

  // Split off onto the sender chain
  secret = derive(secret, _secret_label, sender_bytes, _secret_size);

  // Work down the generations
  for (uint32_t i = 0; i < generation; ++i) {
    secret = derive(secret, _secret_label, sender_bytes, _secret_size);
  }

  auto key = hkdf_expand_label(_suite, secret, _key_label, {}, _key_size);
  auto nonce = hkdf_expand_label(_suite, secret, _nonce_label, {}, _nonce_size);

  return Generation{ generation, secret, key, nonce };
}

bytes
KeyChain::derive(const bytes& secret,
                 const std::string& label,
                 const bytes& context,
                 const size_t size) const
{
  return hkdf_expand_label(_suite, secret, label, context, size);
}

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
  , _init_secret(Digest(suite).output_size())
  , _application_keys(suite)
  , _index(0)
  , _identity_priv(credential.private_key().value())
  , _zero(Digest(suite).output_size(), 0)
{}

// Initialize a group from a Welcome
State::State(const std::vector<ClientInitKey>& my_client_init_keys,
             const Welcome& welcome)
  : _suite(welcome.cipher_suite)
  , _tree(welcome.cipher_suite)
  , _application_keys(welcome.cipher_suite)
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
        cik.private_key().value().decrypt(enc_pkg.encrypted_key_package);
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
  auto [key, nonce] = welcome.group_info_keymat(key_pkg.init_secret);
  auto group_info_data =
    AESGCM(key, nonce).decrypt(welcome.encrypted_group_info);
  auto group_info = tls::get<GroupInfo>(group_info_data, _suite);

  // Verify the singature on the GroupInfo
  if (!group_info.verify()) {
    throw InvalidParameterError("Invalid GroupInfo");
  }

  // Ingest the KeyPackage and GroupInfo
  _init_secret = key_pkg.init_secret;
  _epoch = group_info.epoch;
  _group_id = group_info.group_id;
  _tree = group_info.tree;
  _confirmed_transcript_hash = group_info.confirmed_transcript_hash;
  _interim_transcript_hash = group_info.interim_transcript_hash;
  _zero = bytes(Digest(_suite).output_size(), 0);

  // Add self to tree
  auto maybe_index = _tree.find(my_cik);
  if (!maybe_index.has_value()) {
    throw InvalidParameterError("New joiner not in tree");
  }

  _index = maybe_index.value();
  _tree.merge(_index, my_cik.private_key().value());

  // Decapsulate the direct path
  auto update_secret = _tree.decap(group_info.signer_index, group_info.path);

  // Ratchet forward into the current epoch
  update_epoch_secrets(update_secret);

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
  pt.sign(_identity_priv);
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
  auto prev_init_secret = bytes(next._init_secret);
  auto group_info = GroupInfo(_suite);
  group_info.group_id = next._group_id;
  group_info.epoch = next._epoch + 1;
  group_info.tree = next._tree;

  // KEM new entropy to the group and the new joiners
  auto [path, update_secret] = next._tree.encap(_index, leaf_secret);
  commit.path = path;

  // Create the Commit message and advance the transcripts / key schedule
  auto pt = next.ratchet_and_sign(commit, update_secret);

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

MLSPlaintext
State::ratchet_and_sign(const Commit& op, const bytes& update_secret)
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
    hmac(_suite, _confirmation_key, _confirmed_transcript_hash);
  pt.sign(_identity_priv);

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
  auto update_secret = next._tree.decap(pt.sender, commit_data.commit.path);

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

bytes
State::next_epoch_secret(CipherSuite suite,
                         const bytes& init_secret,
                         const bytes& update_secret)
{
  return hkdf_extract(suite, init_secret, update_secret);
}

State::EpochSecrets
State::derive_epoch_secrets(CipherSuite suite,
                            const bytes& epoch_secret,
                            const GroupContext& group_context)
{
  auto ctx = tls::marshal(group_context);
  return {
    epoch_secret,
    derive_secret(suite, epoch_secret, "app", ctx),
    derive_secret(suite, epoch_secret, "handshake", ctx),
    derive_secret(suite, epoch_secret, "sender data", ctx),
    derive_secret(suite, epoch_secret, "confirm", ctx),
    derive_secret(suite, epoch_secret, "init", ctx),
  };
}

///
/// Message protection
///

MLSCiphertext
State::protect(const bytes& pt)
{
  MLSPlaintext mpt{ _group_id, _epoch, _index, pt };
  mpt.sign(_identity_priv);
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

  auto epoch_secret = (lhs._epoch_secret == rhs._epoch_secret);
  auto application_secret =
    (lhs._application_secret == rhs._application_secret);
  auto confirmation_key = (lhs._confirmation_key == rhs._confirmation_key);
  auto init_secret = (lhs._init_secret == rhs._init_secret);

  return suite && group_id && epoch && tree && confirmed_transcript_hash &&
         interim_transcript_hash && epoch_secret && application_secret &&
         confirmation_key && init_secret;
}

bool
operator!=(const State& lhs, const State& rhs)
{
  return !(lhs == rhs);
}

void
State::update_epoch_secrets(const bytes& update_secret)
{
  auto epoch_secret = next_epoch_secret(_suite, _init_secret, update_secret);
  auto ctx = GroupContext{
    _group_id,
    _epoch,
    _tree.root_hash(),
    _confirmed_transcript_hash,
  };
  auto secrets = derive_epoch_secrets(_suite, epoch_secret, ctx);

  _epoch_secret = secrets.epoch_secret;
  _application_secret = secrets.application_secret;
  _handshake_secret = secrets.handshake_secret;
  _sender_data_secret = secrets.sender_data_secret;
  _confirmation_key = secrets.confirmation_key;
  _init_secret = secrets.init_secret;

  auto key_size = AESGCM::key_size(_suite);
  _sender_data_key =
    hkdf_expand_label(_suite, _sender_data_secret, "sd key", {}, key_size);
  _handshake_key_used.clear();

  _application_keys.start(_index, _application_secret);
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
            const tls::opaque<1>& sender_data_nonce,
            const tls::opaque<1>& encrypted_sender_data)
{
  tls::ostream w;
  w << group_id << epoch << content_type << sender_data_nonce
    << encrypted_sender_data;
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
  return pt.verify(pub);
}

bool
State::verify_confirmation(const bytes& confirmation) const
{
  auto confirm = hmac(_suite, _confirmation_key, _confirmed_transcript_hash);
  return constant_time_eq(confirm, confirmation);
}

KeyChain::Generation
State::generate_handshake_keys(const LeafIndex& sender, bool encrypt)
{
  auto context = tls::marshal(sender);
  auto key_size = AESGCM::key_size(_suite);
  auto nonce_size = AESGCM::nonce_size;

  if (encrypt && _handshake_key_used.count(sender) > 0) {
    throw ProtocolError("Attempt to encrypt two handshake messages");
  }

  if (encrypt) {
    _handshake_key_used.insert(sender);
  }

  return KeyChain::Generation{
    0,
    _handshake_secret,
    hkdf_expand_label(_suite, _handshake_secret, "hs key", context, key_size),
    hkdf_expand_label(
      _suite, _handshake_secret, "hs nonce", context, nonce_size),
  };
}

MLSCiphertext
State::encrypt(const MLSPlaintext& pt)
{
  // Pull from the key schedule
  KeyChain::Generation keys;
  switch (pt.content.inner_type()) {
    // TODO(rlb) Enable encryption of Proposal / Commit messages
    case ContentType::application:
      keys = _application_keys.next();
      break;

    default:
      throw InvalidParameterError("Unknown content type");
  }

  // Encrypt the sender data
  tls::ostream sender_data;
  sender_data << _index << keys.generation;

  auto sender_data_nonce = random_bytes(AESGCM::nonce_size);
  auto sender_data_aad_val = sender_data_aad(
    _group_id, _epoch, pt.content.inner_type(), sender_data_nonce);

  auto sender_data_gcm = AESGCM(_sender_data_key, sender_data_nonce);
  sender_data_gcm.set_aad(sender_data_aad_val);
  auto encrypted_sender_data = sender_data_gcm.encrypt(sender_data.bytes());

  // Compute the plaintext input and AAD
  // XXX(rlb@ipv.sx): Apply padding?
  auto content = pt.marshal_content(0);
  auto aad = content_aad(_group_id,
                         _epoch,
                         pt.content.inner_type(),
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

  auto sender_data_gcm = AESGCM(_sender_data_key, ct.sender_data_nonce);
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
  KeyChain::Generation keys;
  switch (ct.content_type) {
    // TODO(rlb) Enable decryption of proposal / commit
    case ContentType::application:
      keys = _application_keys.get(sender, generation);
      break;

    default:
      throw InvalidParameterError("Unknown content type");
  }

  // Compute the plaintext AAD and decrypt
  auto aad = content_aad(ct.group_id,
                         ct.epoch,
                         ct.content_type,
                         ct.sender_data_nonce,
                         ct.encrypted_sender_data);
  auto gcm = AESGCM(keys.key, keys.nonce);
  gcm.set_aad(aad);
  auto content = gcm.decrypt(ct.ciphertext);

  // Set up a new plaintext based on the content
  return MLSPlaintext{ _suite, _group_id,       _epoch,
                       sender, ct.content_type, content };
}

} // namespace mls
