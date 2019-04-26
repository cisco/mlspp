#include "state.h"

namespace mls {

///
/// GroupState
///

GroupState::GroupState(const bytes& group_id,
                       CipherSuite suite,
                       const bytes& leaf_secret,
                       const Credential& credential)
  : group_id(group_id)
  , epoch(0)
  , tree(suite, leaf_secret)
  , transcript_hash(Digest(suite).output_size(), 0)
{
  roster.add(0, credential);
}

GroupState::GroupState(const WelcomeInfo& info)
  : group_id(info.group_id)
  , epoch(info.epoch + 1)
  , roster(info.roster)
  , tree(info.tree)
  , transcript_hash(info.transcript_hash)
{}

GroupState::GroupState(CipherSuite suite)
  : epoch(0)
  , tree(suite)
{}

tls::ostream&
operator<<(tls::ostream& out, const GroupState& obj)
{
  return out << obj.group_id << obj.epoch << obj.roster << obj.tree
             << obj.transcript_hash;
}

tls::istream&
operator>>(tls::istream& out, GroupState& obj)
{
  return out >> obj.group_id >> obj.epoch >> obj.roster >> obj.tree >>
         obj.transcript_hash;
}

bool
operator==(const GroupState& lhs, const GroupState& rhs)
{
  auto group_id = (lhs.group_id == rhs.group_id);
  auto epoch = (lhs.epoch == rhs.epoch);
  auto roster = (lhs.roster == rhs.roster);
  auto tree = (lhs.tree == rhs.tree);
  auto transcript_hash = (lhs.transcript_hash == rhs.transcript_hash);
  return group_id && epoch && roster && tree && transcript_hash;
}

///
/// ApplicationKeyChain
///

const char* ApplicationKeyChain::_secret_label = "app sender";
const char* ApplicationKeyChain::_nonce_label = "nonce";
const char* ApplicationKeyChain::_key_label = "key";

ApplicationKeyChain::KeyAndNonce
ApplicationKeyChain::get(uint32_t generation) const
{
  auto secret = _base_secret;
  for (uint32_t i = 0; i < generation; ++i) {
    secret = derive(secret, _secret_label, _secret_size);
  }

  auto key = hkdf_expand_label(_suite, secret, _key_label, {}, _key_size);
  auto nonce = hkdf_expand_label(_suite, secret, _nonce_label, {}, _nonce_size);

  return KeyAndNonce{ secret, key, nonce };
}

bytes
ApplicationKeyChain::derive(const bytes& secret,
                            const std::string& label,
                            const size_t size) const
{
  return hkdf_expand_label(_suite, secret, label, _sender, size);
}

///
/// Constructors
///

State::State(const bytes& group_id,
             CipherSuite suite,
             const bytes& leaf_secret,
             SignaturePrivateKey identity_priv,
             const Credential& credential)
  : _suite(suite)
  , _state(group_id, suite, leaf_secret, credential)
  , _init_secret(zero_bytes(32))
  , _index(0)
  , _identity_priv(std::move(identity_priv))
  , _zero(Digest(suite).output_size(), 0)
{}

State::State(SignaturePrivateKey identity_priv,
             const Credential& credential,
             const bytes& init_secret,
             const Welcome& welcome,
             const Handshake& handshake)
  : _suite(welcome.cipher_suite)
  , _state(welcome.cipher_suite)
  , _identity_priv(std::move(identity_priv))
{
  // Verify that we have an add and it is for us
  if (handshake.operation.type != GroupOperationType::add) {
    throw InvalidParameterError("Incorrect handshake type");
  }

  auto add = handshake.operation.add;
  if (credential != add.init_key.credential) {
    throw InvalidParameterError("Add not targeted for this node");
  }

  // Make sure that the init key for the chosen ciphersuite is the
  // one we sent
  auto init_uik = add.init_key.find_init_key(_suite);
  if (!init_uik) {
    throw ProtocolError("Selected cipher suite not supported");
  }

  auto init_priv = DHPrivateKey::node_derive(_suite, init_secret);
  if (*init_uik != init_priv.public_key()) {
    throw ProtocolError("Incorrect init key");
  }

  // Decrypt the Welcome
  auto welcome_info = welcome.decrypt(init_priv);

  // Make sure the WelcomeInfo matches the Add
  if (add.welcome_info_hash != welcome_info.hash(_suite)) {
    throw ProtocolError("Mismatch in welcome info hash");
  }

  // Ingest the WelcomeInfo
  _state = GroupState{ welcome_info };

  _init_secret = welcome_info.init_secret;
  _zero = bytes(Digest(_suite).output_size(), 0);

  // Add to the transcript hash
  update_transcript_hash(handshake.operation);

  // Add to the tree
  _index = add.index;
  _state.tree.add_leaf(_index, init_secret);

  // Add to the roster
  _state.roster.add(_index.val, credential);

  // Ratchet forward into shared state
  update_epoch_secrets(_zero);

  if (!verify(handshake)) {
    throw InvalidParameterError("Handshake signature failed to verify");
  }
}

State::InitialInfo
State::negotiate(const bytes& group_id,
                 const std::vector<CipherSuite> supported_ciphersuites,
                 const bytes& leaf_secret,
                 const SignaturePrivateKey& identity_priv,
                 const Credential& credential,
                 const UserInitKey& user_init_key)
{
  // Negotiate a ciphersuite with the other party
  CipherSuite suite;
  auto selected = false;
  for (auto my_suite : supported_ciphersuites) {
    for (auto other_suite : user_init_key.cipher_suites) {
      if (my_suite == other_suite) {
        selected = true;
        suite = my_suite;
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

  // We have manually guaranteed that `suite` is always initialized
  // NOLINTNEXTLINE(clang-analyzer-core.CallAndMessage)
  auto state = State{ group_id, suite, leaf_secret, identity_priv, credential };
  auto welcome_add = state.add(user_init_key);
  state = state.handle(welcome_add.second);

  return InitialInfo(state, welcome_add);
}

///
/// Message factories
///

std::pair<Welcome, Handshake>
State::add(const UserInitKey& user_init_key) const
{
  return add(_state.tree.size(), user_init_key);
}

std::pair<Welcome, Handshake>
State::add(uint32_t index, const UserInitKey& user_init_key) const
{
  if (!user_init_key.verify()) {
    throw InvalidParameterError("bad signature on user init key");
  }

  auto pub = user_init_key.find_init_key(_suite);
  if (!pub) {
    throw ProtocolError("New member does not support the group's ciphersuite");
  }

  auto welcome_info_str = welcome_info();
  auto welcome =
    Welcome{ user_init_key.user_init_key_id, *pub, welcome_info_str };

  auto welcome_info_hash = welcome_info_str.hash(_suite);
  auto add = sign(Add{ LeafIndex{ index }, user_init_key, welcome_info_hash });
  return std::pair<Welcome, Handshake>(welcome, add);
}

Handshake
State::update(const bytes& leaf_secret)
{
  auto path = _state.tree.encrypt(_index, leaf_secret);
  _cached_leaf_secret = leaf_secret;
  return sign(Update{ path });
}

Handshake
State::remove(const bytes& evict_secret, uint32_t index) const
{
  if (index >= _state.tree.size()) {
    throw InvalidParameterError("Index too large for tree");
  }

  auto path = _state.tree.encrypt(LeafIndex{ index }, evict_secret);
  return sign(Remove{ LeafIndex{ index }, path });
}

///
/// Message handlers
///

State
State::handle(const Handshake& handshake) const
{
  if (handshake.prior_epoch != _state.epoch) {
    throw InvalidParameterError("Epoch mismatch");
  }

  auto next = handle(handshake.signer_index, handshake.operation);

  if (!next.verify(handshake)) {
    throw InvalidParameterError("Invalid handshake message signature");
  }

  return next;
}

State
State::handle(LeafIndex signer_index, const GroupOperation& operation) const
{
  auto next = *this;
  bytes update_secret;
  switch (operation.type) {
    case GroupOperationType::add:
      update_secret = next.handle(operation.add);
      break;
    case GroupOperationType::update:
      update_secret = next.handle(signer_index, operation.update);
      break;
    case GroupOperationType::remove:
      update_secret = next.handle(operation.remove);
      break;
  }

  next.update_transcript_hash(operation);
  next._state.epoch = _state.epoch + 1;
  next.update_epoch_secrets(update_secret);

  return next;
}

bytes
State::handle(const Add& add)
{
  // Verify the UserInitKey in the Add message
  if (!add.init_key.verify()) {
    throw InvalidParameterError("Invalid signature on init key in group add");
  }

  // Verify the index in the Add message
  if (add.index.val > _state.tree.size()) {
    throw InvalidParameterError("Invalid leaf index");
  }
  if (add.index.val < _state.tree.size() && _state.tree.occupied(add.index)) {
    throw InvalidParameterError("Leaf is not available for add");
  }

  // Verify the WelcomeInfo hash
  if (add.welcome_info_hash != welcome_info().hash(_suite)) {
    throw ProtocolError("Mismatch in welcome info hash");
  }

  // Add to the tree
  auto init_key = add.init_key.find_init_key(_suite);
  if (!init_key) {
    throw ProtocolError("New node does not support group's cipher suite");
  }
  _state.tree.add_leaf(add.index, *init_key);

  // Add to the roster
  _state.roster.add(add.index.val, add.init_key.credential);

  return _zero;
}

bytes
State::handle(LeafIndex index, const Update& update)
{
  std::optional<bytes> leaf_secret = std::nullopt;
  if (index == _index) {
    if (_cached_leaf_secret.empty()) {
      throw InvalidParameterError("Got self-update without generating one");
    }

    leaf_secret = _cached_leaf_secret;
    _cached_leaf_secret.clear();
  }

  return update_leaf(index, update.path, leaf_secret);
}

bytes
State::handle(const Remove& remove)
{
  auto leaf_secret = std::nullopt;
  auto update_secret = update_leaf(remove.removed, remove.path, leaf_secret);
  _state.tree.blank_path(remove.removed);
  _state.roster.remove(remove.removed.val);

  auto cut = _state.tree.leaf_span();
  _state.tree.truncate(cut);
  _state.roster.truncate(cut.val);

  return update_secret;
}

State::EpochSecrets
State::derive_epoch_secrets(CipherSuite suite,
                            const bytes& init_secret,
                            const bytes& update_secret,
                            const GroupState& state)
{
  auto state_bytes = tls::marshal(state);
  auto epoch_secret = hkdf_extract(suite, init_secret, update_secret);
  return {
    epoch_secret,
    derive_secret(suite, epoch_secret, "app", state_bytes),
    derive_secret(suite, epoch_secret, "confirm", state_bytes),
    derive_secret(suite, epoch_secret, "init", state_bytes),
  };
}

///
/// Inner logic and convenience functions
///

bool
operator==(const State& lhs, const State& rhs)
{
  auto state = (lhs._state == rhs._state);
  auto epoch_secret = (lhs._epoch_secret == rhs._epoch_secret);
  auto application_secret =
    (lhs._application_secret == rhs._application_secret);
  auto confirmation_key = (lhs._confirmation_key == rhs._confirmation_key);
  auto init_secret = (lhs._init_secret == rhs._init_secret);

  return state && epoch_secret && application_secret && confirmation_key &&
         init_secret;
}

bool
operator!=(const State& lhs, const State& rhs)
{
  return !(lhs == rhs);
}

WelcomeInfo
State::welcome_info() const
{
  return { _state.group_id, _state.epoch,           _state.roster,
           _state.tree,     _state.transcript_hash, _init_secret };
}

void
State::update_transcript_hash(const GroupOperation& operation)
{
  auto operation_bytes = tls::marshal(operation);
  _state.transcript_hash = Digest(_suite)
                             .write(_state.transcript_hash)
                             .write(operation_bytes)
                             .digest();
}

bytes
State::update_leaf(LeafIndex index,
                   const DirectPath& path,
                   const std::optional<bytes>& leaf_secret)
{
  if (leaf_secret) {
    _state.tree.set_path(index, *leaf_secret);
  } else {
    auto secrets = _state.tree.decrypt(index, path);
    _state.tree.merge_path(index, secrets);
  }

  return _state.tree.root_secret();
}

void
State::update_epoch_secrets(const bytes& update_secret)
{
  auto secrets =
    derive_epoch_secrets(_suite, _init_secret, update_secret, _state);
  _epoch_secret = secrets.epoch_secret;
  _application_secret = secrets.application_secret;
  _confirmation_key = secrets.confirmation_key;
  _init_secret = secrets.init_secret;
}

Handshake
State::sign(const GroupOperation& operation) const
{
  auto next = handle(_index, operation);

  auto sig_data = next._state.transcript_hash;
  auto sig = _identity_priv.sign(sig_data);

  auto confirm_data = sig_data + sig;
  auto confirm = hmac(_suite, next._confirmation_key, confirm_data);

  return Handshake{ _state.epoch, operation, _index, sig, confirm };
}

bool
State::verify(const Handshake& handshake) const
{
  auto pub = _state.roster.get(handshake.signer_index.val).public_key();
  auto sig_data = _state.transcript_hash;
  auto sig = handshake.signature;
  auto sig_ver = pub.verify(sig_data, sig);

  auto confirm_data = sig_data + sig;
  auto confirm = hmac(_suite, _confirmation_key, confirm_data);
  auto confirm_ver = constant_time_eq(confirm, handshake.confirmation);

  return sig_ver && confirm_ver;
}

} // namespace mls
