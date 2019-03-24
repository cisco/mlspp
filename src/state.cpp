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
  roster.add(credential);
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

  auto key = derive(secret, _key_label, _key_size);
  auto nonce = derive(secret, _nonce_label, _nonce_size);

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
  // Decrypt and ingest the Welcome
  auto init_priv = DHPrivateKey::derive(_suite, init_secret);
  auto welcome_info = welcome.decrypt(init_priv);

  _state = GroupState{ welcome_info };

  _index = _state.tree.size();
  _init_secret = welcome_info.init_secret;
  _zero = bytes(Digest(_suite).output_size(), 0);

  // Process the add
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
  if (*init_uik != init_priv.public_key()) {
    throw ProtocolError("Incorrect init key");
  }

  // Add to the transcript hash
  auto operation_bytes = tls::marshal(handshake.operation);
  _state.transcript_hash = Digest(_suite)
                             .write(_state.transcript_hash)
                             .write(operation_bytes)
                             .digest();

  // Add to the tree
  _state.tree.add_leaf(init_secret);

  // Add to the roster
  _state.roster.add(credential);

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
  if (!user_init_key.verify()) {
    throw InvalidParameterError("bad signature on user init key");
  }

  auto pub = user_init_key.find_init_key(_suite);
  if (!pub) {
    throw ProtocolError("New member does not support the group's ciphersuite");
  }

  WelcomeInfo welcome_info{ _state.group_id,        _state.epoch,
                            _state.roster,          _state.tree,
                            _state.transcript_hash, _init_secret };

  Welcome welcome{ user_init_key.user_init_key_id, *pub, welcome_info };

  auto add = sign(Add{ user_init_key });
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
  auto path = _state.tree.encrypt(index, evict_secret);
  return sign(Remove{ index, path });
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
State::handle(uint32_t signer_index, const GroupOperation& operation) const
{
  auto next = *this;
  next._state.epoch = _state.epoch + 1;

  auto operation_bytes = tls::marshal(operation);
  next._state.transcript_hash = Digest(_suite)
                                  .write(_state.transcript_hash)
                                  .write(operation_bytes)
                                  .digest();

  switch (operation.type) {
    case GroupOperationType::add:
      next.handle(operation.add);
      break;
    case GroupOperationType::update:
      next.handle(signer_index, operation.update);
      break;
    case GroupOperationType::remove:
      next.handle(operation.remove);
      break;
  }

  return next;
}

void
State::handle(const Add& add)
{
  // Verify the UserInitKey in the Add message
  if (!add.init_key.verify()) {
    throw InvalidParameterError("Invalid signature on init key in group add");
  }

  // Add to the tree
  auto init_key = add.init_key.find_init_key(_suite);
  if (!init_key) {
    throw ProtocolError("New node does not support group's cipher suite");
  }
  _state.tree.add_leaf(*init_key);

  // Add to the roster
  _state.roster.add(add.init_key.credential);

  // Update symmetric state
  update_epoch_secrets(_zero);
}

void
State::handle(uint32_t index, const Update& update)
{
  optional<bytes> leaf_secret = nullopt;
  if (index == _index) {
    if (_cached_leaf_secret.empty()) {
      throw InvalidParameterError("Got self-update without generating one");
    }

    leaf_secret = _cached_leaf_secret;
    _cached_leaf_secret.resize(0);
  }

  update_leaf(index, update.path, leaf_secret);
}

void
State::handle(const Remove& remove)
{
  auto leaf_secret = nullopt;
  update_leaf(remove.removed, remove.path, leaf_secret);
  _state.tree.blank_path(remove.removed);
  _state.roster.remove(remove.removed);
}

State::EpochSecrets
State::derive_epoch_secrets(CipherSuite suite,
                            const bytes& init_secret,
                            const bytes& update_secret,
                            const GroupState& state)
{
  auto secret_size = Digest(suite).output_size();
  auto epoch_secret = hkdf_extract(suite, init_secret, update_secret);
  return {
    epoch_secret,
    derive_secret(suite, epoch_secret, "app", state, secret_size),
    derive_secret(suite, epoch_secret, "confirm", state, secret_size),
    derive_secret(suite, epoch_secret, "init", state, secret_size),
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

void
State::update_leaf(uint32_t index,
                   const DirectPath& path,
                   const optional<bytes>& leaf_secret)
{
  if (leaf_secret) {
    _state.tree.set_path(index, *leaf_secret);
  } else {
    auto secrets = _state.tree.decrypt(index, path);
    _state.tree.merge_path(index, secrets);
  }

  update_epoch_secrets(_state.tree.root_secret());
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
  auto pub = _state.roster.get(handshake.signer_index).public_key();
  auto sig_data = _state.transcript_hash;
  auto sig = handshake.signature;
  auto sig_ver = pub.verify(sig_data, sig);

  auto confirm_data = sig_data + sig;
  auto confirm = hmac(_suite, _confirmation_key, confirm_data);
  auto confirm_ver = constant_time_eq(confirm, handshake.confirmation);

  return sig_ver && confirm_ver;
}

tls::ostream&
operator<<(tls::ostream& out, const State& obj)
{
  return out << obj._state;
}

} // namespace mls
