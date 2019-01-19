#include "state.h"

namespace mls {

///
/// Constructors
///

static const epoch_t zero_epoch{ 0 };

State::State(const bytes& group_id,
             CipherSuite suite,
             const SignaturePrivateKey& identity_priv,
             const Credential& credential)
  : _index(0)
  , _identity_priv(identity_priv)
  , _epoch(zero_epoch)
  , _group_id(group_id)
  , _suite(suite)
  , _message_master_secret()
  , _init_secret(zero_bytes(32))
  , _tree(suite, random_bytes(32))
  , _transcript_hash(Digest(suite).output_size(), 0)
  , _zero(Digest(suite).output_size(), 0)
{
  _roster.add(credential);
}

State::State(const SignaturePrivateKey& identity_priv,
             const Credential& credential,
             const bytes& init_secret,
             const Welcome& welcome,
             const Handshake& handshake)
  : _identity_priv(identity_priv)
  , _suite(welcome.cipher_suite)
  , _tree(welcome.cipher_suite)
{
  // Decrypt and ingest the Welcome
  auto init_priv = DHPrivateKey::derive(_suite, init_secret);
  auto welcome_info = welcome.decrypt(init_priv);

  _group_id = welcome_info.group_id;
  _epoch = welcome_info.epoch + 1;
  _tree = welcome_info.tree;
  _roster = welcome_info.roster;
  _transcript_hash = welcome_info.transcript_hash;
  _index = _tree.size();
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
  } else if (*init_uik != init_priv.public_key()) {
    throw ProtocolError("Incorrect init key");
  }

  // Add to the transcript hash
  auto operation_bytes = tls::marshal(handshake.operation);
  _transcript_hash =
    Digest(_suite).write(_transcript_hash).write(operation_bytes).digest();

  // Add to the tree
  _tree.add_leaf(init_secret);

  // Add to the roster
  _roster.add(credential);

  // Ratchet forward into shared state
  derive_epoch_keys(_zero);

  if (!verify(handshake)) {
    throw InvalidParameterError("Handshake signature failed to verify");
  }
}

State::InitialInfo
State::negotiate(const bytes& group_id,
                 const std::vector<CipherSuite> supported_ciphersuites,
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

  auto state = State{ group_id, suite, identity_priv, credential };
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

  WelcomeInfo welcome_info{ _group_id, _epoch,           _roster,
                            _tree,     _transcript_hash, _init_secret };

  Welcome welcome{ user_init_key.user_init_key_id, *pub, welcome_info };

  auto add = sign(Add{ user_init_key });
  return std::pair<Welcome, Handshake>(welcome, add);
}

Handshake
State::update(const bytes& leaf_secret)
{
  auto path = _tree.encrypt(_index, leaf_secret);
  _cached_leaf_secret = leaf_secret;
  return sign(Update{ path });
}

Handshake
State::remove(uint32_t index) const
{
  auto evict_secret = random_bytes(32);
  auto path = _tree.encrypt(index, evict_secret);
  return sign(Remove{ index, path });
}

///
/// Message handlers
///

State
State::handle(const Handshake& handshake) const
{
  if (handshake.prior_epoch != _epoch) {
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
  next._epoch = _epoch + 1;

  auto operation_bytes = tls::marshal(operation);
  next._transcript_hash =
    Digest(_suite).write(_transcript_hash).write(operation_bytes).digest();

  switch (operation.type) {
    case GroupOperationType::add:
      next.handle(operation.add);
      break;
    case GroupOperationType::update:
      next.handle(signer_index, operation.update);
      break;
    case GroupOperationType::remove:
      next.handle(signer_index, operation.remove);
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
  _tree.add_leaf(*init_key);

  // Add to the roster
  _roster.add(add.init_key.credential);

  // Update symmetric state
  derive_epoch_keys(_zero);
}

void
State::handle(uint32_t index, const Update& update)
{
  optional<bytes> leaf_secret = nullopt;
  if (index == _index) {
    if (_cached_leaf_secret.size() == 0) {
      throw InvalidParameterError("Got self-update without generating one");
    }

    leaf_secret = _cached_leaf_secret;
    _cached_leaf_secret.resize(0);
  }

  update_leaf(index, update.path, leaf_secret);
}

void
State::handle(uint32_t index, const Remove& remove)
{
  auto leaf_secret = nullopt;
  update_leaf(remove.removed, remove.path, leaf_secret);
  _tree.blank_path(remove.removed);
  _roster.remove(remove.removed);
}

///
/// Inner logic and convenience functions
///

bool
operator==(const State& lhs, const State& rhs)
{
  auto epoch = (lhs._epoch == rhs._epoch);
  auto group_id = (lhs._group_id == rhs._group_id);
  auto roster = (lhs._roster == rhs._roster);
  auto ratchet_tree = (lhs._tree == rhs._tree);
  auto message_master_secret =
    (lhs._message_master_secret == rhs._message_master_secret);
  auto init_secret = (lhs._init_secret == rhs._init_secret);

  // Uncomment for debug info
  /*
  std::cout << "== == == == ==" << std::endl
            << std::endl
            << "_epoch " << epoch << " " << lhs._epoch << " " << rhs._epoch
            << std::endl
            << "_group_id " << group_id << " " << lhs._group_id << " "
            << rhs._group_id << std::endl
            << "_roster " << roster << " " << lhs._roster.size() << " "
            << rhs._roster.size() << std::endl
            << "_tree " << ratchet_tree << " " << lhs._tree.size() << " "
            << rhs._tree.size() << std::endl
            << "_message_master_secret " << message_master_secret << std::endl
            << "_init_secret " << init_secret << std::endl;
  */

  return epoch && group_id && roster && ratchet_tree && message_master_secret &&
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
    _tree.set_path(index, *leaf_secret);
  } else {
    auto temp_path = path;
    auto secrets = _tree.decrypt(index, temp_path);
    _tree.merge_path(index, secrets);
  }

  derive_epoch_keys(_tree.root_secret());
}

void
State::derive_epoch_keys(const bytes& update_secret)
{
  auto epoch_secret = hkdf_extract(_suite, _init_secret, update_secret);
  _message_master_secret = derive_secret(
    _suite, epoch_secret, "app", *this, Digest(_suite).output_size());
  _confirmation_key = derive_secret(
    _suite, epoch_secret, "confirm", *this, Digest(_suite).output_size());
  _init_secret = derive_secret(
    _suite, epoch_secret, "init", *this, Digest(_suite).output_size());
}

Handshake
State::sign(const GroupOperation& operation) const
{
  auto next = handle(_index, operation);

  auto sig_data = next._transcript_hash;
  auto sig = _identity_priv.sign(sig_data);

  auto confirm_data = sig_data;
  confirm_data.insert(confirm_data.end(), sig.begin(), sig.end());
  auto confirm = hmac(_suite, next._confirmation_key, confirm_data);

  return Handshake{ _epoch, operation, _index, sig, confirm };
}

bool
State::verify(const Handshake& handshake) const
{
  auto pub = _roster.get(handshake.signer_index).public_key();
  auto sig_data = _transcript_hash;
  auto sig = handshake.signature;
  auto sig_ver = pub.verify(sig_data, sig);

  auto confirm_data = sig_data;
  confirm_data.insert(confirm_data.end(), sig.begin(), sig.end());
  auto confirm = hmac(_suite, _confirmation_key, confirm_data);

  // TODO(rlb@ipv.sx): Verify MAC in constant time
  auto confirm_ver = (confirm == handshake.confirmation);

  return sig_ver && confirm_ver;
}

// struct {
//   opaque group_id<0..255>;
//   uint32 epoch;
//   optional<Credential> roster<1..2^32-1>;
//   optional<PublicKey> tree<1..2^32-1>;
//   opaque transcript_hash<0..255>;
// } GroupState;
tls::ostream&
operator<<(tls::ostream& out, const State& obj)
{
  return out << obj._group_id << obj._epoch << obj._roster << obj._tree
             << obj._transcript_hash;
}

} // namespace mls
