#include "state.h"

namespace mls {

///
/// Constructors
///

static const epoch_t zero_epoch{ 0 };

State::State(const bytes& group_id, const SignaturePrivateKey& identity_priv)
  : _index(0)
  , _identity_priv(identity_priv)
  , _epoch(zero_epoch)
  , _group_id(group_id)
  , _message_master_secret()
  , _init_secret()
  , _add_priv(DHPrivateKey::generate())
  , _tree(random_bytes(32))
{
  RawKeyCredential cred{ identity_priv.public_key() };
  _roster.add(cred);
}

State::State(const SignaturePrivateKey& identity_priv,
             const bytes& init_secret,
             const Welcome& welcome,
             const Handshake& handshake)
  : _identity_priv(identity_priv)
  , _add_priv(DHPrivateKey::generate()) // XXX(rlb@ipv.sx) dummy
{
  if (handshake.operation.type != GroupOperationType::add) {
    throw InvalidParameterError("Incorrect handshake type");
  }

  auto add = handshake.operation.add;

  // XXX(rlb@ipv.sx): Assuming exactly one init key, of the same
  // algorithm.  Should do algorithm negotiation.
  auto init_priv = DHPrivateKey::derive(init_secret);
  auto init_key = add.init_key.init_keys[0];
  auto identity_key = add.init_key.identity_key;
  if ((identity_key != identity_priv.public_key()) ||
      (init_key != init_priv.public_key())) {
    throw InvalidParameterError("Group add not targeted for this node");
  }

  // Initialize per-participant state
  _index = welcome.tree.size();
  _identity_priv = identity_priv;

  // Initialize shared state
  _group_id = welcome.group_id;
  _epoch = welcome.epoch + 1;

  RawKeyCredential cred{ identity_key };
  _roster = welcome.roster;
  _roster.add(cred);

  _tree = welcome.tree;
  auto leaf_secret = init_priv.derive(welcome.add_key);
  auto temp_path = _tree.encrypt(_index, leaf_secret);
  _tree.decrypt(_index, temp_path);
  _tree.merge(_index, temp_path);

  // Initialize shared secret state
  auto tree_secret = *(_tree.root().secret());
  auto tree_priv = DHPrivateKey::derive(tree_secret);
  auto update_secret = tree_priv.derive(welcome.add_key);
  derive_epoch_keys(true, update_secret, tls::marshal(add));

  // TODO verify the resulting state against the Add
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

  auto leaf_secret = _add_priv.derive(user_init_key.init_keys[0]);
  auto path = _tree.encrypt(_tree.size(), leaf_secret);

  Welcome welcome{ _group_id, _epoch,      _roster,
                   _tree,     _transcript, _add_priv.public_key() };
  auto add = sign(Add{ path, user_init_key });
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

  auto next = *this;
  next._epoch = _epoch + 1;

  switch (handshake.operation.type) {
    case GroupOperationType::add:
      next.handle(handshake.operation.add);
      break;
    case GroupOperationType::update:
      next.handle(handshake.signer_index, handshake.operation.update);
      break;
    case GroupOperationType::remove:
      next.handle(handshake.signer_index, handshake.operation.remove);
      break;
  }

  if (!next.verify(handshake.signer_index, handshake.signature)) {
    throw InvalidParameterError("Invalid handshake message signature");
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

  // Add the new leaf to the ratchet tree
  // XXX(rlb@ipv.sx): Assumes only one initkey
  auto init_key = add.init_key.init_keys[0];
  auto identity_key = add.init_key.identity_key;

  auto leaf_data = _add_priv.derive(init_key);
  auto leaf_key = DHPrivateKey::derive(leaf_data);

  auto tree_size = _tree.size();
  auto path = add.path;
  _tree.decrypt(tree_size, path);
  _tree.merge(tree_size, path);

  // Add to the roster
  RawKeyCredential cred{ identity_key };
  _roster.add(cred);

  // Update symmetric state
  auto tree_key = _tree.root().public_key();
  auto update_secret = _add_priv.derive(tree_key);
  derive_epoch_keys(true, update_secret, tls::marshal(add));
}

void
State::handle(uint32_t index, const Update& update)
{
  optional<bytes> leaf_secret = std::experimental::nullopt;
  if (index == _index) {
    if (_cached_leaf_secret.size() == 0) {
      throw InvalidParameterError("Got self-update without generating one");
    }

    leaf_secret = _cached_leaf_secret;
    _cached_leaf_secret.resize(0);
  }

  update_leaf(index, update.path, update, leaf_secret);
}

void
State::handle(uint32_t index, const Remove& remove)
{
  auto leaf_secret = std::experimental::nullopt;
  update_leaf(remove.removed, remove.path, remove, leaf_secret);

  _roster.copy(remove.removed, index);
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
  auto add_priv = (lhs._add_priv == rhs._add_priv);

  // Uncomment for debug info
  /*
  std::cout << "== == == == ==" << std::endl
            << std::endl
            << "_epoch " << epoch << " " << lhs._epoch << " " << rhs._epoch
            << std::endl
            << "_group_id " << group_id << std::endl
            << "_roster " << roster << std::endl
            << "_tree " << ratchet_tree << std::endl
            << "_message_master_secret " << message_master_secret << std::endl
            << "_init_secret " << init_secret << std::endl
            << "_add_priv " << add_priv << std::endl;
  */

  return epoch && group_id && roster && ratchet_tree && message_master_secret &&
         init_secret && add_priv;
}

bool
operator!=(const State& lhs, const State& rhs)
{
  return !(lhs == rhs);
}

template<typename Message>
void
State::update_leaf(uint32_t index,
                   const RatchetPath& path,
                   const Message& handshake,
                   const optional<bytes>& leaf_secret)
{
  if (leaf_secret) {
    _tree.set_leaf(index, *leaf_secret);
  } else {
    auto temp_path = path;
    _tree.decrypt(index, temp_path);
    _tree.merge(index, temp_path);
  }

  auto update_secret = *(_tree.root().secret());
  derive_epoch_keys(false, update_secret, tls::marshal(handshake));
}

void
State::derive_epoch_keys(bool add,
                         const bytes& update_secret,
                         const bytes& message)
{
  auto init_secret = _init_secret;
  if (add) {
    // XXX(rlb@ipv.sx) Crypto agility; should be sized according to
    // hash function in use.
    init_secret = bytes(32, 0);
  }

  auto epoch_secret = hkdf_extract(init_secret, update_secret);

  _message_master_secret =
    derive_secret(epoch_secret, "msg", _group_id, _epoch, message);

  _init_secret =
    derive_secret(epoch_secret, "init", _group_id, _epoch, message);

  auto add_secret =
    derive_secret(epoch_secret, "add", _group_id, _epoch, message);

  _add_priv = DHPrivateKey::derive(add_secret);
}

Handshake
State::sign(const GroupOperation& operation) const
{
  return Handshake{ _epoch, operation, _index, bytes() };
}

bool
State::verify(uint32_t signer_index, const bytes& signature) const
{
  // TODO
  return true;
}

} // namespace mls
