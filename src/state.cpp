#include "state.h"

namespace mls {

///
/// Constructors
///

static const epoch_t zero_epoch{ 0 };

State::State(const bytes& group_id, const SignaturePrivateKey& identity_priv)
  : _index(0)
  , _identity_priv(identity_priv)
  , _prior_epoch()
  , _epoch(zero_epoch)
  , _group_id(group_id)
  , _message_master_secret()
  , _init_secret()
  , _add_priv(DHPrivateKey::generate())
  , _ratchet_tree(random_bytes(32))
{
  RawKeyCredential cred{ identity_priv.public_key() };
  _roster.add(cred);
}

State::State(const SignaturePrivateKey& identity_priv,
             const bytes& init_secret,
             const Handshake<GroupAdd>& group_add)
  : _identity_priv(identity_priv)
  , _add_priv(DHPrivateKey::generate()) // XXX(rlb@ipv.sx) dummy
{
  if (!group_add.verify(group_add.message.group_init_key.roster)) {
    throw InvalidParameterError("Group add is not from a member of the group");
  }

  // XXX(rlb@ipv.sx): Assuming exactly one init key, of the same
  // algorithm.  Should do algorithm negotiation.
  auto init_priv = DHPrivateKey::derive(init_secret);
  auto init_key = group_add.message.user_init_key.init_keys[0];
  auto identity_key = group_add.message.user_init_key.identity_key;
  if ((identity_key != identity_priv.public_key()) ||
      (init_key != init_priv.public_key())) {
    throw InvalidParameterError("Group add not targeted for this node");
  }

  auto leaf_data = init_priv.derive(group_add.message.group_init_key.add_key);

  init_from_details(
    identity_priv, leaf_data, group_add.message.group_init_key, group_add);
}

///
/// Message factories
///

Handshake<GroupAdd>
State::add(const UserInitKey& user_init_key) const
{
  if (!user_init_key.verify()) {
    throw InvalidParameterError("bad signature on user init key");
  }

  auto leaf_secret = _add_priv.derive(user_init_key.init_keys[0]);
  auto path = _ratchet_tree.encrypt(_ratchet_tree.size(), leaf_secret);

  return sign(GroupAdd{ path, user_init_key, group_init_key() });
}

Handshake<Update>
State::update(const bytes& leaf_secret) const
{
  auto path = _ratchet_tree.encrypt(_index, leaf_secret);
  return sign(Update{ path });
}

Handshake<Remove>
State::remove(uint32_t index) const
{
  auto evict_secret = random_bytes(32);
  auto path = _ratchet_tree.encrypt(index, evict_secret);
  return sign(Remove{ index, path });
}

///
/// Message handlers
///

State
State::handle(const Handshake<GroupAdd>& group_add) const
{
  // Verify the incoming message
  if (!verify_now(group_add)) {
    throw InvalidParameterError("GroupAdd is not from a member of the group");
  }

  if (!group_add.message.user_init_key.verify()) {
    throw InvalidParameterError("Invalid signature on init key in group add");
  }

  // Create a copy of the current state
  auto next = spawn(group_add.epoch());

  // Add the new leaf to the ratchet tree
  // XXX(rlb@ipv.sx): Assumes only one initkey
  auto init_key = group_add.message.user_init_key.init_keys[0];
  auto identity_key = group_add.message.user_init_key.identity_key;

  auto leaf_data = _add_priv.derive(init_key);
  auto leaf_key = DHPrivateKey::derive(leaf_data);

  auto tree_size = _ratchet_tree.size();
  auto path = group_add.message.path;
  next._ratchet_tree.decrypt(tree_size, path);
  next._ratchet_tree.merge(tree_size, path);

  // Add to symmetric state
  next.add_inner(identity_key, group_add);

  return next;
}

State
State::handle(const Handshake<Update>& update, const bytes& leaf_secret) const
{
  if (!verify_now(update)) {
    throw InvalidParameterError("Update is not from a member of the group");
  }

  if (update.signer_index != _index) {
    throw InvalidParameterError("Improper self-Update handler call");
  }

  auto next = spawn(update.epoch());

  next.update_leaf(
    update.signer_index, update.message.path, update, leaf_secret);

  return next;
}

State
State::handle(const Handshake<Update>& update) const
{
  if (!verify_now(update)) {
    throw InvalidParameterError("Update is not from a member of the group");
  }

  if (update.signer_index == _index) {
    throw InvalidParameterError(
      "Improper Update handler call; use self-update");
  }

  auto next = spawn(update.epoch());

  next.update_leaf(update.signer_index,
                   update.message.path,
                   update,
                   std::experimental::nullopt);

  return next;
}

State
State::handle(const Handshake<Remove>& remove) const
{
  if (!verify_now(remove)) {
    throw InvalidParameterError("Remove is not from a member of the group");
  }

  auto next = spawn(remove.epoch());

  next.update_leaf(remove.message.removed,
                   remove.message.path,
                   remove,
                   std::experimental::nullopt);

  return next;
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
  auto ratchet_tree = (lhs._ratchet_tree == rhs._ratchet_tree);
  auto message_master_secret =
    (lhs._message_master_secret == rhs._message_master_secret);
  auto init_secret = (lhs._init_secret == rhs._init_secret);
  auto add_priv = (lhs._add_priv == rhs._add_priv);

  // Uncomment for debug info
  /*
  std::cout << "== == == == ==" << std::endl
            << "_prior_epoch " << lhs._prior_epoch << " " << rhs._prior_epoch
            << std::endl
            << "_epoch " << epoch << " " << lhs._epoch << " " << rhs._epoch
            << std::endl
            << "_group_id " << group_id << std::endl
            << "_roster " << roster << std::endl
            << "_ratchet_tree " << ratchet_tree << std::endl
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

State
State::spawn(const epoch_t& epoch) const
{
  auto next = *this;
  next._prior_epoch = _epoch;
  next._epoch = epoch;
  return next;
}

template<typename Message>
void
State::init_from_details(const SignaturePrivateKey& identity_priv,
                         const bytes& leaf_secret,
                         const GroupInitKey& group_init_key,
                         const Handshake<Message>& handshake)
{
  auto tree_size = group_init_key.ratchet_tree.size();
  _index = tree_size;
  _identity_priv = identity_priv;

  _roster = group_init_key.roster;
  _ratchet_tree = group_init_key.ratchet_tree;

  RawKeyCredential cred{ _identity_priv.public_key() };
  _roster.add(cred);

  // XXX(rlb@ipv.sx) This is clumsy, but might not be necessary
  // after further modernization
  auto temp_path = _ratchet_tree.encrypt(_index, leaf_secret);
  _ratchet_tree.decrypt(_index, temp_path);
  _ratchet_tree.merge(_index, temp_path);

  _prior_epoch = group_init_key.epoch;
  _epoch = next_epoch(_prior_epoch, handshake.message);

  _group_id = group_init_key.group_id;

  auto tree_secret = *(_ratchet_tree.root().secret());
  auto tree_priv = DHPrivateKey::derive(tree_secret);
  auto update_secret = tree_priv.derive(group_init_key.add_key);
  derive_epoch_keys(true, update_secret, tls::marshal(handshake));
}

template<typename Message>
void
State::add_inner(const SignaturePublicKey& identity_key,
                 const Handshake<Message>& handshake)
{
  RawKeyCredential cred{ identity_key };
  _roster.add(cred);

  // NB: complementary to init_from_details
  auto tree_key = _ratchet_tree.root().public_key();
  auto update_secret = _add_priv.derive(tree_key);
  derive_epoch_keys(true, update_secret, tls::marshal(handshake));
}

template<typename Message>
void
State::update_leaf(uint32_t index,
                   const RatchetPath& path,
                   const Handshake<Message>& handshake,
                   const optional<bytes>& leaf_secret)
{
  if (leaf_secret) {
    _ratchet_tree.set_leaf(index, *leaf_secret);
  } else {
    auto temp_path = path;
    _ratchet_tree.decrypt(index, temp_path);
    _ratchet_tree.merge(index, temp_path);
  }

  auto update_secret = *(_ratchet_tree.root().secret());
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

template<typename Message>
Handshake<Message>
State::sign(const Message& body) const
{
  Handshake<Message> handshake{
    body, _epoch, uint32_t(_ratchet_tree.size()), _index
  };

  handshake.sign(_identity_priv);
  return handshake;
}

template<typename T>
bool
State::verify_now(const Handshake<T>& message) const
{
  if (message.prior_epoch != _epoch) {
    return false;
  }

  return message.verify(_roster);
}

GroupInitKey
State::group_init_key() const
{
  return GroupInitKey{ _epoch,
                       uint32_t(_ratchet_tree.size()),
                       _group_id,
                       0x0000, // ciphersuite, ignored
                       _add_priv.public_key(),
                       _roster,
                       _ratchet_tree };
}

} // namespace mls
