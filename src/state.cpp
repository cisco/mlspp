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
  auto identity_leaf = MerkleNode::leaf(_identity_priv.public_key().to_bytes());
  _identity_tree.add(identity_leaf);
}

State::State(const SignaturePrivateKey& identity_priv,
             const bytes& init_secret,
             const Handshake<GroupAdd>& group_add)
  : _identity_priv(identity_priv)
  , _add_priv(DHPrivateKey::generate()) // XXX(rlb@ipv.sx) dummy
{
  auto prior_root = group_add.message.group_init_key.identity_root();
  if (!group_add.verify(prior_root)) {
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

State::State(const SignaturePrivateKey& identity_priv,
             const bytes& leaf_secret,
             const Handshake<UserAdd>& user_add,
             const GroupInitKey& group_init_key)
  : _identity_priv(identity_priv)
  , _add_priv(DHPrivateKey::generate()) // XXX(rlb@ipv.sx) dummy
{
  init_from_details(identity_priv, leaf_secret, group_init_key, user_add);
}

State::State(const SignaturePrivateKey& identity_priv,
             const bytes& leaf_secret,
             const GroupInitKey& group_init_key)
  : _identity_priv(identity_priv)
  , _add_priv(DHPrivateKey::generate()) // XXX(rlb@ipv.sx) dummy
{
  Handshake<None> dummy;
  dummy.sign(identity_priv); // XXX(rlb@ipv.sx) To allow marshal
  init_from_details(identity_priv, leaf_secret, group_init_key, dummy);
}

///
/// Message factories
///

Handshake<UserAdd>
State::join(const SignaturePrivateKey& identity_priv,
            const bytes& init_secret,
            const GroupInitKey& group_init_key)
{
  State temp_state(identity_priv, init_secret, group_init_key);
  temp_state._epoch = group_init_key.epoch;

  auto path = temp_state._ratchet_tree.encrypt(temp_state._index, init_secret);

  return temp_state.sign(UserAdd{ path });
}

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
State::handle(const Handshake<UserAdd>& user_add) const
{
  // Verify that the user_add addresse this state
  if (user_add.prior_epoch != _epoch) {
    throw InvalidParameterError("Invalid epoch");
  }

  // Verify the incoming message against the **new** identity tree
  auto temp_identity_tree = _identity_tree;
  auto identity_leaf = MerkleNode::leaf(user_add.identity_key.to_bytes());
  temp_identity_tree.add(identity_leaf);
  if (!user_add.verify(temp_identity_tree.root().value())) {
    throw InvalidParameterError("UserAdd is not from a member of the group");
  }

  if (user_add.signer_index != _identity_tree.size()) {
    throw InvalidParameterError("UserAdd is not from the new member");
  }

  // Create a copy of the current state
  auto next = spawn(user_add.epoch());

  // Update the ratchet tree
  auto path = user_add.message.path;
  next._ratchet_tree.decrypt(user_add.signer_index, path);
  next._ratchet_tree.merge(user_add.signer_index, path);

  // Add to symmetric state
  next.add_inner(user_add.identity_key, user_add);

  return next;
}

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

  auto path = group_add.message.path;
  next._ratchet_tree.decrypt(group_add.signer_index, path);
  next._ratchet_tree.merge(group_add.signer_index, path);

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

  // TODO: Update identity tree and ratchet tree with blank nodes

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
  auto identity_tree = (lhs._identity_tree == rhs._identity_tree);
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
            << "_identity_tree " << identity_tree << std::endl
            << "_ratchet_tree " << ratchet_tree << std::endl
            << "_message_master_secret " << message_master_secret << std::endl
            << "_init_secret " << init_secret << std::endl
            << "_add_priv " << add_priv << std::endl;
  */

  return epoch && group_id && identity_tree && ratchet_tree &&
         message_master_secret && init_secret && add_priv;
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

  _identity_tree =
    Tree<MerkleNode>(tree_size, group_init_key.identity_frontier);
  _ratchet_tree = group_init_key.ratchet_tree;

  auto identity_leaf = MerkleNode::leaf(_identity_priv.public_key().to_bytes());
  _identity_tree.add(identity_leaf);

  // XXX(rlb@ipv.sx) This is clumsy, but might not be necessary
  // after further modernization
  auto index = _ratchet_tree.size();
  auto temp_path = _ratchet_tree.encrypt(index, leaf_secret);
  _ratchet_tree.decrypt(index, temp_path);
  _ratchet_tree.merge(index, temp_path);

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
  auto identity_leaf = MerkleNode::leaf(identity_key.to_bytes());
  _identity_tree.add(identity_leaf);

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
  // XXX(rlb@ipv.sx) Probably need to fold in leaf_secret somehow
  auto temp_path = path;
  _ratchet_tree.decrypt(index, temp_path);
  _ratchet_tree.merge(index, temp_path);

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
  auto copath = _identity_tree.copath(_index);

  Handshake<Message> handshake{
    body, _epoch, uint32_t(_identity_tree.size()), _index, copath
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

  auto root = _identity_tree.root().value();
  return message.verify(root);
}

GroupInitKey
State::group_init_key() const
{
  return GroupInitKey{ _epoch,
                       uint32_t(_identity_tree.size()),
                       _group_id,
                       0x0000, // ciphersuite, ignored
                       _add_priv.public_key(),
                       _identity_tree.frontier(),
                       _ratchet_tree };
}

} // namespace mls
