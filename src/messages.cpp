#include "messages.h"
#include "tree.h"

namespace mls {

// UserInitKey

void
UserInitKey::sign(const SignaturePrivateKey& identity_priv)
{
  identity_key = identity_priv.public_key();
  auto tbs = to_be_signed();
  signature = identity_priv.sign(tbs);
}

bool
UserInitKey::verify() const
{
  auto tbs = to_be_signed();
  return identity_key.verify(tbs, signature);
}

bytes
UserInitKey::to_be_signed() const
{
  tls::ostream out;
  out << cipher_suites << init_keys << identity_key << algorithm;
  return out.bytes();
}

bool
operator==(const UserInitKey& lhs, const UserInitKey& rhs)
{
  return (lhs.cipher_suites == rhs.cipher_suites) &&
         (lhs.init_keys == rhs.init_keys) &&
         (lhs.identity_key == rhs.identity_key) &&
         (lhs.signature == rhs.signature);
}

tls::ostream&
operator<<(tls::ostream& out, const UserInitKey& obj)
{
  return out << obj.cipher_suites << obj.init_keys << obj.identity_key
             << obj.algorithm << obj.signature;
}

tls::istream&
operator>>(tls::istream& in, UserInitKey& obj)
{
  return in >> obj.cipher_suites >> obj.init_keys >> obj.identity_key >>
         obj.algorithm >> obj.signature;
}

// GroupInitKey

bytes
GroupInitKey::identity_root() const
{
  Tree<MerkleNode> identity_tree(group_size, identity_frontier);
  return identity_tree.root().value();
}

bool
operator==(const GroupInitKey& lhs, const GroupInitKey& rhs)
{
  return (lhs.epoch == rhs.epoch) && (lhs.group_size == rhs.group_size) &&
         (lhs.group_id == rhs.group_id) && (lhs.add_key == rhs.add_key) &&
         (lhs.identity_frontier == rhs.identity_frontier) &&
         (lhs.ratchet_frontier == rhs.ratchet_frontier);
}

tls::ostream&
operator<<(tls::ostream& out, const GroupInitKey& obj)
{
  return out << obj.epoch << obj.group_size << obj.group_id << obj.add_key
             << obj.identity_frontier << obj.ratchet_frontier;
}

tls::istream&
operator>>(tls::istream& in, GroupInitKey& obj)
{
  return in >> obj.epoch >> obj.group_size >> obj.group_id >> obj.add_key >>
         obj.identity_frontier >> obj.ratchet_frontier;
}

// HandshakeType

tls::ostream&
operator<<(tls::ostream& out, const HandshakeType& obj)
{
  return out << uint8_t(obj);
}

tls::istream&
operator>>(tls::istream& in, HandshakeType& obj)
{
  uint8_t type;
  in >> type;
  obj = HandshakeType(type);
  return in;
}

// None

const HandshakeType None::type = HandshakeType::none;

bool
operator==(const None& lhs, const None& rhs)
{
  return true;
}

tls::ostream&
operator<<(tls::ostream& out, const None& obj)
{
  return out;
}

tls::istream&
operator>>(tls::istream& in, None& obj)
{
  return in;
}

// UserAdd

const HandshakeType UserAdd::type = HandshakeType::user_add;

bool
operator==(const UserAdd& lhs, const UserAdd& rhs)
{
  return (lhs.path == rhs.path);
}

tls::ostream&
operator<<(tls::ostream& out, const UserAdd& obj)
{
  return out << obj.path;
}

tls::istream&
operator>>(tls::istream& in, UserAdd& obj)
{
  return in >> obj.path;
}

// GroupAdd

const HandshakeType GroupAdd::type = HandshakeType::group_add;

bool
operator==(const GroupAdd& lhs, const GroupAdd& rhs)
{
  return (lhs.user_init_key == rhs.user_init_key) &&
         (lhs.group_init_key == rhs.group_init_key);
}

tls::ostream&
operator<<(tls::ostream& out, const GroupAdd& obj)
{
  return out << obj.user_init_key << obj.group_init_key;
}

tls::istream&
operator>>(tls::istream& in, GroupAdd& obj)
{
  return in >> obj.user_init_key >> obj.group_init_key;
}

// Update

const HandshakeType Update::type = HandshakeType::update;

bool
operator==(const Update& lhs, const Update& rhs)
{
  return (lhs.path == rhs.path);
}

tls::ostream&
operator<<(tls::ostream& out, const Update& obj)
{
  return out << obj.path;
}

tls::istream&
operator>>(tls::istream& in, Update& obj)
{
  return in >> obj.path;
}

// Remove

const HandshakeType Remove::type = HandshakeType::remove;

bool
operator==(const Remove& lhs, const Remove& rhs)
{
  return (lhs.path == rhs.path);
}

tls::ostream&
operator<<(tls::ostream& out, const Remove& obj)
{
  return out << obj.removed << obj.path;
}

tls::istream&
operator>>(tls::istream& in, Remove& obj)
{
  return in >> obj.removed >> obj.path;
}

tls::ostream&
operator<<(tls::ostream& out, const EpochInfo& obj)
{
  return out << obj.prior_epoch << obj.msg_type << obj.message;
}

} // namespace mls
