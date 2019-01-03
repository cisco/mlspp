#include "messages.h"

namespace mls {

// RatchetNode

bool
operator==(const RatchetNode& lhs, const RatchetNode& rhs)
{
  return (lhs.public_key == rhs.public_key) &&
         (lhs.node_secrets == rhs.node_secrets);
}

tls::ostream&
operator<<(tls::ostream& out, const RatchetNode& obj)
{
  return out << obj.public_key << obj.node_secrets;
}

tls::istream&
operator>>(tls::istream& in, RatchetNode& obj)
{
  return in >> obj.public_key >> obj.node_secrets;
}

// DirectPath

bool
operator==(const DirectPath& lhs, const DirectPath& rhs)
{
  return (lhs.nodes == rhs.nodes);
}

tls::ostream&
operator<<(tls::ostream& out, const DirectPath& obj)
{
  return out << obj.nodes;
}

tls::istream&
operator>>(tls::istream& in, DirectPath& obj)
{
  return in >> obj.nodes;
}

// UserInitKey

void
UserInitKey::add_init_key(const DHPublicKey& pub)
{
  cipher_suites.push_back(pub.cipher_suite());
  init_keys.push_back(pub.to_bytes());
}

optional<DHPublicKey>
UserInitKey::find_init_key(CipherSuite suite) const
{
  for (int i = 0; i < cipher_suites.size(); ++i) {
    if (cipher_suites[i] == suite) {
      return DHPublicKey{ suite, init_keys[i] };
    }
  }

  return nullopt;
}

void
UserInitKey::sign(const SignaturePrivateKey& identity_priv)
{
  if (cipher_suites.size() != init_keys.size()) {
    throw InvalidParameterError("Mal-formed UserInitKey");
  }

  identity_key = identity_priv.public_key();
  algorithm = identity_priv.signature_scheme();
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
  out << cipher_suites << init_keys << algorithm << identity_key;
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
  return out << obj.cipher_suites << obj.init_keys << obj.algorithm
             << obj.identity_key << obj.signature;
}

tls::istream&
operator>>(tls::istream& in, UserInitKey& obj)
{
  in >> obj.cipher_suites >> obj.init_keys >> obj.algorithm;

  auto key = SignaturePublicKey(obj.algorithm);
  in >> key;
  obj.identity_key = key;

  in >> obj.signature;
  return in;
}

// Welcome

bool
operator==(const Welcome& lhs, const Welcome& rhs)
{
  return (lhs.group_id == rhs.group_id) && (lhs.epoch == rhs.epoch) &&
         (lhs.roster == rhs.roster) && (lhs.tree == rhs.tree) &&
         (lhs.transcript == rhs.transcript) &&
         (lhs.init_secret == rhs.init_secret);
}

tls::ostream&
operator<<(tls::ostream& out, const Welcome& obj)
{
  return out << obj.group_id << obj.epoch << obj.cipher_suite << obj.roster
             << obj.tree << obj.transcript << obj.init_secret;
}

tls::istream&
operator>>(tls::istream& in, Welcome& obj)
{
  in >> obj.group_id >> obj.epoch >> obj.cipher_suite;

  // Set the tree struct to use the correct ciphersuite for this
  // group
  obj.tree = RatchetTree(obj.cipher_suite);

  in >> obj.roster;
  in >> obj.tree;
  in >> obj.transcript;
  in >> obj.init_secret;
  return in;
}

// GroupOperationType

tls::ostream&
operator<<(tls::ostream& out, const GroupOperationType& obj)
{
  return out << uint8_t(obj);
}

tls::istream&
operator>>(tls::istream& in, GroupOperationType& obj)
{
  uint8_t type;
  in >> type;
  obj = GroupOperationType(type);
  return in;
}

// Add

const GroupOperationType Add::type = GroupOperationType::add;

bool
operator==(const Add& lhs, const Add& rhs)
{
  return (lhs.init_key == rhs.init_key);
}

tls::ostream&
operator<<(tls::ostream& out, const Add& obj)
{
  return out << obj.init_key;
}

tls::istream&
operator>>(tls::istream& in, Add& obj)
{
  return in >> obj.init_key;
}

// Update

const GroupOperationType Update::type = GroupOperationType::update;

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

const GroupOperationType Remove::type = GroupOperationType::remove;

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

// GroupOperation
bool
operator==(const GroupOperation& lhs, const GroupOperation& rhs)
{
  return (lhs.type == rhs.type) &&
         (((lhs.type == GroupOperationType::add) && (lhs.add == rhs.add)) ||
          ((lhs.type == GroupOperationType::update) &&
           (lhs.update == rhs.update)) ||
          ((lhs.type == GroupOperationType::remove) &&
           (lhs.remove == rhs.remove)));
}

tls::ostream&
operator<<(tls::ostream& out, const GroupOperation& obj)
{
  out << obj.type;

  switch (obj.type) {
    case GroupOperationType::add:
      return out << obj.add;
    case GroupOperationType::update:
      return out << obj.update;
    case GroupOperationType::remove:
      return out << obj.remove;
  }

  throw InvalidParameterError("Unknown group operation type");
}

tls::istream&
operator>>(tls::istream& in, GroupOperation& obj)
{
  in >> obj.type;

  switch (obj.type) {
    case GroupOperationType::add:
      return in >> obj.add;
    case GroupOperationType::update:
      return in >> obj.update;
    case GroupOperationType::remove:
      return in >> obj.remove;
  }

  throw InvalidParameterError("Unknown group operation type");
}

// Handshake
bool
operator==(const Handshake& lhs, const Handshake& rhs)
{
  return (lhs.prior_epoch == rhs.prior_epoch) &&
         (lhs.operation == rhs.operation) &&
         (lhs.signer_index == rhs.signer_index) &&
         (lhs.signature == rhs.signature);
}

tls::ostream&
operator<<(tls::ostream& out, const Handshake& obj)
{
  return out << obj.prior_epoch << obj.operation << obj.signer_index
             << obj.signature;
}

tls::istream&
operator>>(tls::istream& in, Handshake& obj)
{
  return in >> obj.prior_epoch >> obj.operation >> obj.signer_index >>
         obj.signature;
}

} // namespace mls
