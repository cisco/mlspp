#pragma once

#include "common.h"
#include "crypto.h"
#include "ratchet_tree.h"
#include "tls_syntax.h"
#include "tree.h"

namespace mls {

// struct {
//     CipherSuite cipher_suites<0..255>; // ignored
//     DHPublicKey init_keys<1..2^16-1>;  // only use first
//     SignaturePublicKey identity_key;
//     SignatureScheme algorithm;         // always 0
//     tls::opaque signature<0..2^16-1>;
// } UserInitKey;
struct UserInitKey
{
  tls::vector<uint16_t, 1> cipher_suites;
  tls::vector<DHPublicKey, 2> init_keys;
  SignaturePublicKey identity_key;
  uint16_t algorithm = 0;
  tls::opaque<2> signature;

  void sign(const SignaturePrivateKey& identity_priv);
  bool verify() const;
  bytes to_be_signed() const;
};

bool
operator==(const UserInitKey& lhs, const UserInitKey& rhs);
tls::ostream&
operator<<(tls::ostream& out, const UserInitKey& obj);
tls::istream&
operator>>(tls::istream& in, UserInitKey& obj);

// struct {
//     uint64 epoch;
//     uint32 group_size;
//     tls::opaque group_id<0..2^16-1>;
//     CipherSuite cipher_suite;                // ignored
//     DHPublicKey add_key;
//     MerkleNode identity_frontier<0..2^16-1>;
//     DHPublicKey ratchet_frontier<0..2^16-1>; // XXX changed
// } GroupInitKey;
struct GroupInitKey
{
  epoch_t epoch;
  uint32_t group_size;
  tls::opaque<2> group_id;
  uint16_t cipher_suite;
  DHPublicKey add_key;
  tls::vector<MerkleNode, 2> identity_frontier;
  RatchetTree ratchet_tree;

  bytes identity_root() const;
};

bool
operator==(const GroupInitKey& lhs, const GroupInitKey& rhs);
tls::ostream&
operator<<(tls::ostream& out, const GroupInitKey& obj);
tls::istream&
operator>>(tls::istream& in, GroupInitKey& obj);

enum class HandshakeType : uint8_t
{
  none = 0,
  user_add = 1,
  group_add = 2,
  update = 3,
  remove = 4,
};

tls::ostream&
operator<<(tls::ostream& out, const HandshakeType& obj);
tls::istream&
operator>>(tls::istream& in, HandshakeType& obj);

// struct {} None;
struct None
{
  static const HandshakeType type;
};

bool
operator==(const None& lhs, const None& rhs);
tls::ostream&
operator<<(tls::ostream& out, const None& obj);
tls::istream&
operator>>(tls::istream& in, None& obj);

// struct {
//     DHPublicKey path<1..2^16-1>;
// } UserAdd;
struct UserAdd
{
public:
  RatchetPath path;

  static const HandshakeType type;
};

bool
operator==(const UserAdd& lhs, const UserAdd& rhs);
tls::ostream&
operator<<(tls::ostream& out, const UserAdd& obj);
tls::istream&
operator>>(tls::istream& in, UserAdd& obj);

// struct {
//     UserInitKey init_key;
// } GroupAdd;
struct GroupAdd
{
public:
  RatchetPath path;
  UserInitKey user_init_key;
  GroupInitKey group_init_key;

  static const HandshakeType type;
};

bool
operator==(const GroupAdd& lhs, const GroupAdd& rhs);
tls::ostream&
operator<<(tls::ostream& out, const GroupAdd& obj);
tls::istream&
operator>>(tls::istream& in, GroupAdd& obj);

// struct {
//     DHPublicKey path<1..2^16-1>;
// } Update;
struct Update
{
public:
  RatchetPath path;

  static const HandshakeType type;
};

bool
operator==(const Update& lhs, const Update& rhs);
tls::ostream&
operator<<(tls::ostream& out, const Update& obj);
tls::istream&
operator>>(tls::istream& in, Update& obj);

// struct {
//     uint32 removed;
//     DHPublicKey path<1..2^16-1>;
// } Remove;
struct Remove
{
public:
  uint32_t removed;
  RatchetPath path;

  static const HandshakeType type;
};

bool
operator==(const Remove& lhs, const Remove& rhs);
tls::ostream&
operator<<(tls::ostream& out, const Remove& obj);
tls::istream&
operator>>(tls::istream& in, Remove& obj);

// struct {
//     HandshakeType msg_type;
//     uint24 inner_length;
//     select (Handshake.msg_type) {
//         case none:      struct{};
//         case init:      Init;
//         case user_add:  UserAdd;
//         case group_add: GroupAdd;
//         case update:    Update;
//         case remove:    Remove;
//     };
//
//     uint64 prior_epoch;
//     uint64 current_epoch;
//
//     uint32 group_size;
//     uint32 signer_index;
//     MerkleNode identity_proof<1..2^16-1>;
//     SignaturePublicKey identity_key;
//
//     SignatureScheme algorithm;             // OMITTED
//     tls::opaque signature<1..2^16-1>;
// } Handshake;
//
// XXX(rlb@ipv.sx): Handling polymorphism at compile time via a
// template will make it difficult to generically read a handshake
// message from a stream.  There are basically two approaches: (1)
// peeking at the message type before reading the stream, or (2)
// reading the bytes into some generic struct, then convert it to a
// specific struct.
template<typename Message>
struct Handshake
{
  Message message;

  epoch_t prior_epoch;

  uint32_t group_size;
  uint32_t signer_index;
  tls::vector<MerkleNode, 2> identity_proof;
  SignaturePublicKey identity_key;
  tls::opaque<2, 1> signature;

  epoch_t epoch() const { return next_epoch(prior_epoch, message); }

  void sign(const SignaturePrivateKey& identity_priv)
  {
    identity_key = identity_priv.public_key();
    auto tbs = to_be_signed();
    signature = identity_priv.sign(tbs);
  }

  bool verify(const bytes& identity_root) const
  {
    auto tbs = to_be_signed();
    if (!identity_key.verify(tbs, signature)) {
      return false;
    }

    Tree<MerkleNode> identity_tree(group_size, signer_index, identity_proof);

    auto leaf = MerkleNode::leaf(identity_key.to_bytes());
    identity_tree.update(signer_index, leaf);

    return identity_tree.root().value() == identity_root;
  }

  bytes to_be_signed() const
  {
    tls::opaque<3> message_data = tls::marshal(message);

    tls::ostream out;
    out << Message::type << message_data << prior_epoch << group_size
        << signer_index << identity_proof << identity_key;
    return out.bytes();
  }
};

template<typename Message>
bool
operator==(const Handshake<Message>& lhs, const Handshake<Message>& rhs)
{
  return (lhs.message == rhs.message) && (lhs.prior_epoch == rhs.prior_epoch) &&
         (lhs.group_size == rhs.group_size) &&
         (lhs.signer_index == rhs.signer_index) &&
         (lhs.identity_proof == rhs.identity_proof) &&
         (lhs.identity_key == rhs.identity_key) &&
         (lhs.signature == rhs.signature);
}

template<typename Message>
tls::ostream&
operator<<(tls::ostream& out, const Handshake<Message>& obj)
{
  auto tbs = obj.to_be_signed();
  out.write_raw(tbs);
  out << obj.signature;
  return out;
}

template<typename Message>
tls::istream&
operator>>(tls::istream& in, Handshake<Message>& obj)
{
  HandshakeType type;
  in >> type;
  if (type != Message::type) {
    throw tls::ReadError("Improper content type for object type");
  }

  tls::opaque<3> message;
  in >> message;
  tls::unmarshal(message, obj.message);

  in >> obj.prior_epoch >> obj.group_size >> obj.signer_index >>
    obj.identity_proof >> obj.identity_key >> obj.signature;
  return in;
}

// Epoch evolution
//
// struct {
//    uint64 prior_epoch;
//    HandshakeType msg_type;
//    opaque message<0..2^24-1>;
// } EpochInfo;
struct EpochInfo
{
  epoch_t prior_epoch;
  HandshakeType msg_type;
  tls::opaque<3> message;
};

tls::ostream&
operator<<(tls::ostream& out, const EpochInfo& obj);

template<typename Message>
epoch_t
next_epoch(const epoch_t& prior, const Message& message)
{
  // TODO Enable non-linear epoch updates
  return prior + 1;
}

} // namespace mls
