#pragma once

#include "common.h"
#include "crypto.h"
#include "ratchet_tree.h"
#include "roster.h"
#include "tls_syntax.h"

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
//     MerkleNode identity_frontier<0..2^16-1>; // XXX changed
//     DHPublicKey ratchet_frontier<0..2^16-1>; // XXX changed
// } GroupInitKey;
struct GroupInitKey
{
  epoch_t epoch;
  uint32_t group_size;
  tls::opaque<2> group_id;
  uint16_t cipher_suite;
  DHPublicKey add_key;
  Roster roster;
  RatchetTree ratchet_tree;
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
  group_add = 1,
  update = 2,
  remove = 3,
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
//     MerkleNode identity_proof<1..2^16-1>;  // XXX changed
//     SignaturePublicKey identity_key;       // XXX changed
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
  tls::opaque<2, 1> signature;

  epoch_t epoch() const { return next_epoch(prior_epoch, message); }

  void sign(const SignaturePrivateKey& identity_priv)
  {
    auto tbs = to_be_signed();
    signature = identity_priv.sign(tbs);
  }

  bool verify(const Roster& roster) const
  {
    auto identity_key = roster.get(signer_index).public_key();
    auto tbs = to_be_signed();
    return identity_key.verify(tbs, signature);
  }

  bytes to_be_signed() const
  {
    tls::opaque<3> message_data = tls::marshal(message);

    tls::ostream out;
    out << Message::type << message_data << prior_epoch << group_size
        << signer_index;
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

  in >> obj.prior_epoch >> obj.group_size >> obj.signer_index >> obj.signature;
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
