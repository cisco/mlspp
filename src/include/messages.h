#pragma once

#include "common.h"
#include "crypto.h"
#include "ratchet_tree.h"
#include "tls_syntax.h"
#include <optional>

#define DUMMY_CIPHERSUITE CipherSuite::P256_SHA256_AES128GCM
#define DUMMY_SCHEME SignatureScheme::P256_SHA256

namespace mls {

// struct {
//    DHPublicKey public_key;
//    HPKECiphertext node_secrets<0..2^16-1>;
// } RatchetNode
struct RatchetNode : public CipherAware
{
  DHPublicKey public_key;
  tls::variant_vector<HPKECiphertext, CipherSuite, 2> node_secrets;

  RatchetNode(CipherSuite suite)
    : CipherAware(suite)
    , public_key(suite)
    , node_secrets(suite)
  {}

  RatchetNode(const DHPublicKey& public_key,
              const std::vector<HPKECiphertext>& node_secrets)
    : CipherAware(public_key)
    , public_key(public_key)
    , node_secrets(node_secrets)
  {}
};

bool
operator==(const RatchetNode& lhs, const RatchetNode& rhs);
tls::ostream&
operator<<(tls::ostream& out, const RatchetNode& obj);
tls::istream&
operator>>(tls::istream& in, RatchetNode& obj);

// struct {
//    RatchetNode nodes<0..2^16-1>;
// } DirectPath;
struct DirectPath : public CipherAware
{
  tls::variant_vector<RatchetNode, CipherSuite, 2> nodes;

  DirectPath(CipherSuite suite)
    : CipherAware(suite)
    , nodes(suite)
  {}
};

bool
operator==(const DirectPath& lhs, const DirectPath& rhs);
tls::ostream&
operator<<(tls::ostream& out, const DirectPath& obj);
tls::istream&
operator>>(tls::istream& in, DirectPath& obj);

// struct {
//     opaque user_init_key_id<0..255>;
//     ProtocolVersion supported_versions<0..255>;
//     CipherSuite cipher_suites<0..255>;
//     HPKEPublicKey init_keys<1..2^16-1>;
//     Credential credential;
//     opaque signature<0..2^16-1>;
// } UserInitKey;
struct UserInitKey
{
  tls::opaque<1> user_init_key_id;
  tls::vector<ProtocolVersion, 1> supported_versions;
  tls::vector<CipherSuite, 1> cipher_suites;
  tls::vector<tls::opaque<2>, 2> init_keys; // Postpone crypto parsing
  Credential credential;
  tls::opaque<2> signature;

  UserInitKey()
    : supported_versions(1, mls10Version)
  {}

  void add_init_key(const DHPublicKey& pub);
  std::optional<DHPublicKey> find_init_key(CipherSuite suite) const;
  void sign(const SignaturePrivateKey& identity_priv,
            const Credential& credential);
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
//   ProtocolVersion version;
//   opaque group_id<0..255>;
//   uint32 epoch;
//   optional<Credential> roster<1..2^32-1>;
//   optional<HPKEPublicKey> tree<1..2^32-1>;
//   opaque transcript_hash<0..255>;
//   opaque init_secret<0..255>;
// } WelcomeInfo;
struct WelcomeInfo : public CipherAware
{
  ProtocolVersion version;
  tls::opaque<1> group_id;
  epoch_t epoch;
  RatchetTree tree;
  tls::opaque<1> transcript_hash;
  tls::opaque<1> init_secret;

  WelcomeInfo(CipherSuite suite)
    : CipherAware(suite)
    , tree(suite)
  {}

  WelcomeInfo(tls::opaque<2> group_id,
              epoch_t epoch,
              RatchetTree tree,
              tls::opaque<1> transcript_hash,
              tls::opaque<1> init_secret)
    : CipherAware(tree)
    , version(mls10Version)
    , group_id(group_id)
    , epoch(epoch)
    , tree(tree)
    , transcript_hash(transcript_hash)
    , init_secret(init_secret)
  {}

  bytes hash(CipherSuite suite) const;
};

bool
operator==(const WelcomeInfo& lhs, const WelcomeInfo& rhs);
tls::ostream&
operator<<(tls::ostream& out, const WelcomeInfo& obj);
tls::istream&
operator>>(tls::istream& in, WelcomeInfo& obj);

// struct {
//   opaque user_init_key_id<0..255>;
//   CipherSuite cipher_suite;
//   HPKECiphertext encrypted_welcome_info;
// } Welcome;
struct Welcome
{
  tls::opaque<1> user_init_key_id;
  CipherSuite cipher_suite;
  HPKECiphertext encrypted_welcome_info;

  Welcome()
    : encrypted_welcome_info(DUMMY_CIPHERSUITE)
  {}

  Welcome(const bytes& id, const DHPublicKey& pub, const WelcomeInfo& info);
  WelcomeInfo decrypt(const DHPrivateKey& priv) const;
};

bool
operator==(const Welcome& lhs, const Welcome& rhs);
tls::ostream&
operator<<(tls::ostream& out, const Welcome& obj);
tls::istream&
operator>>(tls::istream& in, Welcome& obj);

// enum { ... } GroupOperationType;
enum class GroupOperationType : uint8_t
{
  add = 1,
  update = 2,
  remove = 3,
};

tls::ostream&
operator<<(tls::ostream& out, const GroupOperationType& obj);
tls::istream&
operator>>(tls::istream& in, GroupOperationType& obj);

// struct {
//     uint32 index;
//     UserInitKey init_key;
//     opaque welcome_info_hash<0..255>;
// } Add;
struct Add
{
public:
  LeafIndex index;
  UserInitKey init_key;
  tls::opaque<1> welcome_info_hash;

  Add() {}

  Add(LeafIndex index, const UserInitKey& init_key, bytes welcome_info_hash)
    : index(index)
    , init_key(init_key)
    , welcome_info_hash(std::move(welcome_info_hash))
  {}

  static const GroupOperationType type;
};

bool
operator==(const Add& lhs, const Add& rhs);
tls::ostream&
operator<<(tls::ostream& out, const Add& obj);
tls::istream&
operator>>(tls::istream& in, Add& obj);

// struct {
//     DirectPath path;
// } Update;
struct Update : public CipherAware
{
public:
  DirectPath path;

  Update(CipherSuite suite)
    : CipherAware(suite)
    , path(suite)
  {}

  Update(const DirectPath& path)
    : CipherAware(path)
    , path(path)
  {}

  static const GroupOperationType type;
};

bool
operator==(const Update& lhs, const Update& rhs);
tls::ostream&
operator<<(tls::ostream& out, const Update& obj);
tls::istream&
operator>>(tls::istream& in, Update& obj);

// struct {
//     uint32 removed;
//     DirectPath path;
// } Remove;
struct Remove : public CipherAware
{
public:
  LeafIndex removed;
  DirectPath path;

  Remove(CipherSuite suite)
    : CipherAware(suite)
    , path(suite)
  {}

  Remove(LeafIndex removed, const DirectPath& path)
    : CipherAware(path)
    , removed(removed)
    , path(path)
  {}

  static const GroupOperationType type;
};

bool
operator==(const Remove& lhs, const Remove& rhs);
tls::ostream&
operator<<(tls::ostream& out, const Remove& obj);
tls::istream&
operator>>(tls::istream& in, Remove& obj);

// Container class for all operations
//
// struct {
//     GroupOperationType msg_type;
//     select (GroupOperation.msg_type) {
//         case init:      Init;
//         case add:       Add;
//         case update:    Update;
//         case remove:    Remove;
//     };
// } GroupOperation;
//
// NB: This is a "pseudo-union" type, in that only one of the struct
// members will be populated with a non-zero value.  This is a bit
// wasteful of memory, but necessary to avoid the silliness of C++
// union types over structs.
struct GroupOperation : public CipherAware
{
  GroupOperationType type;

  std::optional<Add> add;
  std::optional<Update> update;
  std::optional<Remove> remove;

  GroupOperation()
    : CipherAware(DUMMY_CIPHERSUITE)
  {}

  GroupOperation(CipherSuite suite)
    : CipherAware(suite)
  {}

  GroupOperation(const Add& add)
    : CipherAware(DUMMY_CIPHERSUITE)
    , type(add.type)
    , add(add)
  {}

  GroupOperation(const Update& update)
    : CipherAware(update)
    , type(update.type)
    , update(update)

  {}

  GroupOperation(const Remove& remove)
    : CipherAware(remove)
    , type(remove.type)
    , remove(remove)
  {}

  friend bool operator==(const GroupOperation& lhs, const GroupOperation& rhs);
  friend tls::ostream& operator<<(tls::ostream& out, const GroupOperation& obj);
  friend tls::istream& operator>>(tls::istream& in, GroupOperation& obj);
};

// enum {
//     invalid(0),
//     handshake(1),
//     application(2),
//     (255)
// } ContentType;
enum struct ContentType : uint8_t
{
  invalid = 0,
  handshake = 1,
  application = 2,
};

tls::ostream&
operator<<(tls::ostream& out, const ContentType& obj);
tls::istream&
operator>>(tls::istream& in, ContentType& obj);

// struct {
//     opaque group_id<0..255>;
//     uint32 epoch;
//     uint32 sender;
//     ContentType content_type;
//
//     select (MLSPlaintext.content_type) {
//         case handshake:
//             GroupOperation operation;
//             opaque confirmation<0..255>;
//
//         case application:
//             opaque application_data<0..2^32-1>;
//     }
//
//     opaque signature<0..2^16-1>;
// } MLSPlaintext;
struct MLSPlaintext : public CipherAware
{
  using CipherAware::CipherAware;

  tls::opaque<1> group_id;
  epoch_t epoch;
  LeafIndex sender;
  ContentType content_type;

  std::optional<GroupOperation> operation;
  std::optional<tls::opaque<1>> confirmation;
  std::optional<tls::opaque<4>> application_data;

  tls::opaque<2> signature;

  MLSPlaintext(bytes group_id,
               epoch_t epoch,
               LeafIndex sender,
               GroupOperation operation)
    : CipherAware(operation.cipher_suite())
    , group_id(group_id)
    , epoch(epoch)
    , sender(sender)
    , content_type(ContentType::handshake)
    , operation(operation)
  {}

  MLSPlaintext(bytes group_id,
               epoch_t epoch,
               LeafIndex sender,
               const bytes& application_data)
    : CipherAware(DUMMY_CIPHERSUITE)
    , group_id(group_id)
    , epoch(epoch)
    , sender(sender)
    , content_type(ContentType::application)
    , application_data(application_data)
  {}

  bytes to_be_signed() const;
  void sign(const SignaturePrivateKey& priv);
  bool verify(const SignaturePublicKey& pub) const;

  bytes marshal_content(size_t padding_size) const;
  void unmarshal_content(CipherSuite suite, const bytes& marshaled);

  bytes content() const;
  bytes auth_data() const;

  friend bool operator==(const MLSPlaintext& lhs, const MLSPlaintext& rhs);
  friend tls::ostream& operator<<(tls::ostream& out, const MLSPlaintext& obj);
  friend tls::istream& operator>>(tls::istream& in, MLSPlaintext& obj);
};

// struct {
//     uint32 epoch;
//     opaque masked_sender_data[9];
//     opaque ciphertext<0..2^32-1>;
// } MLSCiphertext;
struct MLSCiphertext
{
  uint32_t epoch;
  std::array<uint8_t, 9> masked_sender_data;
  tls::opaque<4> ciphertext;
};

bool
operator==(const MLSCiphertext& lhs, const MLSCiphertext& rhs);
tls::ostream&
operator<<(tls::ostream& out, const MLSCiphertext& obj);
tls::istream&
operator>>(tls::istream& in, MLSCiphertext& obj);

} // namespace mls
