#pragma once

#include "common.h"
#include "crypto.h"
#include "ratchet_tree.h"
#include "tls_syntax.h"
#include <optional>

namespace mls {

// struct {
//    DHPublicKey public_key;
//    HPKECiphertext node_secrets<0..2^16-1>;
// } RatchetNode
struct RatchetNode : public CipherAware
{
  DHPublicKey public_key;
  tls::variant_vector<HPKECiphertext, CipherSuite, 2> node_secrets;

  RatchetNode(CipherSuite suite);
  RatchetNode(DHPublicKey public_key,
              const std::vector<HPKECiphertext>& node_secrets);

  TLS_SERIALIZABLE(public_key, node_secrets);
};

// struct {
//    RatchetNode nodes<0..2^16-1>;
// } DirectPath;
struct DirectPath : public CipherAware
{
  tls::variant_vector<RatchetNode, CipherSuite, 2> nodes;
  DirectPath(CipherSuite suite);

  TLS_SERIALIZABLE(nodes);
};

// struct {
//     opaque client_init_key_id<0..255>;
//     ProtocolVersion supported_versions<0..255>;
//     CipherSuite cipher_suites<0..255>;
//     HPKEPublicKey init_keys<1..2^16-1>;
//     Credential credential;
//     opaque signature<0..2^16-1>;
// } ClientInitKey;
//
// XXX(rlb@ipv.sx): Right now, we use this to represent both the
// public version of a client's capabilities, and the private
// version (with private keys).  This results in some ugly checking
// code when private keys are needed, so it might be nice to split
// these two cases in the type system.
struct ClientInitKey
{
  tls::opaque<1> client_init_key_id;
  tls::vector<ProtocolVersion, 1> supported_versions;
  tls::vector<CipherSuite, 1> cipher_suites;
  tls::vector<tls::opaque<2>, 2> init_keys; // Postpone crypto parsing
  Credential credential;
  tls::opaque<2> signature;

  ClientInitKey();
  ClientInitKey(bytes client_init_key_id,
                const CipherList& supported_ciphersuites,
                const bytes& init_secret,
                const Credential& credential);

  void add_init_key(const DHPrivateKey& priv);
  std::optional<DHPublicKey> find_init_key(CipherSuite suite) const;
  std::optional<DHPrivateKey> find_private_key(CipherSuite suite) const;
  void sign(const Credential& credential);
  bool verify() const;
  bytes to_be_signed() const;

  TLS_SERIALIZABLE(client_init_key_id, supported_versions, cipher_suites,
                   init_keys, credential, signature)

  private:
  std::map<CipherSuite, DHPrivateKey> _private_keys;
};

// struct {
//   ProtocolVersion version;
//   opaque group_id<0..255>;
//   uint32 epoch;
//   optional<Credential> roster<1..2^32-1>;
//   optional<HPKEPublicKey> tree<1..2^32-1>;
//   opaque interim_transcript_hash<0..255>;
//   opaque init_secret<0..255>;
// } WelcomeInfo;
struct WelcomeInfo : public CipherAware
{
  ProtocolVersion version;
  tls::opaque<1> group_id;
  epoch_t epoch;
  RatchetTree tree;
  tls::opaque<1> interim_transcript_hash;
  tls::opaque<1> init_secret;

  WelcomeInfo(CipherSuite suite);
  WelcomeInfo(tls::opaque<2> group_id,
              epoch_t epoch,
              RatchetTree tree,
              const tls::opaque<1>& interim_transcript_hash,
              const tls::opaque<1>& init_secret);

  bytes hash(CipherSuite suite) const;

  TLS_SERIALIZABLE(version, group_id, epoch, tree, interim_transcript_hash, init_secret);
};

// struct {
//   opaque client_init_key_id<0..255>;
//   CipherSuite cipher_suite;
//   HPKECiphertext encrypted_welcome_info;
// } Welcome;
struct Welcome
{
  tls::opaque<1> client_init_key_id;
  CipherSuite cipher_suite;
  HPKECiphertext encrypted_welcome_info;

  Welcome();
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
  none = 0,
  add = 1,
  update = 2,
  remove = 3,
};

// struct {
//     uint32 index;
//     ClientInitKey init_key;
//     opaque welcome_info_hash<0..255>;
// } Add;
struct Add
{
public:
  LeafIndex index;
  ClientInitKey init_key;
  tls::opaque<1> welcome_info_hash;

  Add() = default;
  Add(LeafIndex index, ClientInitKey init_key, bytes welcome_info_hash);
  static const GroupOperationType type;

  TLS_SERIALIZABLE(index, init_key, welcome_info_hash)
};

// struct {
//     DirectPath path;
// } Update;
struct Update : public CipherAware
{
public:
  DirectPath path;

  Update(CipherSuite suite);
  Update(const DirectPath& path);
  static const GroupOperationType type;

  TLS_SERIALIZABLE(path);
};

// struct {
//     uint32 removed;
//     DirectPath path;
// } Remove;
struct Remove : public CipherAware
{
public:
  LeafIndex removed;
  DirectPath path;

  Remove(CipherSuite suite);
  Remove(LeafIndex removed, const DirectPath& path);
  static const GroupOperationType type;

  TLS_SERIALIZABLE(removed, path);
};

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

  GroupOperation();
  GroupOperation(CipherSuite suite);
  GroupOperation(const Add& add);
  GroupOperation(const Update& update);
  GroupOperation(const Remove& remove);

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
  tls::opaque<1> confirmation;
  tls::opaque<4> application_data;

  tls::opaque<2> signature;

  MLSPlaintext(bytes group_id,
               epoch_t epoch,
               LeafIndex sender,
               GroupOperation operation);
  MLSPlaintext(bytes group_id,
               epoch_t epoch,
               LeafIndex sender,
               bytes application_data);

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
//     opaque group_id<0..255>;
//     uint32 epoch;
//     ContentType content_type;
//     opaque sender_data_nonce<0..255>;
//     opaque encrypted_sender_data<0..255>;
//     opaque ciphertext<0..2^32-1>;
// } MLSCiphertext;
struct MLSCiphertext
{
  tls::opaque<1> group_id;
  uint32_t epoch;
  ContentType content_type;
  tls::opaque<1> sender_data_nonce;
  tls::opaque<1> encrypted_sender_data;
  tls::opaque<4> ciphertext;

  TLS_SERIALIZABLE(group_id, epoch, content_type, sender_data_nonce,
                   encrypted_sender_data, ciphertext);
};

} // namespace mls
