#pragma once

#include "common.h"
#include "crypto.h"
#include "ratchet_tree.h"
#include "tls_syntax.h"
#include <optional>
#include <variant>

namespace mls {

///
/// Protocol versions
///

enum class ProtocolVersion : uint8_t
{
  mls10 = 0xFF,
};

// struct {
//    HPKEPublicKey public_key;
//    HPKECiphertext node_secrets<0..2^16-1>;
// } RatchetNode
struct RatchetNode
{
  HPKEPublicKey public_key;
  tls::vector<HPKECiphertext, 2> node_secrets;

  TLS_SERIALIZABLE(public_key, node_secrets);
};

// struct {
//    RatchetNode nodes<0..2^16-1>;
// } DirectPath;
struct DirectPath
{
  tls::vector<RatchetNode, 2> nodes;

  TLS_SERIALIZABLE(nodes);
};

// struct {
//     ProtocolVersion version;
//     CipherSuite cipher_suite;
//     HPKEPublicKey init_key;
//     Credential credential;
//     Extension extensions<0..2^16-1>;
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
  ProtocolVersion version;
  CipherSuite cipher_suite;
  HPKEPublicKey init_key;
  Credential credential;
  // TODO Extensions
  tls::opaque<2> signature;

  ClientInitKey();
  ClientInitKey(CipherSuite suite_in,
                const HPKEPrivateKey& init_key_in,
                Credential credential_in);

  const std::optional<HPKEPrivateKey>& private_key() const;
  bytes hash() const;

  bool verify() const;

  TLS_SERIALIZABLE(version, cipher_suite, init_key, credential, signature);

  private:
  bytes to_be_signed() const;
  std::optional<HPKEPrivateKey> _private_key;
};

// struct {
//   // GroupContext inputs
//   opaque group_id<0..255>;
//   uint32 epoch;
//   optional<RatchetNode> tree<1..2^32-1>;
//   opaque confirmed_transcript_hash<0..255>;
//
//   // Inputs to the next round of the key schedule
//   opaque interim_transcript_hash<0..255>;
//   opaque epoch_secret<0..255>;
//
//   uint32 signer_index;
//   opaque signature<0..255>;
// } GroupInfo;
struct GroupInfo {
  tls::opaque<1> group_id;
  epoch_t epoch;
  RatchetTree tree;
  tls::opaque<1> prior_confirmed_transcript_hash;

  tls::opaque<1> confirmed_transcript_hash;
  tls::opaque<1> interim_transcript_hash;
  DirectPath path;
  tls::opaque<1> confirmation;

  LeafIndex signer_index;
  tls::opaque<2> signature;

  GroupInfo(CipherSuite suite);
  GroupInfo(bytes group_id_in,
            epoch_t epoch_in,
            RatchetTree tree_in,
            bytes prior_confirmed_transcript_hash_in,
            bytes confirmed_transcript_hash_in,
            bytes interim_transcript_hash_in,
            DirectPath path_in,
            bytes confirmation_in);

  bytes to_be_signed() const;
  void sign(LeafIndex index, const SignaturePrivateKey& priv);
  bool verify() const;

  TLS_SERIALIZABLE(group_id,
                   epoch,
                   tree,
                   prior_confirmed_transcript_hash,
                   confirmed_transcript_hash,
                   interim_transcript_hash,
                   path,
                   confirmation,
                   signer_index,
                   signature);
};

// struct {
//   opaque group_info_key<1..255>;
//   opaque group_info_nonce<1..255>;
//   opaque path_secret<1..255>;
// } KeyPackage;
struct KeyPackage {
  tls::opaque<1> init_secret;

  TLS_SERIALIZABLE(init_secret);
};

// struct {
//   opaque client_init_key_hash<1..255>;
//   HPKECiphertext encrypted_key_package;
// } EncryptedKeyPackage;
struct EncryptedKeyPackage {
  tls::opaque<1> client_init_key_hash;
  HPKECiphertext encrypted_key_package;

  TLS_SERIALIZABLE(client_init_key_hash, encrypted_key_package);
};


// struct {
//   ProtocolVersion version = mls10;
//   CipherSuite cipher_suite;
//   EncryptedKeyPackage key_packages<1..2^32-1>;
//   opaque encrypted_group_info<1..2^32-1>;
// } Welcome;
struct Welcome {
  ProtocolVersion version;
  CipherSuite cipher_suite;
  tls::vector<EncryptedKeyPackage, 4> key_packages;
  tls::opaque<4> encrypted_group_info;

  Welcome();
  Welcome(CipherSuite suite,
          bytes init_secret,
          const GroupInfo& group_info);

  void encrypt(const ClientInitKey& cik);

  private:
  bytes _init_secret;
};

bool operator==(const Welcome& lhs, const Welcome& rhs);
tls::ostream& operator<<(tls::ostream& str, const Welcome& obj);
tls::istream& operator>>(tls::istream& str, Welcome& obj);

///
/// Proposals & Commit
///

enum struct ProposalType : uint8_t {
  invalid = 0,
  add = 1,
  update = 2,
  remove = 3,
};

struct Add {
  ClientInitKey client_init_key;

  static const ProposalType type;
  TLS_SERIALIZABLE(client_init_key)
};

struct Update {
  HPKEPublicKey leaf_key;

  static const ProposalType type;
  TLS_SERIALIZABLE(leaf_key)
};

struct Remove {
  LeafIndex removed;

  static const ProposalType type;
  TLS_SERIALIZABLE(removed)
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
  application = 1,
  proposal = 2,
  commit = 3,
};

struct Proposal : public tls::variant<ProposalType, Add, Update, Remove>
{
  using parent = tls::variant<ProposalType, Add, Update, Remove>;
  using parent::parent;

  static const ContentType type;
};

// struct {
//     ProposalID updates<0..2^16-1>;
//     ProposalID removes<0..2^16-1>;
//     ProposalID adds<0..2^16-1>;
//     ProposalID ignored<0..2^16-1>;
//     DirectPath path;
// } Commit;
using ProposalID = tls::opaque<1>;
struct Commit {
  tls::vector<ProposalID, 2> updates;
  tls::vector<ProposalID, 2> removes;
  tls::vector<ProposalID, 2> adds;
  tls::vector<ProposalID, 2> ignored;
  DirectPath path;

  TLS_SERIALIZABLE(updates, removes, adds, ignored, path);
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
struct ApplicationData : tls::opaque<4>
{
  using parent = tls::opaque<4>;
  using parent::parent;

  static const ContentType type;
};

struct CommitData
{
  Commit commit;
  tls::opaque<1> confirmation;

  static const ContentType type;
  TLS_SERIALIZABLE(commit, confirmation);
};

struct GroupContext;

struct MLSPlaintext
{
  tls::opaque<1> group_id;
  epoch_t epoch;
  LeafIndex sender;
  tls::opaque<4> authenticated_data;
  tls::variant<ContentType, ApplicationData, Proposal, CommitData> content;
  tls::opaque<2> signature;

  // Constructor for unmarshaling directly
  MLSPlaintext() = default;

  // Constructor for decrypting
  MLSPlaintext(bytes group_id,
               epoch_t epoch,
               LeafIndex sender,
               ContentType content_type,
               bytes authenticated_data,
               const bytes& content);

  // Constructors for encrypting
  MLSPlaintext(bytes group_id,
               epoch_t epoch,
               LeafIndex sender,
               const ApplicationData& application_data);
  MLSPlaintext(bytes group_id,
               epoch_t epoch,
               LeafIndex sender,
               const Proposal& proposal);
  MLSPlaintext(bytes group_id,
               epoch_t epoch,
               LeafIndex sender,
               const Commit& commit);

  bytes to_be_signed(const GroupContext& context) const;
  void sign(const GroupContext& context, const SignaturePrivateKey& priv);
  bool verify(const GroupContext& context, const SignaturePublicKey& pub) const;

  bytes marshal_content(size_t padding_size) const;

  bytes commit_content() const;
  bytes commit_auth_data() const;

  TLS_SERIALIZABLE(group_id, epoch, sender, authenticated_data, content, signature);
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
  tls::opaque<4> authenticated_data;
  tls::opaque<4> ciphertext;

  TLS_SERIALIZABLE(group_id, epoch, content_type, sender_data_nonce,
                   encrypted_sender_data, authenticated_data, ciphertext);
};

} // namespace mls
