#pragma once

#include "mls/common.h"
#include "mls/core_types.h"
#include "mls/credential.h"
#include "mls/crypto.h"
#include "mls/treekem.h"
#include <optional>
#include <tls/tls_syntax.h>
#include <variant>

namespace mls {

// struct {
//   opaque group_id<0..255>;
//   uint64 epoch;
//   optional<Node> tree<1..2^32-1>;
//   opaque confirmed_transcript_hash<0..255>;
//   opaque interim_transcript_hash<0..255>;
//   Extension extensions<0..2^16-1>;
//   opaque confirmation<0..255>
//   uint32 signer_index;
//   opaque signature<0..2^16-1>;
// } GroupInfo;
struct GroupInfo
{
private:
  CipherSuite suite;

public:
  bytes group_id;
  epoch_t epoch;
  TreeKEMPublicKey tree;

  bytes confirmed_transcript_hash;
  bytes interim_transcript_hash;
  ExtensionList extensions;

  bytes confirmation;
  LeafIndex signer_index;
  bytes signature;

  GroupInfo(CipherSuite suite);
  GroupInfo(bytes group_id_in,
            epoch_t epoch_in,
            TreeKEMPublicKey tree_in,
            bytes confirmed_transcript_hash_in,
            bytes interim_transcript_hash_in,
            ExtensionList extensions_in,
            bytes confirmation_in);

  bytes to_be_signed() const;
  void sign(LeafIndex index, const SignaturePrivateKey& priv);
  bool verify() const;

  TLS_SERIALIZABLE(group_id,
                   epoch,
                   tree,
                   confirmed_transcript_hash,
                   interim_transcript_hash,
                   extensions,
                   confirmation,
                   signer_index,
                   signature)
  TLS_TRAITS(tls::vector<1>,
             tls::pass,
             tls::pass,
             tls::vector<1>,
             tls::vector<1>,
             tls::pass,
             tls::vector<1>,
             tls::pass,
             tls::vector<2>)
};

// struct {
//   opaque epoch_secret<1..255>;
//   opaque path_secret<1..255>;
// } GroupSecrets;
struct GroupSecrets
{
  struct PathSecret
  {
    bytes secret;

    TLS_SERIALIZABLE(secret)
    TLS_TRAITS(tls::vector<1>)
  };

  bytes epoch_secret;
  std::optional<PathSecret> path_secret;

  TLS_SERIALIZABLE(epoch_secret, path_secret)
  TLS_TRAITS(tls::vector<1>, tls::pass)
};

// struct {
//   opaque key_package_hash<1..255>;
//   HPKECiphertext encrypted_group_secrets;
// } EncryptedGroupSecrets;
struct EncryptedGroupSecrets
{
  bytes key_package_hash;
  HPKECiphertext encrypted_group_secrets;

  TLS_SERIALIZABLE(key_package_hash, encrypted_group_secrets)
  TLS_TRAITS(tls::vector<1>, tls::pass)
};

// struct {
//   ProtocolVersion version = mls10;
//   CipherSuite cipher_suite;
//   EncryptedGroupSecrets group_secretss<1..2^32-1>;
//   opaque encrypted_group_info<1..2^32-1>;
// } Welcome;
struct Welcome
{
  ProtocolVersion version;
  CipherSuite cipher_suite;
  std::vector<EncryptedGroupSecrets> secrets;
  bytes encrypted_group_info;

  Welcome();
  Welcome(CipherSuite suite, bytes epoch_secret, const GroupInfo& group_info);

  void encrypt(const KeyPackage& kp, const std::optional<bytes>& path_secret);
  std::optional<int> find(const KeyPackage& kp) const;
  GroupInfo decrypt(const bytes& epoch_secret) const;

  TLS_SERIALIZABLE(version, cipher_suite, secrets, encrypted_group_info)
  TLS_TRAITS(tls::pass, tls::pass, tls::vector<4>, tls::vector<4>)

private:
  bytes _epoch_secret;
  std::tuple<bytes, bytes> group_info_key_nonce(
    const bytes& epoch_secret) const;
};

///
/// Proposals & Commit
///
struct ProposalType
{
  enum struct selector : uint8_t
  {
    invalid = 0,
    add = 1,
    update = 2,
    remove = 3,
  };

  template<typename T>
  static const selector type;
};

struct Add
{
  KeyPackage key_package;
  TLS_SERIALIZABLE(key_package)
};

struct Update
{
  KeyPackage key_package;
  TLS_SERIALIZABLE(key_package)
};

struct Remove
{
  LeafIndex removed;
  TLS_SERIALIZABLE(removed)
};

// enum {
//     invalid(0),
//     handshake(1),
//     application(2),
//     (255)
// } ContentType;
struct ContentType
{
  enum struct selector : uint8_t
  {
    invalid = 0,
    application = 1,
    proposal = 2,
    commit = 3,
  };

  template<typename T>
  static const selector type;
};

struct Proposal
{
  std::variant<Add, Update, Remove> content;

  ProposalType::selector proposal_type() const;

  TLS_SERIALIZABLE(content)
  TLS_TRAITS(tls::variant<ProposalType>)
};

struct ProposalID
{
  bytes id;
  TLS_SERIALIZABLE(id)
  TLS_TRAITS(tls::vector<1>)
};

// struct {
//     ProposalID proposals<0..2^32-1>;
//     optional<UpdatePath> path;
// } Commit;
struct Commit
{
  std::vector<ProposalID> proposals;
  std::optional<UpdatePath> path;

  TLS_SERIALIZABLE(proposals, path)
  TLS_TRAITS(tls::vector<4>, tls::pass)
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
struct ApplicationData
{
  bytes data;
  TLS_SERIALIZABLE(data)
  TLS_TRAITS(tls::vector<4>)
};

struct GroupContext;

enum struct SenderType : uint8_t
{
  invalid = 0,
  member = 1,
  preconfigured = 2,
  new_member = 3,
};

struct Sender
{
  SenderType sender_type{ SenderType::invalid };
  uint32_t sender{ 0 };

  TLS_SERIALIZABLE(sender_type, sender)
};

struct MAC
{
  bytes mac_value;

  TLS_SERIALIZABLE(mac_value)
  TLS_TRAITS(tls::vector<1>)
};

struct MLSPlaintext
{
  bytes group_id;
  epoch_t epoch;
  Sender sender;
  bytes authenticated_data;
  std::variant<ApplicationData, Proposal, Commit> content;

  bytes signature;
  std::optional<MAC> confirmation_tag;
  std::optional<MAC> membership_tag;

  // Constructor for unmarshaling directly
  MLSPlaintext();

  // Constructor for decrypting
  MLSPlaintext(bytes group_id,
               epoch_t epoch,
               Sender sender,
               ContentType::selector content_type,
               bytes authenticated_data,
               const bytes& content);

  // Constructors for encrypting
  MLSPlaintext(bytes group_id,
               epoch_t epoch,
               Sender sender,
               ApplicationData application_data);
  MLSPlaintext(bytes group_id, epoch_t epoch, Sender sender, Proposal proposal);
  MLSPlaintext(bytes group_id, epoch_t epoch, Sender sender, Commit commit);

  bytes to_be_signed(const GroupContext& context) const;
  void sign(const CipherSuite& suite,
            const GroupContext& context,
            const SignaturePrivateKey& priv);
  bool verify(const CipherSuite& suite,
              const GroupContext& context,
              const SignaturePublicKey& pub) const;

  bytes membership_tag_input(const GroupContext& context) const;
  void set_membership_tag(const CipherSuite& suite,
                          const GroupContext& context,
                          const bytes& mac_key);
  bool verify_membership_tag(const CipherSuite& suite,
                             const GroupContext& context,
                             const bytes& mac_key) const;

  bytes marshal_content(size_t padding_size) const;

  bytes commit_content() const;
  bytes commit_auth_data() const;

  TLS_SERIALIZABLE(group_id,
                   epoch,
                   sender,
                   authenticated_data,
                   content,
                   signature,
                   confirmation_tag,
                   membership_tag)
  TLS_TRAITS(tls::vector<1>,
             tls::pass,
             tls::pass,
             tls::vector<4>,
             tls::variant<ContentType>,
             tls::vector<2>,
             tls::pass,
             tls::pass)

  private:
  // Not part of the struct, an indicator of whether this MLSPlaintext was
  // constructed from an MLSCiphertext
  bool decrypted;
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
  bytes group_id;
  epoch_t epoch;
  ContentType::selector content_type;
  bytes sender_data_nonce;
  bytes encrypted_sender_data;
  bytes authenticated_data;
  bytes ciphertext;

  TLS_SERIALIZABLE(group_id,
                   epoch,
                   content_type,
                   sender_data_nonce,
                   encrypted_sender_data,
                   authenticated_data,
                   ciphertext)
  TLS_TRAITS(tls::vector<1>,
             tls::pass,
             tls::pass,
             tls::vector<1>,
             tls::vector<1>,
             tls::vector<4>,
             tls::vector<4>)
};

} // namespace mls
