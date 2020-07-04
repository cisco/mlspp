#pragma once

#include "common.h"
#include "credential.h"
#include "crypto.h"
#include "core_types.h"
#include "treekem.h"
#include "tls_syntax.h"
#include <optional>
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
struct GroupInfo {
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
struct GroupSecrets {
  struct PathSecret {
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
struct EncryptedGroupSecrets {
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
struct Welcome {
  ProtocolVersion version;
  CipherSuite cipher_suite;
  std::vector<EncryptedGroupSecrets> secrets;
  bytes encrypted_group_info;

  Welcome();
  Welcome(CipherSuite suite,
          bytes epoch_secret,
          const GroupInfo& group_info);

  void encrypt(const KeyPackage& kp, const std::optional<bytes>& path_secret);
  std::optional<int> find(const KeyPackage& kp) const;
  GroupInfo decrypt(const bytes& epoch_secret) const;

  TLS_SERIALIZABLE(version, cipher_suite, secrets, encrypted_group_info)
  TLS_TRAITS(tls::pass, tls::pass, tls::vector<4>, tls::vector<4>)

  private:
  bytes _epoch_secret;
  std::tuple<bytes, bytes> group_info_key_nonce(const bytes& epoch_secret) const;
};

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
  KeyPackage key_package;

  static const ProposalType type;
  TLS_SERIALIZABLE(key_package)
};

struct Update {
  KeyPackage key_package;

  static const ProposalType type;
  TLS_SERIALIZABLE(key_package)
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

struct Proposal
{
  std::variant<Add, Update, Remove> content;

  static const ContentType type;
  TLS_SERIALIZABLE(content)
  TLS_TRAITS(tls::variant<ProposalType>)
};

struct ProposalID {
  bytes id;
  TLS_SERIALIZABLE(id)
  TLS_TRAITS(tls::vector<1>)
};

// struct {
//     ProposalID updates<0..2^16-1>;
//     ProposalID removes<0..2^16-1>;
//     ProposalID adds<0..2^16-1>;
//     ProposalID ignored<0..2^16-1>;
//     DirectPath path;
// } Commit;
struct Commit {
  std::vector<ProposalID> updates;
  std::vector<ProposalID> removes;
  std::vector<ProposalID> adds;
  std::vector<ProposalID> ignored;
  DirectPath path;

  TLS_SERIALIZABLE(updates, removes, adds, ignored, path)
  TLS_TRAITS(tls::vector<2>,
             tls::vector<2>,
             tls::vector<2>,
             tls::vector<2>,
             tls::pass)
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

  static const ContentType type;
  TLS_SERIALIZABLE(data)
  TLS_TRAITS(tls::vector<4>)
};

struct CommitData
{
  Commit commit;
  bytes confirmation;

  static const ContentType type;
  TLS_SERIALIZABLE(commit, confirmation)
  TLS_TRAITS(tls::pass, tls::vector<1>)
};

struct GroupContext;

struct MLSPlaintext
{
  bytes group_id;
  epoch_t epoch;
  LeafIndex sender;
  bytes authenticated_data;
  std::variant<ApplicationData, Proposal, CommitData> content;
  bytes signature;

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

  TLS_SERIALIZABLE(group_id, epoch, sender, authenticated_data, content, signature)
  TLS_TRAITS(tls::vector<1>,
             tls::pass,
             tls::pass,
             tls::vector<4>,
             tls::variant<ContentType>,
             tls::vector<2>)
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
  ContentType content_type;
  bytes sender_data_nonce;
  bytes encrypted_sender_data;
  bytes authenticated_data;
  bytes ciphertext;

  TLS_SERIALIZABLE(group_id, epoch, content_type, sender_data_nonce,
                   encrypted_sender_data, authenticated_data, ciphertext);
  TLS_TRAITS(tls::vector<1>,
             tls::pass,
             tls::pass,
             tls::vector<1>,
             tls::vector<1>,
             tls::vector<4>,
             tls::vector<4>)
};

} // namespace mls
