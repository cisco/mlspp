#pragma once

#include "mls/common.h"
#include "mls/core_types.h"
#include "mls/credential.h"
#include "mls/crypto.h"
#include "mls/treekem.h"
#include <optional>
#include <tls/tls_syntax.h>

namespace mls {

struct ExternalPubExtension
{
  HPKEPublicKey external_pub;

  static const uint16_t type;
  TLS_SERIALIZABLE(external_pub)
};

struct RatchetTreeExtension
{
  TreeKEMPublicKey tree;

  static const uint16_t type;
  TLS_SERIALIZABLE(tree)
};

struct SFrameParameters
{
  uint16_t cipher_suite;
  uint8_t epoch_bits;

  static const uint16_t type;
  TLS_SERIALIZABLE(cipher_suite, epoch_bits)
};

struct SFrameCapabilities
{
  std::vector<uint16_t> cipher_suites;

  bool compatible(const SFrameParameters& params) const;

  static const uint16_t type;
  TLS_SERIALIZABLE(cipher_suites)
};

///
/// PSKs
///
enum struct PSKType : uint8_t
{
  reserved = 0,
  external = 1,
  reinit = 2,
  branch = 3,
};

struct ExternalPSK
{
  bytes psk_id;
  TLS_SERIALIZABLE(psk_id)
};

struct ReInitPSK
{
  bytes group_id;
  epoch_t psk_epoch;
  TLS_SERIALIZABLE(group_id, psk_epoch)
};

struct BranchPSK
{
  bytes group_id;
  epoch_t psk_epoch;
  TLS_SERIALIZABLE(group_id, psk_epoch)
};

struct PreSharedKeyID
{
  var::variant<ExternalPSK, ReInitPSK, BranchPSK> content;
  bytes psk_nonce;
  TLS_SERIALIZABLE(content, psk_nonce)
  TLS_TRAITS(tls::variant<PSKType>, tls::pass)
};

struct PreSharedKeys
{
  std::vector<PreSharedKeyID> psks;
  TLS_SERIALIZABLE(psks)
};

struct PSKWithSecret
{
  PreSharedKeyID id;
  bytes secret;
};

// struct {
//     CipherSuite cipher_suite;
//     opaque group_id<V>;
//     uint64 epoch;
//     opaque tree_hash<V>;
//     opaque confirmed_transcript_hash<V>;
//     Extension group_context_extensions<V>;
//     Extension other_extensions<V>;
//     MAC confirmation_tag;
//     LeafNodeRef signer;
//     // SignWithLabel(., "GroupInfoTBS", GroupInfoTBS)
//     opaque signature<V>;
// } GroupInfo;
struct GroupInfo
{
  CipherSuite cipher_suite;
  bytes group_id;
  epoch_t epoch;
  bytes tree_hash;
  bytes confirmed_transcript_hash;
  ExtensionList group_context_extensions;
  ExtensionList other_extensions;

  bytes confirmation_tag;
  LeafNodeRef signer;
  bytes signature;

  GroupInfo() = default;
  GroupInfo(CipherSuite cipher_suite_in,
            bytes group_id_in,
            epoch_t epoch_in,
            bytes tree_hash_in,
            bytes confirmed_transcript_hash_in,
            ExtensionList group_context_extensions_in,
            ExtensionList other_extensions_in,
            bytes confirmation_tag_in);

  bytes to_be_signed() const;
  void sign(const TreeKEMPublicKey& tree,
            LeafNodeRef signer_ref,
            const SignaturePrivateKey& priv);
  bool verify(const TreeKEMPublicKey& tree) const;

  TLS_SERIALIZABLE(cipher_suite,
                   group_id,
                   epoch,
                   tree_hash,
                   confirmed_transcript_hash,
                   group_context_extensions,
                   other_extensions,
                   confirmation_tag,
                   signer,
                   signature)
};

// struct {
//   opaque joiner_secret<1..255>;
//   optional<PathSecret> path_secret;
//   PreSharedKeys psks;
// } GroupSecrets;
struct GroupSecrets
{
  struct PathSecret
  {
    bytes secret;

    TLS_SERIALIZABLE(secret)
  };

  bytes joiner_secret;
  std::optional<PathSecret> path_secret;
  PreSharedKeys psks;

  TLS_SERIALIZABLE(joiner_secret, path_secret, psks)
};

// struct {
//   opaque key_package_hash<1..255>;
//   HPKECiphertext encrypted_group_secrets;
// } EncryptedGroupSecrets;
struct EncryptedGroupSecrets
{
  KeyPackageRef new_member;
  HPKECiphertext encrypted_group_secrets;

  TLS_SERIALIZABLE(new_member, encrypted_group_secrets)
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
  Welcome(CipherSuite suite,
          const bytes& joiner_secret,
          const std::vector<PSKWithSecret>& psks,
          const GroupInfo& group_info);

  void encrypt(const KeyPackage& kp, const std::optional<bytes>& path_secret);
  std::optional<int> find(const KeyPackage& kp) const;
  GroupInfo decrypt(const bytes& joiner_secret,
                    const std::vector<PSKWithSecret>& psks) const;

  TLS_SERIALIZABLE(version, cipher_suite, secrets, encrypted_group_info)

private:
  bytes _joiner_secret;
  static KeyAndNonce group_info_key_nonce(
    CipherSuite suite,
    const bytes& joiner_secret,
    const std::vector<PSKWithSecret>& psks);
};

///
/// Proposals & Commit
///

// Add
struct Add
{
  KeyPackage key_package;
  TLS_SERIALIZABLE(key_package)
};

// Update
struct Update
{
  LeafNode leaf_node;
  TLS_SERIALIZABLE(leaf_node)
};

// Remove
struct Remove
{
  LeafNodeRef removed;
  TLS_SERIALIZABLE(removed)
};

// PreSharedKey
struct PreSharedKey
{
  PreSharedKeyID psk;
  TLS_SERIALIZABLE(psk)
};

// ReInit
struct ReInit
{
  bytes group_id;
  ProtocolVersion version;
  CipherSuite cipher_suite;
  ExtensionList extensions;

  TLS_SERIALIZABLE(group_id, version, cipher_suite, extensions)
};

// ExternalInit
struct ExternalInit
{
  bytes kem_output;
  TLS_SERIALIZABLE(kem_output)
};

// AppAck
struct MessageRange
{
  uint32_t sender;
  uint32_t first_generation;
  uint32_t last_generation;
  TLS_SERIALIZABLE(sender, first_generation, last_generation)
};

struct AppAck
{
  std::vector<MessageRange> received_ranges;
  TLS_SERIALIZABLE(received_ranges)
};

// GroupContextExtensions
struct GroupContextExtensions
{
  ExtensionList group_context_extensions;
  TLS_SERIALIZABLE(group_context_extensions)
};

struct ProposalType;

struct Proposal
{
  using Type = uint16_t;

  var::variant<Add,
               Update,
               Remove,
               PreSharedKey,
               ReInit,
               ExternalInit,
               AppAck,
               GroupContextExtensions>
    content;

  Type proposal_type() const;

  TLS_SERIALIZABLE(content)
  TLS_TRAITS(tls::variant<ProposalType>)
};

struct ProposalType
{
  static constexpr Proposal::Type invalid = 0;
  static constexpr Proposal::Type add = 1;
  static constexpr Proposal::Type update = 2;
  static constexpr Proposal::Type remove = 3;
  static constexpr Proposal::Type psk = 4;
  static constexpr Proposal::Type reinit = 5;
  static constexpr Proposal::Type external_init = 6;
  static constexpr Proposal::Type app_ack = 7;
  static constexpr Proposal::Type group_context_extensions = 8;

  constexpr ProposalType()
    : val(invalid)
  {
  }

  constexpr ProposalType(Proposal::Type pt)
    : val(pt)
  {
  }

  Proposal::Type val;
  TLS_SERIALIZABLE(val)
};

enum struct ProposalOrRefType : uint8_t
{
  reserved = 0,
  value = 1,
  reference = 2,
};

struct ProposalOrRef
{
  var::variant<Proposal, ProposalRef> content;

  TLS_SERIALIZABLE(content)
  TLS_TRAITS(tls::variant<ProposalOrRefType>)
};

// struct {
//     ProposalOrRef proposals<0..2^32-1>;
//     optional<UpdatePath> path;
// } Commit;
struct Commit
{
  std::vector<ProposalOrRef> proposals;
  std::optional<UpdatePath> path;

  // Validate that the commit is accepable as an external commit, and if so,
  // produce the public key from the ExternalInit proposal
  std::optional<bytes> valid_external() const;

  TLS_SERIALIZABLE(proposals, path)
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
};

struct GroupContext;

enum struct WireFormat : uint8_t
{
  reserved = 0,
  mls_plaintext = 1,
  mls_ciphertext = 2,
  mls_welcome = 3,
  mls_group_info = 4,
  mls_key_package = 5,
};

enum struct ContentType : uint8_t
{
  invalid = 0,
  application = 1,
  proposal = 2,
  commit = 3,
};

enum struct SenderType : uint8_t
{
  invalid = 0,
  member = 1,
  preconfigured = 2,
  new_member = 3,
};

struct PreconfiguredKeyID
{
  bytes id;
  TLS_SERIALIZABLE(id)
};

struct NewMemberID
{
  TLS_SERIALIZABLE()
};

struct Sender
{
  var::variant<LeafNodeRef, PreconfiguredKeyID, NewMemberID> sender;

  SenderType sender_type() const;

  TLS_SERIALIZABLE(sender)
  TLS_TRAITS(tls::variant<SenderType>)
};

///
/// MLSMessage and friends
///
struct GroupKeySource;

struct MLSMessageContent
{
  using RawContent = var::variant<ApplicationData, Proposal, Commit>;

  bytes group_id;
  epoch_t epoch;
  Sender sender;
  bytes authenticated_data;
  RawContent content;

  MLSMessageContent() = default;
  MLSMessageContent(bytes group_id_in,
                    epoch_t epoch_in,
                    Sender sender_in,
                    bytes authenticated_data_in,
                    RawContent content_in);
  MLSMessageContent(bytes group_id_in,
                    epoch_t epoch_in,
                    Sender sender_in,
                    bytes authenticated_data_in,
                    ContentType content_type);

  ContentType content_type() const;

  TLS_SERIALIZABLE(group_id, epoch, sender, authenticated_data, content)
  TLS_TRAITS(tls::pass,
             tls::pass,
             tls::pass,
             tls::pass,
             tls::variant<ContentType>)
};

struct MLSMessageAuth
{
  ContentType content_type = ContentType::invalid;
  bytes signature;
  std::optional<bytes> confirmation_tag;

  friend tls::ostream& operator<<(tls::ostream& str, const MLSMessageAuth& obj);
  friend tls::istream& operator>>(tls::istream& str, MLSMessageAuth& obj);
  friend bool operator==(const MLSMessageAuth& lhs, const MLSMessageAuth& rhs);
};

struct MLSMessageContentAuth
{
  WireFormat wire_format;
  MLSMessageContent content;
  MLSMessageAuth auth;

  MLSMessageContentAuth() = default;

  static MLSMessageContentAuth sign(WireFormat wire_format,
                                    MLSMessageContent content,
                                    CipherSuite suite,
                                    const SignaturePrivateKey& sig_priv,
                                    const std::optional<GroupContext>& context);
  bool verify(CipherSuite suite,
              const SignaturePublicKey& sig_pub,
              const std::optional<GroupContext>& context) const;

  bytes commit_content() const;
  bytes commit_auth_data() const;

  void set_confirmation_tag(const bytes& confirmation_tag);
  bool check_confirmation_tag(const bytes& confirmation_tag) const;

  friend tls::ostream& operator<<(tls::ostream& str,
                                  const MLSMessageContentAuth& obj);
  friend tls::istream& operator>>(tls::istream& str,
                                  MLSMessageContentAuth& obj);
  friend bool operator==(const MLSMessageContentAuth& lhs,
                         const MLSMessageContentAuth& rhs);

private:
  MLSMessageContentAuth(WireFormat wire_format_in,
                        MLSMessageContent content_in);
  MLSMessageContentAuth(WireFormat wire_format_in,
                        MLSMessageContent content_in,
                        MLSMessageAuth auth_in);

  bytes to_be_signed(const std::optional<GroupContext>& context) const;

  friend struct MLSPlaintext;
  friend struct MLSCiphertext;
};

struct MLSPlaintext
{
  MLSPlaintext() = default;

  epoch_t get_epoch() const { return content.epoch; }

  static MLSPlaintext protect(MLSMessageContentAuth content_auth,
                              CipherSuite suite,
                              const std::optional<bytes>& membership_key,
                              const std::optional<GroupContext>& context);
  std::optional<MLSMessageContentAuth> unprotect(
    CipherSuite suite,
    const std::optional<bytes>& membership_key,
    const std::optional<GroupContext>& context) const;

  friend tls::ostream& operator<<(tls::ostream& str, const MLSPlaintext& obj);
  friend tls::istream& operator>>(tls::istream& str, MLSPlaintext& obj);

private:
  MLSMessageContent content;
  MLSMessageAuth auth;
  std::optional<bytes> membership_tag;

  MLSPlaintext(MLSMessageContentAuth content_auth);

  bytes membership_mac(CipherSuite suite,
                       const bytes& membership_key,
                       const std::optional<GroupContext>& context) const;
};

struct MLSCiphertext
{
  MLSCiphertext() = default;

  epoch_t get_epoch() const { return epoch; }

  static MLSCiphertext protect(MLSMessageContentAuth content_auth,
                               CipherSuite suite,
                               const LeafIndex& index,
                               GroupKeySource& keys,
                               const bytes& sender_data_secret,
                               size_t padding_size);
  std::optional<MLSMessageContentAuth> unprotect(
    CipherSuite suite,
    const TreeKEMPublicKey& tree,
    GroupKeySource& keys,
    const bytes& sender_data_secret) const;

  TLS_SERIALIZABLE(group_id,
                   epoch,
                   content_type,
                   authenticated_data,
                   encrypted_sender_data,
                   ciphertext)

private:
  bytes group_id;
  epoch_t epoch;
  ContentType content_type;
  bytes authenticated_data;
  bytes encrypted_sender_data;
  bytes ciphertext;

  MLSCiphertext(MLSMessageContent content,
                bytes encrypted_sender_data_in,
                bytes ciphertext_in);
};

struct MLSMessage
{
  ProtocolVersion version = ProtocolVersion::mls10;
  var::variant<MLSPlaintext, MLSCiphertext, Welcome, GroupInfo, KeyPackage>
    message;

  epoch_t epoch() const;
  WireFormat wire_format() const;

  MLSMessage() = default;
  MLSMessage(MLSPlaintext mls_plaintext);
  MLSMessage(MLSCiphertext mls_ciphertext);
  MLSMessage(Welcome welcome);
  MLSMessage(GroupInfo group_info);
  MLSMessage(KeyPackage key_package);

  TLS_SERIALIZABLE(version, message)
  TLS_TRAITS(tls::pass, tls::variant<WireFormat>)
};

} // namespace mls

namespace tls {

TLS_VARIANT_MAP(mls::PSKType, mls::ExternalPSK, external)
TLS_VARIANT_MAP(mls::PSKType, mls::ReInitPSK, reinit)
TLS_VARIANT_MAP(mls::PSKType, mls::BranchPSK, branch)

TLS_VARIANT_MAP(mls::ProposalOrRefType, mls::Proposal, value)
TLS_VARIANT_MAP(mls::ProposalOrRefType, mls::ProposalRef, reference)

TLS_VARIANT_MAP(mls::ProposalType, mls::Add, add)
TLS_VARIANT_MAP(mls::ProposalType, mls::Update, update)
TLS_VARIANT_MAP(mls::ProposalType, mls::Remove, remove)
TLS_VARIANT_MAP(mls::ProposalType, mls::PreSharedKey, psk)
TLS_VARIANT_MAP(mls::ProposalType, mls::ReInit, reinit)
TLS_VARIANT_MAP(mls::ProposalType, mls::ExternalInit, external_init)
TLS_VARIANT_MAP(mls::ProposalType, mls::AppAck, app_ack)
TLS_VARIANT_MAP(mls::ProposalType,
                mls::GroupContextExtensions,
                group_context_extensions)

TLS_VARIANT_MAP(mls::ContentType, mls::ApplicationData, application)
TLS_VARIANT_MAP(mls::ContentType, mls::Proposal, proposal)
TLS_VARIANT_MAP(mls::ContentType, mls::Commit, commit)

TLS_VARIANT_MAP(mls::SenderType, mls::KeyPackageRef, member)
TLS_VARIANT_MAP(mls::SenderType, mls::PreconfiguredKeyID, preconfigured)
TLS_VARIANT_MAP(mls::SenderType, mls::NewMemberID, new_member)

TLS_VARIANT_MAP(mls::WireFormat, mls::MLSPlaintext, mls_plaintext)
TLS_VARIANT_MAP(mls::WireFormat, mls::MLSCiphertext, mls_ciphertext)
TLS_VARIANT_MAP(mls::WireFormat, mls::Welcome, mls_welcome)
TLS_VARIANT_MAP(mls::WireFormat, mls::GroupInfo, mls_group_info)
TLS_VARIANT_MAP(mls::WireFormat, mls::KeyPackage, mls_key_package)

} // namespace tls
