#pragma once

#include "mls/common.h"
#include "mls/core_types.h"
#include "mls/credential.h"
#include "mls/crypto.h"
#include "mls/treekem.h"
#include <optional>
#include <tls/tls_syntax.h>

namespace mls {

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
  TLS_TRAITS(tls::vector<1>)
};

struct MAC
{
  bytes mac_value;

  TLS_SERIALIZABLE(mac_value)
  TLS_TRAITS(tls::vector<1>)
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
  TLS_TRAITS(tls::vector<1>)
};

struct ReInitPSK
{
  bytes group_id;
  epoch_t psk_epoch;
  TLS_SERIALIZABLE(group_id, psk_epoch)
  TLS_TRAITS(tls::vector<1>, tls::pass)
};

struct BranchPSK
{
  bytes group_id;
  epoch_t psk_epoch;
  TLS_SERIALIZABLE(group_id, psk_epoch)
  TLS_TRAITS(tls::vector<1>, tls::pass)
};

struct PreSharedKeyID
{
  var::variant<ExternalPSK, ReInitPSK, BranchPSK> content;
  TLS_SERIALIZABLE(content)
  TLS_TRAITS(tls::variant<PSKType>)
};

struct PreSharedKeys
{
  std::vector<PreSharedKeyID> psks;
  TLS_SERIALIZABLE(psks)
  TLS_TRAITS(tls::vector<2>)
};

// struct {
//     CipherSuite cipher_suite;
//     opaque group_id<0..255>;
//     uint64 epoch;
//     opaque tree_hash<0..255>;
//     opaque interim_transcript_hash<0..255>;
//     Extension extensions<0..2^32-1>;
//     HPKEPublicKey external_pub;
//     uint32 signer_index;
//     opaque signature<0..2^16-1>;
// } PublicGroupState;
struct PublicGroupState
{
  CipherSuite cipher_suite;
  bytes group_id;
  epoch_t epoch;
  bytes tree_hash;
  bytes interim_transcript_hash;
  ExtensionList extensions;
  HPKEPublicKey external_pub;
  LeafIndex signer_index;
  bytes signature;

  PublicGroupState() = default;
  PublicGroupState(CipherSuite cipher_suite_in,
                   bytes group_id_in,
                   epoch_t epoch_in,
                   bytes tree_hash_in,
                   bytes interim_transcript_hash_in,
                   ExtensionList extensions_in,
                   HPKEPublicKey external_pub_in);

  bytes to_be_signed() const;
  void sign(const TreeKEMPublicKey& tree,
            LeafIndex index,
            const SignaturePrivateKey& priv);
  bool verify(const TreeKEMPublicKey& tree) const;

  TLS_SERIALIZABLE(cipher_suite,
                   group_id,
                   epoch,
                   tree_hash,
                   interim_transcript_hash,
                   extensions,
                   external_pub,
                   signer_index,
                   signature)
  TLS_TRAITS(tls::pass,
             tls::vector<1>,
             tls::pass,
             tls::vector<1>,
             tls::vector<1>,
             tls::pass,
             tls::pass,
             tls::pass,
             tls::vector<2>)
};

// struct {
//   opaque group_id<0..255>;
//   uint64 epoch;
//   opaque tree_hash<0..255>;
//   opaque confirmed_transcript_hash<0..255>;
//   Extension extensions<0..2^32-1>;
//   MAC confirmation_tag;
//   uint32 signer_index;
//   opaque signature<0..2^16-1>;
// } GroupInfo;
struct GroupInfo
{
public:
  bytes group_id;
  epoch_t epoch;
  bytes tree_hash;

  bytes confirmed_transcript_hash;
  ExtensionList extensions;

  MAC confirmation_tag;
  LeafIndex signer_index;
  bytes signature;

  GroupInfo() = default;
  GroupInfo(bytes group_id_in,
            epoch_t epoch_in,
            bytes tree_hash_in,
            bytes confirmed_transcript_hash_in,
            ExtensionList extensions_in,
            MAC confirmation_tag_in);

  bytes to_be_signed() const;
  void sign(const TreeKEMPublicKey& tree,
            LeafIndex index,
            const SignaturePrivateKey& priv);
  bool verify(const TreeKEMPublicKey& tree) const;

  TLS_SERIALIZABLE(group_id,
                   epoch,
                   tree_hash,
                   confirmed_transcript_hash,
                   extensions,
                   confirmation_tag,
                   signer_index,
                   signature)
  TLS_TRAITS(tls::vector<1>,
             tls::pass,
             tls::vector<1>,
             tls::vector<1>,
             tls::pass,
             tls::pass,
             tls::pass,
             tls::vector<2>)
};

// struct {
//   opaque joiner_secret<1..255>;
//   optional<PathSecret> path_secret;
//   optional<PreSharedKeys> psks;
// } GroupSecrets;
struct GroupSecrets
{
  struct PathSecret
  {
    bytes secret;

    TLS_SERIALIZABLE(secret)
    TLS_TRAITS(tls::vector<1>)
  };

  bytes joiner_secret;
  std::optional<PathSecret> path_secret;
  std::optional<PreSharedKeys> psks;

  TLS_SERIALIZABLE(joiner_secret, path_secret, psks)
  TLS_TRAITS(tls::vector<1>, tls::pass, tls::pass)
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
  Welcome(CipherSuite suite,
          const bytes& joiner_secret,
          const bytes& psk_secret,
          const GroupInfo& group_info);

  void encrypt(const KeyPackage& kp, const std::optional<bytes>& path_secret);
  std::optional<int> find(const KeyPackage& kp) const;
  GroupInfo decrypt(const bytes& joiner_secret, const bytes& psk_secret) const;

  TLS_SERIALIZABLE(version, cipher_suite, secrets, encrypted_group_info)
  TLS_TRAITS(tls::pass, tls::pass, tls::vector<4>, tls::vector<4>)

private:
  bytes _joiner_secret;
  static KeyAndNonce group_info_key_nonce(CipherSuite suite,
                                          const bytes& joiner_secret,
                                          const bytes& psk_secret);
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
  KeyPackage key_package;
  TLS_SERIALIZABLE(key_package)
};

// Remove
struct Remove
{
  LeafIndex removed;
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
  TLS_TRAITS(tls::vector<1>, tls::pass, tls::pass, tls::pass)
};

// ExternalInit
struct ExternalInit
{
  bytes kem_output;
  TLS_SERIALIZABLE(kem_output)
  TLS_TRAITS(tls::vector<2>)
};

// AppAck
struct MessageRange
{
  uint32_t sender;
  uint32_t first_generation;
  uint32_t last_generation;
  TLS_SERIALIZABLE(sender, first_generation, last_generation);
};

struct AppAck
{
  std::vector<MessageRange> received_ranges;
  TLS_SERIALIZABLE(received_ranges)
  TLS_TRAITS(tls::vector<4>)
};

enum struct ProposalType : uint8_t
{
  invalid = 0,
  add = 1,
  update = 2,
  remove = 3,
  psk = 4,
  reinit = 5,
  external_init = 6,
  app_ack = 7,
};

struct Proposal
{
  var::variant<Add, Update, Remove, PreSharedKey, ReInit, ExternalInit, AppAck>
    content;

  ProposalType proposal_type() const;

  TLS_SERIALIZABLE(content)
  TLS_TRAITS(tls::variant<ProposalType>)
};

struct ProposalRef
{
  bytes id;
  TLS_SERIALIZABLE(id)
  TLS_TRAITS(tls::vector<1>)
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
  external_joiner = 4,
};

struct Sender
{
  SenderType sender_type{ SenderType::invalid };
  uint32_t sender{ 0 };

  TLS_SERIALIZABLE(sender_type, sender)
};

struct MLSPlaintext
{
  bytes group_id;
  epoch_t epoch;
  Sender sender;
  bytes authenticated_data;
  var::variant<ApplicationData, Proposal, Commit> content;

  bytes signature;
  std::optional<MAC> confirmation_tag;
  std::optional<MAC> membership_tag;

  // Constructor for unmarshaling directly
  MLSPlaintext();

  // Constructor for decrypting
  MLSPlaintext(bytes group_id,
               epoch_t epoch,
               Sender sender,
               ContentType content_type,
               bytes authenticated_data,
               const bytes& content);

  // Constructors for encrypting
  MLSPlaintext(bytes group_id,
               epoch_t epoch,
               Sender sender,
               ApplicationData application_data);
  MLSPlaintext(bytes group_id, epoch_t epoch, Sender sender, Proposal proposal);
  MLSPlaintext(bytes group_id, epoch_t epoch, Sender sender, Commit commit);

  ContentType content_type() const;

  bytes to_be_signed(const GroupContext& context) const;
  void sign(const CipherSuite& suite,
            const GroupContext& context,
            const SignaturePrivateKey& priv);
  bool verify(const CipherSuite& suite,
              const GroupContext& context,
              const SignaturePublicKey& pub) const;

  bytes membership_tag_input(const GroupContext& context) const;
  bool verify_membership_tag(const bytes& tag) const;

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
//     uint64 epoch;
//     ContentType content_type;
//     opaque authenticated_data<0..2^32-1>;
//     opaque encrypted_sender_data<0..255>;
//     opaque ciphertext<0..2^32-1>;
// } MLSCiphertext;
struct MLSCiphertext
{
  bytes group_id;
  epoch_t epoch;
  ContentType content_type;
  bytes authenticated_data;
  bytes encrypted_sender_data;
  bytes ciphertext;

  TLS_SERIALIZABLE(group_id,
                   epoch,
                   content_type,
                   authenticated_data,
                   encrypted_sender_data,
                   ciphertext)
  TLS_TRAITS(tls::vector<1>,
             tls::pass,
             tls::pass,
             tls::vector<4>,
             tls::vector<1>,
             tls::vector<4>)
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

TLS_VARIANT_MAP(mls::ContentType, mls::ApplicationData, application)
TLS_VARIANT_MAP(mls::ContentType, mls::Proposal, proposal)
TLS_VARIANT_MAP(mls::ContentType, mls::Commit, commit)

} // namespace tls
