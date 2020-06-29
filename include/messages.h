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
  std::vector<HPKECiphertext> node_secrets;

  TLS_SERIALIZABLE(public_key, node_secrets)
  TLS_TRAITS(tls::pass, tls::vector<2>)
};

// struct {
//    RatchetNode nodes<0..2^16-1>;
// } DirectPath;
struct DirectPath
{
  std::vector<RatchetNode> nodes;

  TLS_SERIALIZABLE(nodes)
  TLS_TRAITS(tls::vector<2>)
};

// struct {
//     ProtocolVersion version;
//     CipherSuite cipher_suite;
//     HPKEPublicKey init_key;
//     Credential credential;
//     Extension extensions<0..2^16-1>;
//     opaque signature<0..2^16-1>;
// } KeyPackage;
struct KeyPackage
{
  ProtocolVersion version;
  CipherSuite cipher_suite;
  HPKEPublicKey init_key;
  Credential credential;
  // TODO Extensions
  bytes signature;

  KeyPackage();
  KeyPackage(CipherSuite suite_in,
             const HPKEPublicKey& init_key_in, // NOLINT(modernize-pass-by-value)
             const SignaturePrivateKey& sig_priv_in, // NOLINT(modernize-pass-by-value)
             const Credential& credential_in);

  bytes hash() const;
  bool verify() const;

  TLS_SERIALIZABLE(version, cipher_suite, init_key, credential, signature)
  TLS_TRAITS(tls::pass, tls::pass, tls::pass, tls::pass, tls::vector<2>)

  private:
  bytes to_be_signed() const;
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
  bytes group_id;
  epoch_t epoch;
  RatchetTree tree;
  bytes prior_confirmed_transcript_hash;

  bytes confirmed_transcript_hash;
  bytes interim_transcript_hash;
  DirectPath path;
  bytes confirmation;

  LeafIndex signer_index;
  bytes signature;

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
                   signature)
  TLS_TRAITS(tls::vector<1>,
             tls::pass,
             tls::pass,
             tls::vector<1>,
             tls::vector<1>,
             tls::vector<1>,
             tls::pass,
             tls::vector<1>,
             tls::pass,
             tls::vector<2>)
};

// struct {
//   opaque group_info_key<1..255>;
//   opaque group_info_nonce<1..255>;
//   opaque path_secret<1..255>;
// } GroupSecrets;
struct GroupSecrets {
  bytes init_secret;

  TLS_SERIALIZABLE(init_secret)
  TLS_TRAITS(tls::vector<1>)
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
          bytes init_secret,
          const GroupInfo& group_info);

  void encrypt(const KeyPackage& kp);
  std::optional<int> find(const KeyPackage& kp) const;

  TLS_SERIALIZABLE(version, cipher_suite, secrets, encrypted_group_info)
  TLS_TRAITS(tls::pass, tls::pass, tls::vector<4>, tls::vector<4>)

  private:
  bytes _init_secret;
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
  TLS_SERIALIZABLE(key_package)
};

struct Update {
  HPKEPublicKey leaf_key;
  TLS_SERIALIZABLE(leaf_key)
};

struct Remove {
  LeafIndex removed;
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
             tls::pass);
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

struct CommitData
{
  Commit commit;
  bytes confirmation;

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
             tls::vector<4>);
};

} // namespace mls
