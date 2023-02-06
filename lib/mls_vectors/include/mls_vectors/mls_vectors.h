#pragma once

#include <bytes/bytes.h>
#include <mls/crypto.h>
#include <mls/messages.h>
#include <mls/tree_math.h>
#include <mls/treekem.h>
#include <tls/tls_syntax.h>
#include <vector>

namespace mls_vectors {

struct TreeMathTestVector
{
  using OptionalNode = std::optional<mls::NodeIndex>;

  mls::LeafCount n_leaves;
  mls::NodeCount n_nodes;
  mls::NodeIndex root;
  std::vector<OptionalNode> left;
  std::vector<OptionalNode> right;
  std::vector<OptionalNode> parent;
  std::vector<OptionalNode> sibling;

  std::optional<mls::NodeIndex> null_if_invalid(mls::NodeIndex input,
                                                mls::NodeIndex answer) const;

  TreeMathTestVector() = default;
  TreeMathTestVector(uint32_t n_leaves);
  std::optional<std::string> verify() const;
};

struct CryptoBasicsTestVector
{
  struct RefHash
  {
    std::string label;
    bytes value;
    bytes out;

    RefHash() = default;
    RefHash(mls::CipherSuite suite);
    std::optional<std::string> verify(mls::CipherSuite suite) const;
  };

  struct ExpandWithLabel
  {
    bytes secret;
    std::string label;
    bytes context;
    uint16_t length;
    bytes out;

    ExpandWithLabel() = default;
    ExpandWithLabel(mls::CipherSuite suite);
    std::optional<std::string> verify(mls::CipherSuite suite) const;
  };

  struct DeriveSecret
  {
    bytes secret;
    std::string label;
    bytes out;

    DeriveSecret() = default;
    DeriveSecret(mls::CipherSuite suite);
    std::optional<std::string> verify(mls::CipherSuite suite) const;
  };

  struct SignWithLabel
  {
    mls::SignaturePrivateKey priv;
    mls::SignaturePublicKey pub;
    bytes content;
    std::string label;
    bytes signature;

    SignWithLabel() = default;
    SignWithLabel(mls::CipherSuite suite);
    std::optional<std::string> verify(mls::CipherSuite suite) const;
  };

  struct EncryptWithLabel
  {
    mls::HPKEPrivateKey priv;
    mls::HPKEPublicKey pub;
    std::string label;
    bytes context;
    bytes plaintext;
    bytes kem_output;
    bytes ciphertext;

    EncryptWithLabel() = default;
    EncryptWithLabel(mls::CipherSuite suite);
    std::optional<std::string> verify(mls::CipherSuite suite) const;
  };

  mls::CipherSuite cipher_suite;

  RefHash ref_hash;
  ExpandWithLabel expand_with_label;
  DeriveSecret derive_secret;
  SignWithLabel sign_with_label;
  EncryptWithLabel encrypt_with_label;

  CryptoBasicsTestVector() = default;
  CryptoBasicsTestVector(mls::CipherSuite suite);
  std::optional<std::string> verify() const;
};

struct EncryptionTestVector
{
  struct SenderDataInfo
  {
    bytes ciphertext;
    bytes key;
    bytes nonce;

    SenderDataInfo() = default;
    SenderDataInfo(mls::CipherSuite suite, const bytes& sender_data_secret);
    std::optional<std::string> verify(mls::CipherSuite suite,
                                      const bytes& sender_data_secret) const;
  };

  struct RatchetStep
  {
    uint32_t generation;
    bytes key;
    bytes nonce;
  };

  struct LeafInfo
  {
    std::vector<RatchetStep> handshake;
    std::vector<RatchetStep> application;
  };

  mls::CipherSuite cipher_suite;
  mls::LeafCount n_leaves;

  bytes encryption_secret;
  bytes sender_data_secret;

  SenderDataInfo sender_data_info;
  std::vector<LeafInfo> leaves;

  EncryptionTestVector() = default;
  EncryptionTestVector(mls::CipherSuite suite,
                       uint32_t n_leaves,
                       const std::vector<uint32_t>& generations);
  std::optional<std::string> verify() const;
};

struct KeyScheduleTestVector
{
  struct ExternalPSKInfo
  {
    bytes id;
    bytes nonce;
    bytes secret;
  };

  struct Epoch
  {
    // Chosen by the generator
    bytes tree_hash;
    bytes commit_secret;
    bytes confirmed_transcript_hash;
    std::vector<ExternalPSKInfo> external_psks;
    bytes psk_nonce;

    // Computed values
    bytes group_context;

    bytes psk_secret;
    bytes joiner_secret;
    bytes welcome_secret;
    bytes init_secret;

    bytes sender_data_secret;
    bytes encryption_secret;
    bytes exporter_secret;
    bytes authentication_secret;
    bytes external_secret;
    bytes confirmation_key;
    bytes membership_key;
    bytes resumption_secret;

    mls::HPKEPublicKey external_pub;
  };

  mls::CipherSuite cipher_suite;

  bytes group_id;
  bytes initial_init_secret;

  std::vector<Epoch> epochs;

  static KeyScheduleTestVector create(mls::CipherSuite suite,
                                      uint32_t n_epochs,
                                      uint32_t n_psks);
  std::optional<std::string> verify() const;
};

struct TranscriptTestVector
{
  mls::CipherSuite cipher_suite;

  bytes group_id;
  mls::epoch_t epoch;
  bytes tree_hash_before;
  bytes confirmed_transcript_hash_before;
  bytes interim_transcript_hash_before;

  bytes confirmation_key;

  mls::SignaturePublicKey signature_key;
  mls::MLSAuthenticatedContent commit;

  bytes group_context;
  bytes confirmed_transcript_hash_after;
  bytes interim_transcript_hash_after;

  static TranscriptTestVector create(mls::CipherSuite suite);
  std::optional<std::string> verify() const;
};

struct TreeKEMTestVector
{
  mls::CipherSuite cipher_suite;
  bytes group_id;

  mls::TreeKEMPublicKey ratchet_tree_before;

  mls::LeafIndex add_sender;
  bytes my_leaf_secret;
  mls::LeafNode my_leaf_node;
  bytes my_path_secret;

  mls::LeafIndex update_sender;
  mls::UpdatePath update_path;
  bytes update_group_context;

  bytes tree_hash_before;
  bytes root_secret_after_add;
  bytes root_secret_after_update;
  mls::TreeKEMPublicKey ratchet_tree_after;
  bytes tree_hash_after;

  static TreeKEMTestVector create(mls::CipherSuite suite, size_t n_leaves);
  void initialize_trees();
  std::optional<std::string> verify() const;
};

struct MessagesTestVector
{
  bytes key_package;
  bytes ratchet_tree;

  bytes group_info;
  bytes group_secrets;
  bytes welcome;

  bytes add_proposal;
  bytes update_proposal;
  bytes remove_proposal;
  bytes pre_shared_key_proposal;
  bytes re_init_proposal;
  bytes external_init_proposal;

  bytes commit;

  bytes content_auth_app;
  bytes content_auth_proposal;
  bytes content_auth_commit;
  bytes mls_plaintext;
  bytes mls_ciphertext;

  static MessagesTestVector create();
  std::optional<std::string> verify() const;
};

} // namespace mls_vectors
