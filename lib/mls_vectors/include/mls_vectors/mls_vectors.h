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
  std::vector<mls::NodeIndex> root;
  std::vector<OptionalNode> left;
  std::vector<OptionalNode> right;
  std::vector<OptionalNode> parent;
  std::vector<OptionalNode> sibling;

  static TreeMathTestVector create(uint32_t n_leaves);
  std::optional<std::string> verify() const;
};

struct EncryptionTestVector
{
  struct SenderDataInfo
  {
    bytes ciphertext;
    bytes key;
    bytes nonce;
  };

  struct RatchetStep
  {
    bytes key;
    bytes nonce;
    bytes ciphertext;
  };

  struct LeafInfo
  {
    uint32_t generations;
    bytes handshake_content_auth;
    bytes application_content_auth;
    std::vector<RatchetStep> handshake;
    std::vector<RatchetStep> application;
  };

  mls::CipherSuite cipher_suite;

  bytes tree;
  bytes encryption_secret;
  bytes sender_data_secret;
  size_t padding_size = 0;
  SenderDataInfo sender_data_info;
  bytes authenticated_data;

  std::vector<LeafInfo> leaves;

  static EncryptionTestVector create(mls::CipherSuite suite,
                                     uint32_t n_leaves,
                                     uint32_t n_generations);
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
