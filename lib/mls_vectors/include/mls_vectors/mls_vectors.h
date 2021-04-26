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
    bytes plaintext;
    bytes ciphertext;
  };

  struct LeafInfo
  {
    uint32_t generations;
    std::vector<RatchetStep> handshake;
    std::vector<RatchetStep> application;
  };

  mls::CipherSuite cipher_suite;
  mls::LeafCount n_leaves;

  bytes encryption_secret;
  bytes sender_data_secret;
  SenderDataInfo sender_data_info;

  std::vector<LeafInfo> leaves;

  static EncryptionTestVector create(mls::CipherSuite suite,
                                     uint32_t n_leaves,
                                     uint32_t n_generations);
  std::optional<std::string> verify() const;
};

struct CryptoValue
{
  bytes data;
  TLS_SERIALIZABLE(data)
  TLS_TRAITS(tls::vector<1>)
};

struct KeyScheduleTestVector
{
  struct Epoch
  {
    // Chosen by the generator
    bytes tree_hash;
    bytes commit_secret;
    bytes psk_secret;
    bytes confirmed_transcript_hash;

    // Computed values
    bytes group_context;

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
                                      uint32_t n_epochs);
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

  bytes membership_key;
  bytes confirmation_key;
  mls::MLSPlaintext commit;

  bytes group_context;
  bytes confirmed_transcript_hash_after;
  bytes interim_transcript_hash_after;

  static TranscriptTestVector create(mls::CipherSuite suite);
  std::optional<std::string> verify() const;
};

struct TreeKEMTestVector
{
  mls::CipherSuite cipher_suite;

  mls::TreeKEMPublicKey ratchet_tree_before;

  mls::LeafIndex add_sender;
  bytes my_leaf_secret;
  mls::KeyPackage my_key_package;
  bytes my_path_secret;

  mls::LeafIndex update_sender;
  mls::UpdatePath update_path;

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
  bytes capabilities;
  bytes lifetime;
  bytes ratchet_tree;

  bytes group_info;
  bytes group_secrets;
  bytes welcome;

  bytes public_group_state;

  bytes add_proposal;
  bytes update_proposal;
  bytes remove_proposal;
  bytes pre_shared_key_proposal;
  bytes re_init_proposal;
  bytes external_init_proposal;
  bytes app_ack_proposal;

  bytes commit;

  bytes mls_plaintext_application;
  bytes mls_plaintext_proposal;
  bytes mls_plaintext_commit;
  bytes mls_ciphertext;

  static MessagesTestVector create();
  std::optional<std::string> verify() const;
};

} // namespace mls_vectors
