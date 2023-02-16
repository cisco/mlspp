#pragma once

#include <bytes/bytes.h>
#include <mls/crypto.h>
#include <mls/key_schedule.h>
#include <mls/messages.h>
#include <mls/tree_math.h>
#include <mls/treekem.h>
#include <tls/tls_syntax.h>
#include <vector>

namespace mls_vectors {

struct PseudoRandom
{
  struct Generator
  {
    Generator() = default;
    Generator(mls::CipherSuite suite_in, const std::string& label);
    Generator sub(const std::string& label) const;

    bytes secret(const std::string& label) const;
    bytes generate(const std::string& label, size_t size) const;

    uint16_t uint16(const std::string& label) const;
    uint32_t uint32(const std::string& label) const;
    uint64_t uint64(const std::string& label) const;

    mls::SignaturePrivateKey signature_key(const std::string& label) const;
    mls::HPKEPrivateKey hpke_key(const std::string& label) const;

    size_t output_length() const;

  private:
    mls::CipherSuite suite;
    bytes seed;

    Generator(mls::CipherSuite suite_in, bytes&& seed_in);
  };

  PseudoRandom() = default;
  PseudoRandom(mls::CipherSuite suite, const std::string& label);

  Generator prg;
};

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

struct CryptoBasicsTestVector : PseudoRandom
{
  struct RefHash
  {
    std::string label;
    bytes value;
    bytes out;

    RefHash() = default;
    RefHash(mls::CipherSuite suite, PseudoRandom::Generator&& prg);
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
    ExpandWithLabel(mls::CipherSuite suite, PseudoRandom::Generator&& prg);
    std::optional<std::string> verify(mls::CipherSuite suite) const;
  };

  struct DeriveSecret
  {
    bytes secret;
    std::string label;
    bytes out;

    DeriveSecret() = default;
    DeriveSecret(mls::CipherSuite suite, PseudoRandom::Generator&& prg);
    std::optional<std::string> verify(mls::CipherSuite suite) const;
  };

  struct DeriveTreeSecret
  {
    bytes secret;
    std::string label;
    uint32_t generation;
    uint16_t length;
    bytes out;

    DeriveTreeSecret() = default;
    DeriveTreeSecret(mls::CipherSuite suite, PseudoRandom::Generator&& prg);
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
    SignWithLabel(mls::CipherSuite suite, PseudoRandom::Generator&& prg);
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
    EncryptWithLabel(mls::CipherSuite suite, PseudoRandom::Generator&& prg);
    std::optional<std::string> verify(mls::CipherSuite suite) const;
  };

  mls::CipherSuite cipher_suite;

  RefHash ref_hash;
  ExpandWithLabel expand_with_label;
  DeriveSecret derive_secret;
  DeriveTreeSecret derive_tree_secret;
  SignWithLabel sign_with_label;
  EncryptWithLabel encrypt_with_label;

  CryptoBasicsTestVector() = default;
  CryptoBasicsTestVector(mls::CipherSuite suite);
  std::optional<std::string> verify() const;
};

struct SecretTreeTestVector : PseudoRandom
{
  struct SenderData
  {
    bytes sender_data_secret;
    bytes ciphertext;
    bytes key;
    bytes nonce;

    SenderData() = default;
    SenderData(mls::CipherSuite suite, PseudoRandom::Generator&& prg);
    std::optional<std::string> verify(mls::CipherSuite suite) const;
  };

  struct RatchetStep
  {
    uint32_t generation;
    bytes handshake_key;
    bytes handshake_nonce;
    bytes application_key;
    bytes application_nonce;
  };

  mls::CipherSuite cipher_suite;

  SenderData sender_data;

  bytes encryption_secret;
  std::vector<std::vector<RatchetStep>> leaves;

  SecretTreeTestVector() = default;
  SecretTreeTestVector(mls::CipherSuite suite,
                       uint32_t n_leaves,
                       const std::vector<uint32_t>& generations);
  std::optional<std::string> verify() const;
};

struct KeyScheduleTestVector : PseudoRandom
{
  struct Export
  {
    std::string exporter_label;
    size_t exporter_length;
    bytes exported;
  };

  struct Epoch
  {
    // Chosen by the generator
    bytes tree_hash;
    bytes commit_secret;
    bytes confirmed_transcript_hash;

    // Computed values
    bytes group_context;

    bytes joiner_secret;
    bytes welcome_secret;
    bytes init_secret;

    bytes sender_data_secret;
    bytes encryption_secret;
    bytes exporter_secret;
    bytes epoch_authenticator;
    bytes external_secret;
    bytes confirmation_key;
    bytes membership_key;
    bytes resumption_psk;

    mls::HPKEPublicKey external_pub;
    Export exporter;
  };

  mls::CipherSuite cipher_suite;

  bytes group_id;
  bytes initial_init_secret;

  std::vector<Epoch> epochs;

  KeyScheduleTestVector() = default;
  KeyScheduleTestVector(mls::CipherSuite suite, uint32_t n_epochs);
  std::optional<std::string> verify() const;
};

struct MessageProtectionTestVector : PseudoRandom
{
  mls::CipherSuite cipher_suite;

  bytes group_id;
  mls::epoch_t epoch;
  bytes tree_hash;
  bytes confirmed_transcript_hash;

  mls::SignaturePrivateKey signature_priv;
  mls::SignaturePublicKey signature_pub;

  bytes encryption_secret;
  bytes sender_data_secret;
  bytes membership_key;

  mls::Proposal proposal;
  mls::MLSMessage proposal_pub;
  mls::MLSMessage proposal_priv;

  mls::Commit commit;
  mls::MLSMessage commit_pub;
  mls::MLSMessage commit_priv;

  bytes application;
  mls::MLSMessage application_priv;

  MessageProtectionTestVector() = default;
  MessageProtectionTestVector(mls::CipherSuite suite);
  std::optional<std::string> verify();

private:
  mls::GroupKeySource group_keys() const;
  mls::GroupContext group_context() const;

  mls::MLSMessage protect_pub(
    const mls::GroupContent::RawContent& raw_content) const;
  mls::MLSMessage protect_priv(
    const mls::GroupContent::RawContent& raw_content);
  std::optional<mls::GroupContent> unprotect(const mls::MLSMessage& message);
};

struct PSKSecretTestVector : PseudoRandom
{
  struct PSK
  {
    bytes psk_id;
    bytes psk_nonce;
    bytes psk;
  };

  mls::CipherSuite cipher_suite;
  std::vector<PSK> psks;
  bytes psk_secret;

  PSKSecretTestVector() = default;
  PSKSecretTestVector(mls::CipherSuite suite, size_t n_psks);
  std::optional<std::string> verify() const;
};

struct TranscriptTestVector : PseudoRandom
{
  mls::CipherSuite cipher_suite;

  bytes group_id;
  mls::epoch_t epoch;
  bytes tree_hash_before;
  bytes confirmed_transcript_hash_before;
  bytes interim_transcript_hash_before;

  bytes confirmation_key;

  mls::SignaturePublicKey signature_key;
  mls::AuthenticatedContent commit;

  bytes group_context;
  bytes confirmed_transcript_hash_after;
  bytes interim_transcript_hash_after;

  TranscriptTestVector() = default;
  TranscriptTestVector(mls::CipherSuite suite);
  std::optional<std::string> verify() const;
};

struct WelcomeTestVector : PseudoRandom
{
  mls::CipherSuite cipher_suite;

  mls::HPKEPrivateKey init_priv;
  mls::SignaturePublicKey signer_pub;

  mls::MLSMessage key_package;
  mls::MLSMessage welcome;

  WelcomeTestVector() = default;
  WelcomeTestVector(mls::CipherSuite suite);
  std::optional<std::string> verify() const;
};

struct TreeKEMTestVector : PseudoRandom
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

  TreeKEMTestVector() = default;
  TreeKEMTestVector(mls::CipherSuite suite, size_t n_leaves);
  std::optional<std::string> verify() const;

  void initialize_trees();
  std::tuple<bytes, mls::SignaturePrivateKey, mls::LeafNode> new_leaf_node(
    const std::string& label) const;
};

struct MessagesTestVector : PseudoRandom
{
  bytes mls_welcome;
  bytes mls_group_info;
  bytes mls_key_package;

  bytes ratchet_tree;
  bytes group_secrets;

  bytes add_proposal;
  bytes update_proposal;
  bytes remove_proposal;
  bytes pre_shared_key_proposal;
  bytes re_init_proposal;
  bytes external_init_proposal;
  bytes group_context_extensions_proposal;

  bytes commit;

  bytes public_message_proposal;
  bytes public_message_commit;
  bytes private_message;

  MessagesTestVector();
  std::optional<std::string> verify() const;
};

} // namespace mls_vectors
