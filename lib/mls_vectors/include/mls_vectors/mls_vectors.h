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
    Generator(MLS_NAMESPACE::CipherSuite suite_in, const std::string& label);
    Generator sub(const std::string& label) const;

    bytes secret(const std::string& label) const;
    bytes generate(const std::string& label, size_t size) const;

    uint16_t uint16(const std::string& label) const;
    uint32_t uint32(const std::string& label) const;
    uint64_t uint64(const std::string& label) const;

    MLS_NAMESPACE::SignaturePrivateKey signature_key(
      const std::string& label) const;
    MLS_NAMESPACE::HPKEPrivateKey hpke_key(const std::string& label) const;

    size_t output_length() const;

  private:
    MLS_NAMESPACE::CipherSuite suite;
    bytes seed;

    Generator(MLS_NAMESPACE::CipherSuite suite_in, bytes seed_in);
  };

  PseudoRandom() = default;
  PseudoRandom(MLS_NAMESPACE::CipherSuite suite, const std::string& label);

  Generator prg;
};

struct TreeMathTestVector
{
  using OptionalNode = std::optional<MLS_NAMESPACE::NodeIndex>;

  MLS_NAMESPACE::LeafCount n_leaves;
  MLS_NAMESPACE::NodeCount n_nodes;
  MLS_NAMESPACE::NodeIndex root;
  std::vector<OptionalNode> left;
  std::vector<OptionalNode> right;
  std::vector<OptionalNode> parent;
  std::vector<OptionalNode> sibling;

  std::optional<MLS_NAMESPACE::NodeIndex> null_if_invalid(
    MLS_NAMESPACE::NodeIndex input,
    MLS_NAMESPACE::NodeIndex answer) const;

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
    RefHash(MLS_NAMESPACE::CipherSuite suite,
            const PseudoRandom::Generator& prg);
    std::optional<std::string> verify(MLS_NAMESPACE::CipherSuite suite) const;
  };

  struct ExpandWithLabel
  {
    bytes secret;
    std::string label;
    bytes context;
    uint16_t length;
    bytes out;

    ExpandWithLabel() = default;
    ExpandWithLabel(MLS_NAMESPACE::CipherSuite suite,
                    const PseudoRandom::Generator& prg);
    std::optional<std::string> verify(MLS_NAMESPACE::CipherSuite suite) const;
  };

  struct DeriveSecret
  {
    bytes secret;
    std::string label;
    bytes out;

    DeriveSecret() = default;
    DeriveSecret(MLS_NAMESPACE::CipherSuite suite,
                 const PseudoRandom::Generator& prg);
    std::optional<std::string> verify(MLS_NAMESPACE::CipherSuite suite) const;
  };

  struct DeriveTreeSecret
  {
    bytes secret;
    std::string label;
    uint32_t generation;
    uint16_t length;
    bytes out;

    DeriveTreeSecret() = default;
    DeriveTreeSecret(MLS_NAMESPACE::CipherSuite suite,
                     const PseudoRandom::Generator& prg);
    std::optional<std::string> verify(MLS_NAMESPACE::CipherSuite suite) const;
  };

  struct SignWithLabel
  {
    MLS_NAMESPACE::SignaturePrivateKey priv;
    MLS_NAMESPACE::SignaturePublicKey pub;
    bytes content;
    std::string label;
    bytes signature;

    SignWithLabel() = default;
    SignWithLabel(MLS_NAMESPACE::CipherSuite suite,
                  const PseudoRandom::Generator& prg);
    std::optional<std::string> verify(MLS_NAMESPACE::CipherSuite suite) const;
  };

  struct EncryptWithLabel
  {
    MLS_NAMESPACE::HPKEPrivateKey priv;
    MLS_NAMESPACE::HPKEPublicKey pub;
    std::string label;
    bytes context;
    bytes plaintext;
    bytes kem_output;
    bytes ciphertext;

    EncryptWithLabel() = default;
    EncryptWithLabel(MLS_NAMESPACE::CipherSuite suite,
                     const PseudoRandom::Generator& prg);
    std::optional<std::string> verify(MLS_NAMESPACE::CipherSuite suite) const;
  };

  MLS_NAMESPACE::CipherSuite cipher_suite;

  RefHash ref_hash;
  ExpandWithLabel expand_with_label;
  DeriveSecret derive_secret;
  DeriveTreeSecret derive_tree_secret;
  SignWithLabel sign_with_label;
  EncryptWithLabel encrypt_with_label;

  CryptoBasicsTestVector() = default;
  CryptoBasicsTestVector(MLS_NAMESPACE::CipherSuite suite);
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
    SenderData(MLS_NAMESPACE::CipherSuite suite,
               const PseudoRandom::Generator& prg);
    std::optional<std::string> verify(MLS_NAMESPACE::CipherSuite suite) const;
  };

  struct RatchetStep
  {
    uint32_t generation;
    bytes handshake_key;
    bytes handshake_nonce;
    bytes application_key;
    bytes application_nonce;
  };

  MLS_NAMESPACE::CipherSuite cipher_suite;

  SenderData sender_data;

  bytes encryption_secret;
  std::vector<std::vector<RatchetStep>> leaves;

  SecretTreeTestVector() = default;
  SecretTreeTestVector(MLS_NAMESPACE::CipherSuite suite,
                       uint32_t n_leaves,
                       const std::vector<uint32_t>& generations);
  std::optional<std::string> verify() const;
};

struct KeyScheduleTestVector : PseudoRandom
{
  struct Export
  {
    std::string label;
    bytes context;
    size_t length;
    bytes secret;
  };

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
    bytes epoch_authenticator;
    bytes external_secret;
    bytes confirmation_key;
    bytes membership_key;
    bytes resumption_psk;

    MLS_NAMESPACE::HPKEPublicKey external_pub;
    Export exporter;
  };

  MLS_NAMESPACE::CipherSuite cipher_suite;

  bytes group_id;
  bytes initial_init_secret;

  std::vector<Epoch> epochs;

  KeyScheduleTestVector() = default;
  KeyScheduleTestVector(MLS_NAMESPACE::CipherSuite suite, uint32_t n_epochs);
  std::optional<std::string> verify() const;
};

struct MessageProtectionTestVector : PseudoRandom
{
  MLS_NAMESPACE::CipherSuite cipher_suite;

  bytes group_id;
  MLS_NAMESPACE::epoch_t epoch;
  bytes tree_hash;
  bytes confirmed_transcript_hash;

  MLS_NAMESPACE::SignaturePrivateKey signature_priv;
  MLS_NAMESPACE::SignaturePublicKey signature_pub;

  bytes encryption_secret;
  bytes sender_data_secret;
  bytes membership_key;

  MLS_NAMESPACE::Proposal proposal;
  MLS_NAMESPACE::MLSMessage proposal_pub;
  MLS_NAMESPACE::MLSMessage proposal_priv;

  MLS_NAMESPACE::Commit commit;
  MLS_NAMESPACE::MLSMessage commit_pub;
  MLS_NAMESPACE::MLSMessage commit_priv;

  bytes application;
  MLS_NAMESPACE::MLSMessage application_priv;

  MessageProtectionTestVector() = default;
  MessageProtectionTestVector(MLS_NAMESPACE::CipherSuite suite);
  std::optional<std::string> verify();

private:
  MLS_NAMESPACE::GroupKeySource group_keys() const;
  MLS_NAMESPACE::GroupContext group_context() const;

  MLS_NAMESPACE::MLSMessage protect_pub(
    const MLS_NAMESPACE::GroupContent::RawContent& raw_content) const;
  MLS_NAMESPACE::MLSMessage protect_priv(
    const MLS_NAMESPACE::GroupContent::RawContent& raw_content);
  std::optional<MLS_NAMESPACE::GroupContent> unprotect(
    const MLS_NAMESPACE::MLSMessage& message);
};

struct PSKSecretTestVector : PseudoRandom
{
  struct PSK
  {
    bytes psk_id;
    bytes psk_nonce;
    bytes psk;
  };

  MLS_NAMESPACE::CipherSuite cipher_suite;
  std::vector<PSK> psks;
  bytes psk_secret;

  PSKSecretTestVector() = default;
  PSKSecretTestVector(MLS_NAMESPACE::CipherSuite suite, size_t n_psks);
  std::optional<std::string> verify() const;
};

struct TranscriptTestVector : PseudoRandom
{
  MLS_NAMESPACE::CipherSuite cipher_suite;

  bytes confirmation_key;
  bytes interim_transcript_hash_before;

  MLS_NAMESPACE::AuthenticatedContent authenticated_content;

  bytes confirmed_transcript_hash_after;
  bytes interim_transcript_hash_after;

  TranscriptTestVector() = default;
  TranscriptTestVector(MLS_NAMESPACE::CipherSuite suite);
  std::optional<std::string> verify() const;
};

struct WelcomeTestVector : PseudoRandom
{
  MLS_NAMESPACE::CipherSuite cipher_suite;

  MLS_NAMESPACE::HPKEPrivateKey init_priv;
  MLS_NAMESPACE::SignaturePublicKey signer_pub;

  MLS_NAMESPACE::MLSMessage key_package;
  MLS_NAMESPACE::MLSMessage welcome;

  WelcomeTestVector() = default;
  WelcomeTestVector(MLS_NAMESPACE::CipherSuite suite);
  std::optional<std::string> verify() const;
};

// XXX(RLB): The |structure| of the example trees below is to avoid compile
// errors from gcc's -Werror=comment when there is a '\' character at the end of
// a line.  Inspired by a similar bug in Chromium:
//   https://codereview.chromium.org/874663003/patch/1/10001
enum struct TreeStructure
{
  // Full trees on N leaves, created by member k adding member k+1
  full_tree_2,
  full_tree_3,
  full_tree_4,
  full_tree_5,
  full_tree_6,
  full_tree_7,
  full_tree_8,
  full_tree_32,
  full_tree_33,
  full_tree_34,

  // |               W               |
  // |         ______|______         |
  // |        /             \        |
  // |       U               Y       |
  // |     __|__           __|__     |
  // |    /     \         /     \    |
  // |   T       _       X       Z   |
  // |  / \     / \     / \     / \  |
  // | A   B   C   _   E   F   G   H |
  //
  // * Start with full tree on 8 members
  // * 0 commits removeing 2 and 3, and adding a new member
  internal_blanks_no_skipping,

  // |               W               |
  // |         ______|______         |
  // |        /             \        |
  // |       _               Y       |
  // |     __|__           __|__     |
  // |    /     \         /     \    |
  // |   _       _       X       Z   |
  // |  / \     / \     / \     / \  |
  // | A   _   _   _   E   F   G   H |
  //
  // * Start with full tree on 8 members
  // * 0 commitsremoveing 1, 2, and 3
  internal_blanks_with_skipping,

  // |               W[H]            |
  // |         ______|______         |
  // |        /             \        |
  // |       U               Y[H]    |
  // |     __|__           __|__     |
  // |    /     \         /     \    |
  // |   T       V       X       _   |
  // |  / \     / \     / \     / \  |
  // | A   B   C   D   E   F   G   H |
  //
  // * Start with full tree on 7 members
  // * 0 commits adding a member in a partial Commit (no path)
  unmerged_leaves_no_skipping,

  // |               W [F]           |
  // |         ______|______         |
  // |        /             \        |
  // |       U               Y [F]   |
  // |     __|__           __|__     |
  // |    /     \         /     \    |
  // |   T       _       _       _   |
  // |  / \     / \     / \     / \  |
  // | A   B   C   D   E   F   G   _ |
  //
  // == Fig. 20 / {{parent-hash-tree}}
  // * 0 creates group
  // * 0 adds 1, ..., 6 in a partial Commit
  // * O commits removing 5
  // * 4 commits without any proposals
  // * 0 commits adding a new member in a partial Commit
  unmerged_leaves_with_skipping,
};

extern std::array<TreeStructure, 14> all_tree_structures;
extern std::array<TreeStructure, 11> treekem_test_tree_structures;

struct TreeHashTestVector : PseudoRandom
{
  MLS_NAMESPACE::CipherSuite cipher_suite;
  bytes group_id;

  MLS_NAMESPACE::TreeKEMPublicKey tree;
  std::vector<bytes> tree_hashes;
  std::vector<std::vector<MLS_NAMESPACE::NodeIndex>> resolutions;

  TreeHashTestVector() = default;
  TreeHashTestVector(MLS_NAMESPACE::CipherSuite suite,
                     TreeStructure tree_structure);
  std::optional<std::string> verify();
};

struct TreeOperationsTestVector : PseudoRandom
{
  enum struct Scenario
  {
    add_right_edge,
    add_internal,
    update,
    remove_right_edge,
    remove_internal,
  };

  static const std::vector<Scenario> all_scenarios;

  MLS_NAMESPACE::CipherSuite cipher_suite;

  MLS_NAMESPACE::TreeKEMPublicKey tree_before;
  bytes tree_hash_before;

  MLS_NAMESPACE::Proposal proposal;
  MLS_NAMESPACE::LeafIndex proposal_sender;

  MLS_NAMESPACE::TreeKEMPublicKey tree_after;
  bytes tree_hash_after;

  TreeOperationsTestVector() = default;
  TreeOperationsTestVector(MLS_NAMESPACE::CipherSuite suite, Scenario scenario);
  std::optional<std::string> verify();
};

struct TreeKEMTestVector : PseudoRandom
{
  struct PathSecret
  {
    MLS_NAMESPACE::NodeIndex node;
    bytes path_secret;
  };

  struct LeafPrivateInfo
  {
    MLS_NAMESPACE::LeafIndex index;
    MLS_NAMESPACE::HPKEPrivateKey encryption_priv;
    MLS_NAMESPACE::SignaturePrivateKey signature_priv;
    std::vector<PathSecret> path_secrets;
  };

  struct UpdatePathInfo
  {
    MLS_NAMESPACE::LeafIndex sender;
    MLS_NAMESPACE::UpdatePath update_path;
    std::vector<std::optional<bytes>> path_secrets;
    bytes commit_secret;
    bytes tree_hash_after;
  };

  MLS_NAMESPACE::CipherSuite cipher_suite;

  bytes group_id;
  MLS_NAMESPACE::epoch_t epoch;
  bytes confirmed_transcript_hash;

  MLS_NAMESPACE::TreeKEMPublicKey ratchet_tree;

  std::vector<LeafPrivateInfo> leaves_private;
  std::vector<UpdatePathInfo> update_paths;

  TreeKEMTestVector() = default;
  TreeKEMTestVector(MLS_NAMESPACE::CipherSuite suite,
                    TreeStructure tree_structure);
  std::optional<std::string> verify();
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

struct PassiveClientTestVector : PseudoRandom
{
  struct PSK
  {
    bytes psk_id;
    bytes psk;
  };

  struct Epoch
  {
    std::vector<MLS_NAMESPACE::MLSMessage> proposals;
    MLS_NAMESPACE::MLSMessage commit;
    bytes epoch_authenticator;
  };

  MLS_NAMESPACE::CipherSuite cipher_suite;

  MLS_NAMESPACE::MLSMessage key_package;
  MLS_NAMESPACE::SignaturePrivateKey signature_priv;
  MLS_NAMESPACE::HPKEPrivateKey encryption_priv;
  MLS_NAMESPACE::HPKEPrivateKey init_priv;

  std::vector<PSK> external_psks;

  MLS_NAMESPACE::MLSMessage welcome;
  std::optional<MLS_NAMESPACE::TreeKEMPublicKey> ratchet_tree;
  bytes initial_epoch_authenticator;

  std::vector<Epoch> epochs;

  PassiveClientTestVector() = default;
  std::optional<std::string> verify();
};

} // namespace mls_vectors
