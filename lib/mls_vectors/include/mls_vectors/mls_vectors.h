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

  bytes confirmation_key;
  bytes interim_transcript_hash_before;

  mls::AuthenticatedContent authenticated_content;

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
  mls::CipherSuite cipher_suite;
  bytes group_id;

  mls::TreeKEMPublicKey tree;
  std::vector<bytes> tree_hashes;
  std::vector<std::vector<mls::NodeIndex>> resolutions;

  TreeHashTestVector() = default;
  TreeHashTestVector(mls::CipherSuite suite, TreeStructure tree_structure);
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

  mls::CipherSuite cipher_suite;

  mls::TreeKEMPublicKey tree_before;
  bytes tree_hash_before;

  mls::Proposal proposal;
  mls::LeafIndex proposal_sender;

  mls::TreeKEMPublicKey tree_after;
  bytes tree_hash_after;

  TreeOperationsTestVector() = default;
  TreeOperationsTestVector(mls::CipherSuite suite, Scenario scenario);
  std::optional<std::string> verify();
};

struct TreeKEMTestVector : PseudoRandom
{
  struct PathSecret
  {
    mls::NodeIndex node;
    bytes path_secret;
  };

  struct LeafPrivateInfo
  {
    mls::LeafIndex index;
    mls::HPKEPrivateKey encryption_priv;
    mls::SignaturePrivateKey signature_priv;
    std::vector<PathSecret> path_secrets;
  };

  struct UpdatePathInfo
  {
    mls::LeafIndex sender;
    mls::UpdatePath update_path;
    std::vector<std::optional<bytes>> path_secrets;
    bytes commit_secret;
    bytes tree_hash_after;
  };

  mls::CipherSuite cipher_suite;

  bytes group_id;
  mls::epoch_t epoch;
  bytes confirmed_transcript_hash;

  mls::TreeKEMPublicKey ratchet_tree;

  std::vector<LeafPrivateInfo> leaves_private;
  std::vector<UpdatePathInfo> update_paths;

  TreeKEMTestVector() = default;
  TreeKEMTestVector(mls::CipherSuite suite, TreeStructure tree_structure);
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
    std::vector<mls::MLSMessage> proposals;
    mls::MLSMessage commit;
    bytes epoch_authenticator;
  };

  mls::CipherSuite cipher_suite;

  mls::MLSMessage key_package;
  mls::SignaturePrivateKey signature_priv;
  mls::HPKEPrivateKey encryption_priv;
  mls::HPKEPrivateKey init_priv;

  std::vector<PSK> external_psks;

  mls::MLSMessage welcome;
  std::optional<mls::TreeKEMPublicKey> ratchet_tree;
  bytes initial_epoch_authenticator;

  std::vector<Epoch> epochs;

  PassiveClientTestVector() = default;
  std::optional<std::string> verify();
};

} // namespace mls_vectors
