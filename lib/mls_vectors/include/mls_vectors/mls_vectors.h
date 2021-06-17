#pragma once

#include <bytes/bytes.h>
#include <mls/crypto.h>
#include <mls/messages.h>
#include <mls/tree_math.h>
#include <mls/treekem.h>
#include <tls/tls_syntax.h>
#include <vector>

namespace mls_vectors {

// XXX(RLB) This construction is a little awkward, but otherwise, when we go to
// serialize as JSON, some compilers have a hard time distinguishing between
// `bytes` and `std::vector<uint8_t>` (perhaps because type aliasing rules say
// they shouldn't!).  So we need to tag these vectors explicitly by wrapping
// them in a different type.
struct HexBytes
{
  bytes data;

  HexBytes() = default;
  HexBytes(bytes data_in)
    : data(std::move(data_in))
  {}
  operator const bytes&() const { return data; }
  operator bytes&() { return data; }
};

bool
operator==(const bytes& b, const HexBytes& hb);

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
    HexBytes ciphertext;
    HexBytes key;
    HexBytes nonce;
  };

  struct RatchetStep
  {
    HexBytes key;
    HexBytes nonce;
    HexBytes plaintext;
    HexBytes ciphertext;
  };

  struct LeafInfo
  {
    uint32_t generations;
    std::vector<RatchetStep> handshake;
    std::vector<RatchetStep> application;
  };

  mls::CipherSuite cipher_suite;
  mls::LeafCount n_leaves;

  HexBytes encryption_secret;
  HexBytes sender_data_secret;
  SenderDataInfo sender_data_info;

  std::vector<LeafInfo> leaves;

  static EncryptionTestVector create(mls::CipherSuite suite,
                                     uint32_t n_leaves,
                                     uint32_t n_generations);
  std::optional<std::string> verify() const;
};

struct KeyScheduleTestVector
{
  struct Epoch
  {
    // Chosen by the generator
    HexBytes tree_hash;
    HexBytes commit_secret;
    HexBytes psk_secret;
    HexBytes confirmed_transcript_hash;

    // Computed values
    HexBytes group_context;

    HexBytes joiner_secret;
    HexBytes welcome_secret;
    HexBytes init_secret;

    HexBytes sender_data_secret;
    HexBytes encryption_secret;
    HexBytes exporter_secret;
    HexBytes authentication_secret;
    HexBytes external_secret;
    HexBytes confirmation_key;
    HexBytes membership_key;
    HexBytes resumption_secret;

    mls::HPKEPublicKey external_pub;
  };

  mls::CipherSuite cipher_suite;

  HexBytes group_id;
  HexBytes initial_init_secret;

  std::vector<Epoch> epochs;

  static KeyScheduleTestVector create(mls::CipherSuite suite,
                                      uint32_t n_epochs);
  std::optional<std::string> verify() const;
};

struct TranscriptTestVector
{
  mls::CipherSuite cipher_suite;

  HexBytes group_id;
  mls::epoch_t epoch;
  HexBytes tree_hash_before;
  HexBytes confirmed_transcript_hash_before;
  HexBytes interim_transcript_hash_before;

  HexBytes membership_key;
  HexBytes confirmation_key;
  mls::MLSPlaintext commit;

  HexBytes group_context;
  HexBytes confirmed_transcript_hash_after;
  HexBytes interim_transcript_hash_after;

  static TranscriptTestVector create(mls::CipherSuite suite);
  std::optional<std::string> verify() const;
};

struct TreeKEMTestVector
{
  mls::CipherSuite cipher_suite;

  mls::TreeKEMPublicKey ratchet_tree_before;

  mls::LeafIndex add_sender;
  HexBytes my_leaf_secret;
  mls::KeyPackage my_key_package;
  HexBytes my_path_secret;

  mls::LeafIndex update_sender;
  mls::UpdatePath update_path;
  HexBytes update_group_context;

  HexBytes tree_hash_before;
  HexBytes root_secret_after_add;
  HexBytes root_secret_after_update;
  mls::TreeKEMPublicKey ratchet_tree_after;
  HexBytes tree_hash_after;

  static TreeKEMTestVector create(mls::CipherSuite suite, size_t n_leaves);
  void initialize_trees();
  std::optional<std::string> verify() const;
};

struct MessagesTestVector
{
  HexBytes key_package;
  HexBytes capabilities;
  HexBytes lifetime;
  HexBytes ratchet_tree;

  HexBytes group_info;
  HexBytes group_secrets;
  HexBytes welcome;

  HexBytes public_group_state;

  HexBytes add_proposal;
  HexBytes update_proposal;
  HexBytes remove_proposal;
  HexBytes pre_shared_key_proposal;
  HexBytes re_init_proposal;
  HexBytes external_init_proposal;
  HexBytes app_ack_proposal;

  HexBytes commit;

  HexBytes mls_plaintext_application;
  HexBytes mls_plaintext_proposal;
  HexBytes mls_plaintext_commit;
  HexBytes mls_ciphertext;

  static MessagesTestVector create();
  std::optional<std::string> verify() const;
};

} // namespace mls_vectors
