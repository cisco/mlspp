#pragma once

#include <mls/messages.h>
#include <tls/tls_syntax.h>

using namespace mls;

struct TreeMathTestVector
{
  uint32_t n_leaves;
  std::vector<NodeIndex> root;
  std::vector<NodeIndex> left;
  std::vector<NodeIndex> right;
  std::vector<NodeIndex> parent;
  std::vector<NodeIndex> sibling;

  TLS_SERIALIZABLE(n_leaves, root, left, right, parent, sibling)
  TLS_TRAITS(tls::pass,
             tls::vector<4>,
             tls::vector<4>,
             tls::vector<4>,
             tls::vector<4>,
             tls::vector<4>)

  static TreeMathTestVector create(uint32_t n_leaves);
  static std::optional<std::string> verify(const TreeMathTestVector& tv);
};

struct CryptoValue
{
  bytes data;
  TLS_SERIALIZABLE(data)
  TLS_TRAITS(tls::vector<1>)
};

struct HashRatchetTestVector
{
  struct KeyAndNonce
  {
    CryptoValue key;
    CryptoValue nonce;
    TLS_SERIALIZABLE(key, nonce);
  };

  struct HashRatchetSequence
  {
    std::vector<KeyAndNonce> steps;
    TLS_SERIALIZABLE(steps)
    TLS_TRAITS(tls::vector<4>)
  };

  CryptoValue base_secret;
  std::vector<HashRatchetSequence> chains;

  TLS_SERIALIZABLE(base_secret, chains)
  TLS_TRAITS(tls::pass, tls::vector<4>)

  static HashRatchetTestVector create(CipherSuite suite,
                                      uint32_t n_leaves,
                                      uint32_t n_generations);
  static std::optional<std::string> verify(const HashRatchetTestVector& tv);
};

struct SecretTreeTestVector
{
  CryptoValue base_secret;
  std::vector<CryptoValue> tree_node_secrets;

  TLS_SERIALIZABLE(base_secret, tree_node_secrets)
  TLS_TRAITS(tls::pass, tls::vector<4>)

  static SecretTreeTestVector create(CipherSuite suite, uint32_t n_leaves);
  static std::optional<std::string> verify(const SecretTreeTestVector& tv);
};

struct KeyScheduleTestVector
{
  struct Epoch
  {
    CryptoValue tree_hash;
    MLSPlaintext commit;

    CryptoValue confirmed_transcript_hash;
    CryptoValue interim_transcript_hash;
    CryptoValue group_context;

    CryptoValue commit_secret;
    CryptoValue psk_secret;

    CryptoValue joiner_secret;
    CryptoValue welcome_secret;
    CryptoValue epoch_secret;
    CryptoValue init_secret;

    CryptoValue sender_data_secret;
    CryptoValue encryption_secret;
    CryptoValue exporter_secret;
    CryptoValue authentication_secret;
    CryptoValue external_secret;
    CryptoValue confirmation_key;
    CryptoValue membership_key;
    CryptoValue resumption_secret;

    HPKEPublicKey external_pub;

    TLS_SERIALIZABLE(tree_hash,
                     commit,
                     confirmed_transcript_hash,
                     interim_transcript_hash,
                     group_context,
                     commit_secret,
                     psk_secret,
                     joiner_secret,
                     welcome_secret,
                     epoch_secret,
                     init_secret,
                     sender_data_secret,
                     encryption_secret,
                     exporter_secret,
                     authentication_secret,
                     external_secret,
                     confirmation_key,
                     membership_key,
                     resumption_secret)
  };

  CryptoValue group_id;
  CryptoValue base_init_secret;
  std::vector<Epoch> epochs;

  TLS_SERIALIZABLE(group_id, base_init_secret, epochs)
  TLS_TRAITS(tls::pass, tls::pass, tls::vector<4>)

  static KeyScheduleTestVector create(CipherSuite suite, uint32_t n_epochs);
  static std::optional<std::string> verify(const KeyScheduleTestVector& tv);
};

struct TreeHashingTestVector
{
  CryptoValue tree_hash;
  TreeKEMPublicKey ratchet_tree;

  TLS_SERIALIZABLE(tree_hash, ratchet_tree)

  static TreeHashingTestVector create(CipherSuite suite, uint32_t n_leaves);
  static std::optional<std::string> verify(const TreeHashingTestVector& tv);
};

struct MessagesTestVector
{
  struct Message
  {
    bytes data;
    TLS_SERIALIZABLE(data)
    TLS_TRAITS(tls::vector<4>)
  };

  Message key_package;
  Message capabilities;
  Message ratchet_tree;

  Message group_info;
  Message group_secrets;
  Message welcome;

  Message public_group_state;

  Message add_proposal;
  Message update_proposal;
  Message remove_proposal;
  Message pre_shared_key_proposal;
  Message re_init_proposal;
  Message external_init_proposal;
  Message app_ack_proposal;

  Message commit;

  Message mls_ciphertext;

  TLS_SERIALIZABLE(key_package,
                   capabilities,
                   ratchet_tree,
                   group_info,
                   group_secrets,
                   welcome,
                   public_group_state,
                   add_proposal,
                   update_proposal,
                   remove_proposal,
                   pre_shared_key_proposal,
                   re_init_proposal,
                   external_init_proposal,
                   app_ack_proposal,
                   commit,
                   mls_ciphertext)

  static MessagesTestVector create();
  static std::optional<std::string> verify(const MessagesTestVector& tv);
};
