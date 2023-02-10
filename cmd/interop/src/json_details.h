#pragma once

#include <mls_vectors/mls_vectors.h>
#include <nlohmann/json.hpp>

using nlohmann::json;

///
/// Serializers for foreign types
///

namespace nlohmann {

// bytes
void
to_json(json& j, const bytes& v);
void
from_json(const json& j, bytes& v);

// std::optional<T>
template<typename T>
struct adl_serializer<std::optional<T>>
{
  static void to_json(json& j, const std::optional<T>& v)
  {
    if (!v) {
      j = nullptr;
      return;
    }

    j = opt::get(v);
  }

  static void from_json(const json& j, std::optional<T>& v)
  {
    if (j.is_null()) {
      v = std::nullopt;
      return;
    }

    v = j.get<T>();
  }
};

// LeafCount, NodeCount, etc.
// XXX(RLB): For some reason, just defining this for mls::Uint32 didn't work.
template<typename T>
struct uint_serializer
{
  static void to_json(json& j, const T& v) { j = v.val; }
  static void from_json(const json& j, T& v) { j.get_to(v.val); }
};

#define UINT_SERIALIZER(T)                                                     \
  template<>                                                                   \
  struct adl_serializer<T> : uint_serializer<T>                                \
  {                                                                            \
  };

UINT_SERIALIZER(mls::LeafCount)
UINT_SERIALIZER(mls::NodeCount)
UINT_SERIALIZER(mls::LeafIndex)
UINT_SERIALIZER(mls::NodeIndex)

// mls::Ciphersuite
template<>
struct adl_serializer<mls::CipherSuite>
{
  static void to_json(json& j, const mls::CipherSuite& v)
  {
    j = v.cipher_suite();
  }

  static void from_json(const json& j, mls::CipherSuite& v)
  {
    v = mls::CipherSuite(j.get<mls::CipherSuite::ID>());
  }
};

// Public keys and private keys serialize directly as the content of their
// `data` member, without a length prefix.
template<typename T>
struct asymmetric_key_serializer
{
  static void to_json(json& j, const T& v) { j = bytes{ v.data }; }

  static void from_json(const json& j, T& v)
  {
    v = T();
    v.data = j.get<bytes>();
  }
};

#define ASYMM_KEY_SERIALIZER(T)                                                \
  template<>                                                                   \
  struct adl_serializer<T> : asymmetric_key_serializer<T>                      \
  {                                                                            \
  };

ASYMM_KEY_SERIALIZER(mls::HPKEPublicKey)
ASYMM_KEY_SERIALIZER(mls::HPKEPrivateKey)
ASYMM_KEY_SERIALIZER(mls::SignaturePublicKey)
ASYMM_KEY_SERIALIZER(mls::SignaturePrivateKey)

// Other TLS-serializable things
template<typename T>
struct tls_serializer
{
  static void to_json(json& j, const T& v) { j = bytes(tls::marshal(v)); }

  static void from_json(const json& j, T& v)
  {
    v = tls::get<T>(j.get<bytes>());
  }
};

#define TLS_SERIALIZER(T)                                                      \
  template<>                                                                   \
  struct adl_serializer<T> : tls_serializer<T>                                 \
  {                                                                            \
  };

TLS_SERIALIZER(mls::TreeKEMPublicKey)
TLS_SERIALIZER(mls::AuthenticatedContent)
TLS_SERIALIZER(mls::Credential)
TLS_SERIALIZER(mls::Proposal)
TLS_SERIALIZER(mls::Commit)
TLS_SERIALIZER(mls::ApplicationData)
TLS_SERIALIZER(mls::MLSMessage)
TLS_SERIALIZER(mls::LeafNode)
TLS_SERIALIZER(mls::UpdatePath)
TLS_SERIALIZER(mls::KeyPackage)

} // namespace nlohmann

///
/// Test Vector Serializers
///
namespace mls_vectors {

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(TreeMathTestVector,
                                   n_leaves,
                                   n_nodes,
                                   root,
                                   left,
                                   right,
                                   parent,
                                   sibling)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(CryptoBasicsTestVector::RefHash,
                                   label,
                                   value,
                                   out)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(CryptoBasicsTestVector::ExpandWithLabel,
                                   secret,
                                   label,
                                   context,
                                   length,
                                   out)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(CryptoBasicsTestVector::DeriveSecret,
                                   secret,
                                   label,
                                   out)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(CryptoBasicsTestVector::DeriveTreeSecret,
                                   secret,
                                   label,
                                   generation,
                                   length,
                                   out)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(CryptoBasicsTestVector::SignWithLabel,
                                   priv,
                                   pub,
                                   content,
                                   label,
                                   signature)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(CryptoBasicsTestVector::EncryptWithLabel,
                                   priv,
                                   pub,
                                   label,
                                   context,
                                   plaintext,
                                   kem_output,
                                   ciphertext)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(CryptoBasicsTestVector,
                                   cipher_suite,
                                   ref_hash,
                                   expand_with_label,
                                   derive_secret,
                                   derive_tree_secret,
                                   sign_with_label,
                                   encrypt_with_label)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(SecretTreeTestVector::SenderData,
                                   sender_data_secret,
                                   ciphertext,
                                   key,
                                   nonce)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(SecretTreeTestVector::RatchetStep,
                                   generation,
                                   handshake_key,
                                   handshake_nonce,
                                   application_key,
                                   application_nonce)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(SecretTreeTestVector,
                                   cipher_suite,
                                   encryption_secret,
                                   sender_data,
                                   leaves)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(KeyScheduleTestVector::ExternalPSKInfo,
                                   id,
                                   nonce,
                                   secret)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(KeyScheduleTestVector::Epoch,
                                   tree_hash,
                                   commit_secret,
                                   confirmed_transcript_hash,
                                   external_psks,
                                   psk_nonce,
                                   psk_secret,
                                   group_context,
                                   joiner_secret,
                                   welcome_secret,
                                   init_secret,
                                   sender_data_secret,
                                   encryption_secret,
                                   exporter_secret,
                                   authentication_secret,
                                   external_secret,
                                   confirmation_key,
                                   membership_key,
                                   resumption_secret,
                                   external_pub)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(KeyScheduleTestVector,
                                   cipher_suite,
                                   group_id,
                                   initial_init_secret,
                                   epochs)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(MessageProtectionTestVector,
                                   cipher_suite,
                                   group_id,
                                   epoch,
                                   tree_hash,
                                   confirmed_transcript_hash,
                                   signature_priv,
                                   signature_pub,
                                   encryption_secret,
                                   sender_data_secret,
                                   membership_key,
                                   proposal,
                                   proposal_pub,
                                   proposal_priv,
                                   commit,
                                   commit_pub,
                                   commit_priv,
                                   application,
                                   application_priv)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(TranscriptTestVector,
                                   cipher_suite,
                                   group_id,
                                   epoch,
                                   tree_hash_before,
                                   confirmed_transcript_hash_before,
                                   interim_transcript_hash_before,
                                   confirmation_key,
                                   signature_key,
                                   commit,
                                   group_context,
                                   confirmed_transcript_hash_after,
                                   interim_transcript_hash_after)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(TreeKEMTestVector,
                                   cipher_suite,
                                   group_id,
                                   ratchet_tree_before,
                                   add_sender,
                                   my_leaf_secret,
                                   my_leaf_node,
                                   my_path_secret,
                                   update_sender,
                                   update_path,
                                   update_group_context,
                                   tree_hash_before,
                                   root_secret_after_add,
                                   root_secret_after_update,
                                   ratchet_tree_after,
                                   tree_hash_after)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(MessagesTestVector,
                                   key_package,
                                   ratchet_tree,
                                   group_info,
                                   group_secrets,
                                   welcome,
                                   add_proposal,
                                   update_proposal,
                                   remove_proposal,
                                   pre_shared_key_proposal,
                                   reinit_proposal,
                                   external_init_proposal,
                                   commit,
                                   content_auth_app,
                                   content_auth_proposal,
                                   content_auth_commit,
                                   mls_plaintext,
                                   mls_ciphertext)

} // namespace mls_vectors
