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
TLS_SERIALIZER(mls::Welcome)

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

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(KeyScheduleTestVector::Export,
                                   label,
                                   context,
                                   length,
                                   secret)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(KeyScheduleTestVector::Epoch,
                                   tree_hash,
                                   commit_secret,
                                   psk_secret,
                                   confirmed_transcript_hash,
                                   group_context,
                                   joiner_secret,
                                   welcome_secret,
                                   init_secret,
                                   sender_data_secret,
                                   encryption_secret,
                                   exporter_secret,
                                   epoch_authenticator,
                                   external_secret,
                                   confirmation_key,
                                   membership_key,
                                   resumption_psk,
                                   external_pub,
                                   exporter)
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

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(PSKSecretTestVector::PSK,
                                   psk_id,
                                   psk_nonce,
                                   psk)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(PSKSecretTestVector,
                                   cipher_suite,
                                   psks,
                                   psk_secret)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(TreeHashTestVector,
                                   cipher_suite,
                                   group_id,
                                   tree,
                                   tree_hashes,
                                   resolutions)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(TranscriptTestVector,
                                   cipher_suite,
                                   interim_transcript_hash_before,
                                   confirmation_key,
                                   authenticated_content,
                                   confirmed_transcript_hash_after,
                                   interim_transcript_hash_after)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(WelcomeTestVector,
                                   cipher_suite,
                                   init_priv,
                                   signer_pub,
                                   key_package,
                                   welcome)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(TreeOperationsTestVector,
                                   cipher_suite,
                                   tree_before,
                                   tree_hash_before,
                                   proposal,
                                   proposal_sender,
                                   tree_after,
                                   tree_hash_after)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(TreeKEMTestVector::PathSecret,
                                   node,
                                   path_secret)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(TreeKEMTestVector::LeafPrivateInfo,
                                   index,
                                   encryption_priv,
                                   signature_priv,
                                   path_secrets)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(TreeKEMTestVector::UpdatePathInfo,
                                   sender,
                                   update_path,
                                   path_secrets,
                                   commit_secret,
                                   tree_hash_after)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(TreeKEMTestVector,
                                   cipher_suite,
                                   group_id,
                                   epoch,
                                   confirmed_transcript_hash,
                                   ratchet_tree,
                                   leaves_private,
                                   update_paths)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(MessagesTestVector,
                                   mls_welcome,
                                   mls_group_info,
                                   mls_key_package,
                                   ratchet_tree,
                                   group_secrets,
                                   add_proposal,
                                   update_proposal,
                                   remove_proposal,
                                   pre_shared_key_proposal,
                                   re_init_proposal,
                                   external_init_proposal,
                                   group_context_extensions_proposal,
                                   commit,
                                   public_message_proposal,
                                   public_message_commit,
                                   private_message)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(PassiveClientTestVector::PSK, psk_id, psk)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(PassiveClientTestVector::Epoch,
                                   proposals,
                                   commit,
                                   epoch_authenticator)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(PassiveClientTestVector,
                                   cipher_suite,
                                   key_package,
                                   signature_priv,
                                   encryption_priv,
                                   init_priv,
                                   external_psks,
                                   welcome,
                                   ratchet_tree,
                                   initial_epoch_authenticator,
                                   epochs)

} // namespace mls_vectors
