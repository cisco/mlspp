#include <mls_vectors/mls_vectors.h>
#include <nlohmann/json.hpp>

#include <iostream>

///
/// Serializers for foreign types
///
namespace nlohmann {

// bytes
template<>
struct adl_serializer<bytes>
{
  static void to_json(json& j, const bytes& v) { j = to_hex(v); }

  static void from_json(const json& j, bytes& v)
  {
    v = from_hex(j.get<std::string>());
  }
};

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
  {};

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

// TLS-serializable things
template<typename T>
struct tls_serializer
{
  static void to_json(json& j, const T& v) { j = tls::marshal(v); }
  static void from_json(const json& j, T& v)
  {
    v = tls::get<T>(j.get<bytes>());
  }
};

#define TLS_SERIALIZER(T)                                                      \
  template<>                                                                   \
  struct adl_serializer<T> : tls_serializer<T>                                 \
  {};

TLS_SERIALIZER(mls::HPKEPublicKey)
TLS_SERIALIZER(mls::TreeKEMPublicKey)
TLS_SERIALIZER(mls::MLSPlaintext)
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

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(EncryptionTestVector::SenderDataInfo,
                                   ciphertext,
                                   key,
                                   nonce);
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(EncryptionTestVector::RatchetStep,
                                   key,
                                   nonce,
                                   plaintext,
                                   ciphertext);
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(EncryptionTestVector::LeafInfo,
                                   generations,
                                   handshake,
                                   application);
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(EncryptionTestVector,
                                   cipher_suite,
                                   n_leaves,
                                   encryption_secret,
                                   sender_data_secret,
                                   sender_data_info,
                                   leaves);

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

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(TranscriptTestVector,
                                   cipher_suite,
                                   group_id,
                                   epoch,
                                   tree_hash_before,
                                   confirmed_transcript_hash_before,
                                   interim_transcript_hash_before,
                                   membership_key,
                                   confirmation_key,
                                   commit,
                                   group_context,
                                   confirmed_transcript_hash_after,
                                   interim_transcript_hash_after)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(TreeKEMTestVector,
                                   cipher_suite,
                                   ratchet_tree_before,
                                   add_sender,
                                   my_leaf_secret,
                                   my_key_package,
                                   my_path_secret,
                                   update_sender,
                                   update_path,
                                   tree_hash_before,
                                   root_secret_after_add,
                                   root_secret_after_update,
                                   ratchet_tree_after,
                                   tree_hash_after)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(MessagesTestVector,
                                   key_package,
                                   capabilities,
                                   lifetime,
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
                                   mls_plaintext_application,
                                   mls_plaintext_proposal,
                                   mls_plaintext_commit,
                                   mls_ciphertext)

} // namespace mls_vectors
