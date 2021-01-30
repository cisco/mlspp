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

template<>
struct adl_serializer<mls::LeafCount> : uint_serializer<mls::LeafCount>
{};

template<>
struct adl_serializer<mls::NodeCount> : uint_serializer<mls::NodeCount>
{};

template<>
struct adl_serializer<mls::NodeIndex> : uint_serializer<mls::NodeIndex>
{};

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

} // namespace mls_vectors
