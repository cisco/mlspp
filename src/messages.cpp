#include "messages.h"

#define DUMMY_CIPHERSUITE CipherSuite::P256_SHA256_AES128GCM

namespace mls {

// RatchetNode

RatchetNode::RatchetNode(CipherSuite suite)
  : CipherAware(suite)
  , public_key(suite)
  , node_secrets(suite)
{}

RatchetNode::RatchetNode(DHPublicKey public_key_in,
                         const std::vector<HPKECiphertext>& node_secrets_in)
  : CipherAware(public_key_in.cipher_suite())
  , public_key(std::move(public_key_in))
  , node_secrets(node_secrets_in)
{}

// DirectPath

DirectPath::DirectPath(CipherSuite suite)
  : CipherAware(suite)
  , nodes(suite)
{}

// ClientInitKey

ClientInitKey::ClientInitKey()
  : version(ProtocolVersion::mls10)
  , cipher_suite(DUMMY_CIPHERSUITE)
  , init_key(DUMMY_CIPHERSUITE)
{}

ClientInitKey::ClientInitKey(const HPKEPrivateKey& init_key_in,
                             const Credential& credential_in)
  : version(ProtocolVersion::mls10)
  , cipher_suite(init_key_in.cipher_suite())
  , init_key(init_key_in.public_key())
  , credential(credential_in)
  , _private_key(init_key_in)
{
  if (!credential.private_key().has_value()) {
    throw InvalidParameterError("Credential must have a private key");
  }

  auto tbs = to_be_signed();
  signature = credential.private_key().value().sign(tbs);
}

const std::optional<HPKEPrivateKey>&
ClientInitKey::private_key() const
{
  return _private_key;
}

bytes
ClientInitKey::hash() const
{
  auto marshaled = tls::marshal(*this);
  return Digest(cipher_suite).write(marshaled).digest();
}

bool
ClientInitKey::verify() const
{
  auto tbs = to_be_signed();
  auto identity_key = credential.public_key();
  return identity_key.verify(tbs, signature);
}

bytes
ClientInitKey::to_be_signed() const
{
  tls::ostream out;
  out << version << cipher_suite << init_key << credential;
  return out.bytes();
}

bool
operator==(const ClientInitKey& lhs, const ClientInitKey& rhs)
{
  return (lhs.version == rhs.version) &&
         (lhs.cipher_suite == rhs.cipher_suite) &&
         (lhs.init_key == rhs.init_key) && (lhs.credential == rhs.credential) &&
         (lhs.signature == rhs.signature);
}

bool
operator!=(const ClientInitKey& lhs, const ClientInitKey& rhs)
{
  return !(lhs == rhs);
}

tls::ostream&
operator<<(tls::ostream& str, const ClientInitKey& obj)
{
  return str << obj.version << obj.cipher_suite << obj.init_key
             << obj.credential << obj.signature;
}

tls::istream&
operator>>(tls::istream& str, ClientInitKey& obj)
{
  str >> obj.version >> obj.cipher_suite;
  obj.init_key = HPKEPublicKey(obj.cipher_suite);
  str >> obj.init_key >> obj.credential >> obj.signature;
  return str;
}

// GroupInfo

GroupInfo::GroupInfo(CipherSuite suite)
  : tree(suite)
{}

GroupInfo::GroupInfo(const bytes& group_id_in,
                     epoch_t epoch_in,
                     const RatchetTree tree_in,
                     const bytes& confirmed_transcript_hash_in,
                     const bytes& interim_transcript_hash_in)
  : group_id(group_id_in)
  , epoch(epoch_in)
  , tree(tree_in)
  , confirmed_transcript_hash(confirmed_transcript_hash_in)
  , interim_transcript_hash(interim_transcript_hash_in)
{}

bytes
GroupInfo::to_be_signed() const
{
  tls::ostream w;
  w << group_id << epoch << tree << confirmed_transcript_hash
    << interim_transcript_hash << signer_index;
  return w.bytes();
}

void
GroupInfo::sign(LeafIndex index, const SignaturePrivateKey& priv)
{
  auto cred = tree.get_credential(LeafIndex{ index });
  if (cred.public_key() != priv.public_key()) {
    throw InvalidParameterError("Bad key for index");
  }

  signer_index = index;
  signature = priv.sign(to_be_signed());
}

bool
GroupInfo::verify() const
{
  auto cred = tree.get_credential(LeafIndex{ signer_index });
  return cred.public_key().verify(to_be_signed(), signature);
}

// EncryptedKeyPackage

EncryptedKeyPackage::EncryptedKeyPackage(CipherSuite suite)
  : encrypted_key_package(suite)
{}

EncryptedKeyPackage::EncryptedKeyPackage(const bytes& hash,
                                         const HPKECiphertext& package)
  : client_init_key_hash(hash)
  , encrypted_key_package(package)
{}

// Welcome2

Welcome2::Welcome2(CipherSuite suite,
                   const bytes& epoch_secret,
                   const GroupInfo& group_info)
  : version(ProtocolVersion::mls10)
  , cipher_suite(suite)
  , key_packages(suite)
  , _epoch_secret(epoch_secret)
{
  auto [key, nonce] = group_info_keymat(_epoch_secret);
  auto group_info_data = tls::marshal(group_info);
  encrypted_group_info = AESGCM(key, nonce).encrypt(group_info_data);
}

std::tuple<bytes, bytes>
Welcome2::group_info_keymat(const bytes& epoch_secret) const
{
  auto secret_size = Digest(cipher_suite).output_size();
  auto key_size = AESGCM::key_size(cipher_suite);
  auto nonce_size = AESGCM::nonce_size;

  auto secret = hkdf_expand_label(
    cipher_suite, epoch_secret, "group info", {}, secret_size);
  auto key = hkdf_expand_label(cipher_suite, secret, "key", {}, key_size);
  auto nonce = hkdf_expand_label(cipher_suite, secret, "nonce", {}, nonce_size);
  return std::make_tuple(key, nonce);
}

void
Welcome2::encrypt(const ClientInitKey& cik)
{
  auto key_pkg = KeyPackage{ _epoch_secret };
  auto key_pkg_data = tls::marshal(key_pkg);
  auto enc_pkg = cik.init_key.encrypt(key_pkg_data);
  key_packages.emplace_back(cik.hash(), enc_pkg);
}

bool
operator==(const Welcome2& lhs, const Welcome2& rhs)
{
  return (lhs.version == rhs.version) &&
         (lhs.cipher_suite == rhs.cipher_suite) &&
         (lhs.key_packages == rhs.key_packages) &&
         (lhs.encrypted_group_info == rhs.encrypted_group_info);
}

tls::ostream&
operator<<(tls::ostream& str, const Welcome2& obj)
{
  return str << obj.version << obj.cipher_suite << obj.key_packages
             << obj.encrypted_group_info;
}

tls::istream&
operator>>(tls::istream& str, Welcome2& obj)
{
  str >> obj.version >> obj.cipher_suite;
  obj.key_packages.set_arg(obj.cipher_suite);
  str >> obj.key_packages >> obj.encrypted_group_info;
  return str;
}

// WelcomeInfo

WelcomeInfo::WelcomeInfo(CipherSuite suite)
  : CipherAware(suite)
  , version(ProtocolVersion::mls10)
  , epoch(0)
  , tree(suite)
{}

WelcomeInfo::WelcomeInfo(tls::opaque<2> group_id_in,
                         epoch_t epoch_in,
                         RatchetTree tree_in,
                         const tls::opaque<1>& interim_transcript_hash_in,
                         const tls::opaque<1>& init_secret_in)
  : CipherAware(tree_in.cipher_suite())
  , version(ProtocolVersion::mls10)
  , group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , tree(std::move(tree_in))
  , interim_transcript_hash(interim_transcript_hash_in)
  , init_secret(init_secret_in)
{}

bytes
WelcomeInfo::hash(CipherSuite suite) const
{
  auto marshaled = tls::marshal(*this);
  return Digest(suite).write(marshaled).digest();
}

// Welcome

Welcome::Welcome()
  : cipher_suite(DUMMY_CIPHERSUITE)
  , encrypted_welcome_info(DUMMY_CIPHERSUITE)
{}

Welcome::Welcome(const bytes& id,
                 const DHPublicKey& pub,
                 const WelcomeInfo& info)
  : client_init_key_id(id)
  , cipher_suite(pub.cipher_suite())
  , encrypted_welcome_info(pub.encrypt(tls::marshal(info)))
{}

WelcomeInfo
Welcome::decrypt(const DHPrivateKey& priv) const
{
  auto welcome_info_data = priv.decrypt(encrypted_welcome_info);
  auto welcome_info =
    tls::get<WelcomeInfo>(welcome_info_data, priv.cipher_suite());
  return welcome_info;
}

bool
operator==(const Welcome& lhs, const Welcome& rhs)
{
  return (lhs.client_init_key_id == rhs.client_init_key_id) &&
         (lhs.cipher_suite == rhs.cipher_suite) &&
         (lhs.encrypted_welcome_info == rhs.encrypted_welcome_info);
}

tls::ostream&
operator<<(tls::ostream& out, const Welcome& obj)
{
  return out << obj.client_init_key_id << obj.cipher_suite
             << obj.encrypted_welcome_info;
}

tls::istream&
operator>>(tls::istream& in, Welcome& obj)
{
  in >> obj.client_init_key_id >> obj.cipher_suite;

  obj.encrypted_welcome_info = HPKECiphertext{ obj.cipher_suite };
  in >> obj.encrypted_welcome_info;
  return in;
}

// Add

Add::Add(LeafIndex index_in,
         ClientInitKey init_key_in,
         bytes welcome_info_hash_in)
  : index(index_in)
  , init_key(std::move(init_key_in))
  , welcome_info_hash(std::move(welcome_info_hash_in))
{}

const GroupOperationType Add::type = GroupOperationType::add;

// Update

Update::Update(CipherSuite suite)
  : CipherAware(suite)
  , path(suite)
{}

Update::Update(const DirectPath& path_in)
  : CipherAware(path_in.cipher_suite())
  , path(path_in)
{}

const GroupOperationType Update::type = GroupOperationType::update;

// Remove

Remove::Remove(CipherSuite suite)
  : CipherAware(suite)
  , path(suite)
{}

Remove::Remove(LeafIndex removed_in, const DirectPath& path_in)
  : CipherAware(path_in.cipher_suite())
  , removed(removed_in)
  , path(path_in)
{}

const GroupOperationType Remove::type = GroupOperationType::remove;

// GroupOperation

GroupOperation::GroupOperation(CipherSuite suite)
  : CipherAware(suite)
  , InnerOp(suite, Add{})
{}

GroupOperation::GroupOperation(const Add& add)
  : CipherAware(DUMMY_CIPHERSUITE)
  , InnerOp(DUMMY_CIPHERSUITE, add)
{}

GroupOperation::GroupOperation(const Update& update)
  : CipherAware(update.cipher_suite())
  , InnerOp(update.cipher_suite(), update)

{}

GroupOperation::GroupOperation(const Remove& remove)
  : CipherAware(remove.cipher_suite())
  , InnerOp(remove.cipher_suite(), remove)
{}

// MLSPlaintext

const ContentType HandshakeData::type = ContentType::handshake;
const ContentType ApplicationData::type = ContentType::application;

MLSPlaintext::MLSPlaintext(CipherSuite suite)
  : CipherAware(suite)
  , epoch(0)
  , sender(0)
  , content(suite, ApplicationData{ suite })
{}

MLSPlaintext::MLSPlaintext(CipherSuite suite,
                           const bytes& group_id_in,
                           epoch_t epoch_in,
                           LeafIndex sender_in,
                           ContentType content_type_in,
                           bytes content_in)
  : CipherAware(suite)
  , group_id(group_id_in)
  , epoch(epoch_in)
  , sender(sender_in)
  , content(suite, ApplicationData{ suite })
{
  int cut = content_in.size() - 1;
  for (; content_in[cut] == 0 && cut >= 0; cut -= 1) {
  }
  if (content_in[cut] != 0x01) {
    throw ProtocolError("Invalid marker byte");
  }

  auto start = content_in.begin();
  auto sig_len_bytes = bytes(start + cut - 2, start + cut);
  auto sig_len = tls::get<uint16_t>(sig_len_bytes);

  cut -= 2;
  if (sig_len > cut) {
    throw ProtocolError("Invalid signature size");
  }

  signature = bytes(start + cut - sig_len, start + cut);
  auto content_data = bytes(start, start + cut - sig_len);

  switch (content_type_in) {
    case ContentType::handshake: {
      auto& operation = content.emplace<HandshakeData>(suite);
      tls::unmarshal(content_data, operation);
      break;
    }

    case ContentType::application: {
      auto& application_data = content.emplace<ApplicationData>();
      tls::unmarshal(content_data, application_data);
      break;
    }

    default:
      throw InvalidParameterError("Unknown content type");
  }
}

MLSPlaintext::MLSPlaintext(bytes group_id_in,
                           epoch_t epoch_in,
                           LeafIndex sender_in,
                           const GroupOperation& operation_in)
  : CipherAware(operation_in.cipher_suite())
  , group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , sender(sender_in)
  , content(operation_in.cipher_suite(), HandshakeData{ operation_in, {} })
{}

MLSPlaintext::MLSPlaintext(bytes group_id_in,
                           epoch_t epoch_in,
                           LeafIndex sender_in,
                           const ApplicationData& application_data_in)
  : CipherAware(DUMMY_CIPHERSUITE)
  , group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , sender(sender_in)
  , content(DUMMY_CIPHERSUITE, application_data_in)
{}

// struct {
//     opaque content[MLSPlaintext.length];
//     uint8 signature[MLSInnerPlaintext.sig_len];
//     uint16 sig_len;
//     uint8  marker = 1;
//     uint8  zero\_padding[length\_of\_padding];
// } MLSContentPlaintext;
bytes
MLSPlaintext::marshal_content(size_t padding_size) const
{
  bytes marshaled;
  if (content.type() == ContentType::handshake) {
    marshaled = tls::marshal(std::get<HandshakeData>(content));
  } else if (content.type() == ContentType::application) {
    marshaled = tls::marshal(std::get<ApplicationData>(content));
  } else {
    throw InvalidParameterError("Unknown content type");
  }

  uint16_t sig_len = signature.size();
  auto marker = bytes{ 0x01 };
  auto pad = zero_bytes(padding_size);
  marshaled = marshaled + signature + tls::marshal(sig_len) + marker + pad;
  return marshaled;
}

// struct {
//   opaque group_id<0..255>;
//   uint32 epoch;
//   uint32 sender;
//   ContentType content_type = handshake;
//   GroupOperation operation;
// } MLSPlaintextOpContent;
bytes
MLSPlaintext::op_content() const
{
  auto& handshake_data = std::get<HandshakeData>(content);
  tls::ostream w;
  w << group_id << epoch << sender << content.type()
    << handshake_data.operation;
  return w.bytes();
}

// struct {
//   opaque confirmation<0..255>;
//   opaque signature<0..2^16-1>;
// } MLSPlaintextOpAuthData;
bytes
MLSPlaintext::auth_data() const
{
  auto& handshake_data = std::get<HandshakeData>(content);
  tls::ostream w;
  w << handshake_data.confirmation << signature;
  return w.bytes();
}

bytes
MLSPlaintext::to_be_signed() const
{
  tls::ostream w;
  w << group_id << epoch << sender << content;
  return w.bytes();
}

void
MLSPlaintext::sign(const SignaturePrivateKey& priv)
{
  auto tbs = to_be_signed();
  signature = priv.sign(tbs);
}

bool
MLSPlaintext::verify(const SignaturePublicKey& pub) const
{
  auto tbs = to_be_signed();
  return pub.verify(tbs, signature);
}

} // namespace mls
