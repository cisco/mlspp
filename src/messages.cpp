#include "messages.h"

namespace mls {

// RatchetNode

bool
operator==(const RatchetNode& lhs, const RatchetNode& rhs)
{
  return (lhs.public_key == rhs.public_key) &&
         (lhs.node_secrets == rhs.node_secrets);
}

tls::ostream&
operator<<(tls::ostream& out, const RatchetNode& obj)
{
  return out << obj.public_key << obj.node_secrets;
}

tls::istream&
operator>>(tls::istream& in, RatchetNode& obj)
{
  return in >> obj.public_key >> obj.node_secrets;
}

// DirectPath

bool
operator==(const DirectPath& lhs, const DirectPath& rhs)
{
  return (lhs.nodes == rhs.nodes);
}

tls::ostream&
operator<<(tls::ostream& out, const DirectPath& obj)
{
  return out << obj.nodes;
}

tls::istream&
operator>>(tls::istream& in, DirectPath& obj)
{
  return in >> obj.nodes;
}

// UserInitKey

void
UserInitKey::add_init_key(const DHPublicKey& pub)
{
  cipher_suites.push_back(pub.cipher_suite());
  init_keys.push_back(pub.to_bytes());
}

std::optional<DHPublicKey>
UserInitKey::find_init_key(CipherSuite suite) const
{
  for (size_t i = 0; i < cipher_suites.size(); ++i) {
    if (cipher_suites[i] == suite) {
      return DHPublicKey{ suite, init_keys[i] };
    }
  }

  return std::nullopt;
}

void
UserInitKey::sign(const SignaturePrivateKey& identity_priv,
                  const Credential& credential_in)
{
  if (cipher_suites.size() != init_keys.size()) {
    throw InvalidParameterError("Mal-formed UserInitKey");
  }

  credential = credential_in;

  auto tbs = to_be_signed();
  signature = identity_priv.sign(tbs);
}

bool
UserInitKey::verify() const
{
  auto tbs = to_be_signed();
  auto identity_key = credential.public_key();
  return identity_key.verify(tbs, signature);
}

bytes
UserInitKey::to_be_signed() const
{
  tls::ostream out;
  out << cipher_suites << init_keys << credential;
  return out.bytes();
}

// XXX(rlb@ipv.sx): Don't compare signature, since some signature
// algorithms are non-deterministic.  Instead, we just verify that
// the public keys are the same and both signatures are valid over
// the same contents.
bool
operator==(const UserInitKey& lhs, const UserInitKey& rhs)
{
  return (lhs.cipher_suites == rhs.cipher_suites) &&
         (lhs.init_keys == rhs.init_keys) &&
         (lhs.credential == rhs.credential) && (lhs.signature == rhs.signature);
}

tls::ostream&
operator<<(tls::ostream& out, const UserInitKey& obj)
{
  return out << obj.user_init_key_id << obj.supported_versions
             << obj.cipher_suites << obj.init_keys << obj.credential
             << obj.signature;
}

tls::istream&
operator>>(tls::istream& in, UserInitKey& obj)
{
  return in >> obj.user_init_key_id >> obj.supported_versions >>
         obj.cipher_suites >> obj.init_keys >> obj.credential >> obj.signature;
}

// WelcomeInfo

bytes
WelcomeInfo::hash(CipherSuite suite) const
{
  auto marshaled = tls::marshal(*this);
  return Digest(suite).write(marshaled).digest();
}

bool
operator==(const WelcomeInfo& lhs, const WelcomeInfo& rhs)
{
  return (lhs.version == rhs.version) && (lhs.group_id == rhs.group_id) &&
         (lhs.epoch == rhs.epoch) && (lhs.tree == rhs.tree) &&
         (lhs.transcript_hash == rhs.transcript_hash) &&
         (lhs.init_secret == rhs.init_secret);
}

tls::ostream&
operator<<(tls::ostream& out, const WelcomeInfo& obj)
{
  return out << obj.version << obj.group_id << obj.epoch << obj.tree
             << obj.transcript_hash << obj.init_secret;
}

tls::istream&
operator>>(tls::istream& in, WelcomeInfo& obj)
{
  in >> obj.version >> obj.group_id >> obj.epoch;

  // Set the tree struct to use the correct ciphersuite for this
  // group
  obj.tree = RatchetTree(obj.cipher_suite());

  in >> obj.tree;
  in >> obj.transcript_hash;
  in >> obj.init_secret;
  return in;
}

// Welcome

Welcome::Welcome(const bytes& id,
                 const DHPublicKey& pub,
                 const WelcomeInfo& info)
  : user_init_key_id(id)
  , cipher_suite(pub.cipher_suite())
  , encrypted_welcome_info(pub.encrypt(tls::marshal(info)))
{}

WelcomeInfo
Welcome::decrypt(const DHPrivateKey& priv) const
{
  auto welcome_info_bytes = priv.decrypt(encrypted_welcome_info);
  auto welcome_info = WelcomeInfo{ priv.cipher_suite() };
  tls::unmarshal(welcome_info_bytes, welcome_info);
  return welcome_info;
}

bool
operator==(const Welcome& lhs, const Welcome& rhs)
{
  return (lhs.user_init_key_id == rhs.user_init_key_id) &&
         (lhs.cipher_suite == rhs.cipher_suite) &&
         (lhs.encrypted_welcome_info == rhs.encrypted_welcome_info);
}

tls::ostream&
operator<<(tls::ostream& out, const Welcome& obj)
{
  return out << obj.user_init_key_id << obj.cipher_suite
             << obj.encrypted_welcome_info;
}

tls::istream&
operator>>(tls::istream& in, Welcome& obj)
{
  in >> obj.user_init_key_id >> obj.cipher_suite;

  obj.encrypted_welcome_info = HPKECiphertext{ obj.cipher_suite };
  in >> obj.encrypted_welcome_info;
  return in;
}

// GroupOperationType

tls::ostream&
operator<<(tls::ostream& out, const GroupOperationType& obj)
{
  return out << uint8_t(obj);
}

tls::istream&
operator>>(tls::istream& in, GroupOperationType& obj)
{
  uint8_t type;
  in >> type;
  obj = GroupOperationType(type);
  return in;
}

// Add

const GroupOperationType Add::type = GroupOperationType::add;

bool
operator==(const Add& lhs, const Add& rhs)
{
  return (lhs.index == rhs.index) && (lhs.init_key == rhs.init_key) &&
         (lhs.welcome_info_hash == rhs.welcome_info_hash);
}

tls::ostream&
operator<<(tls::ostream& out, const Add& obj)
{
  return out << obj.index << obj.init_key << obj.welcome_info_hash;
}

tls::istream&
operator>>(tls::istream& in, Add& obj)
{
  return in >> obj.index >> obj.init_key >> obj.welcome_info_hash;
}

// Update

const GroupOperationType Update::type = GroupOperationType::update;

bool
operator==(const Update& lhs, const Update& rhs)
{
  return (lhs.path == rhs.path);
}

tls::ostream&
operator<<(tls::ostream& out, const Update& obj)
{
  return out << obj.path;
}

tls::istream&
operator>>(tls::istream& in, Update& obj)
{
  return in >> obj.path;
}

// Remove

const GroupOperationType Remove::type = GroupOperationType::remove;

bool
operator==(const Remove& lhs, const Remove& rhs)
{
  return (lhs.path == rhs.path);
}

tls::ostream&
operator<<(tls::ostream& out, const Remove& obj)
{
  return out << obj.removed << obj.path;
}

tls::istream&
operator>>(tls::istream& in, Remove& obj)
{
  return in >> obj.removed >> obj.path;
}

// GroupOperation
bool
operator==(const GroupOperation& lhs, const GroupOperation& rhs)
{
  return (lhs.type == rhs.type) &&
         (((lhs.type == GroupOperationType::add) && (lhs.add == rhs.add)) ||
          ((lhs.type == GroupOperationType::update) &&
           (lhs.update == rhs.update)) ||
          ((lhs.type == GroupOperationType::remove) &&
           (lhs.remove == rhs.remove))) &&
         (lhs.confirmation == rhs.confirmation);
}

tls::ostream&
operator<<(tls::ostream& out, const GroupOperation& obj)
{
  out << obj.type;

  switch (obj.type) {
    case GroupOperationType::add:
      out << obj.add;
      break;
    case GroupOperationType::update:
      out << obj.update;
      break;
    case GroupOperationType::remove:
      out << obj.remove;
      break;
    default:
      throw InvalidParameterError("Unknown group operation type");
  }

  out << obj.confirmation;
  return out;
}

tls::istream&
operator>>(tls::istream& in, GroupOperation& obj)
{
  in >> obj.type;

  switch (obj.type) {
    case GroupOperationType::add:
      in >> obj.add;
      break;
    case GroupOperationType::update:
      in >> obj.update;
      break;
    case GroupOperationType::remove:
      in >> obj.remove;
      break;
    default:
      throw InvalidParameterError("Unknown group operation type");
  }

  in >> obj.confirmation;
  return in;
}

// ContentType

tls::ostream&
operator<<(tls::ostream& out, const ContentType& obj)
{
  return out << static_cast<uint8_t>(obj);
}

tls::istream&
operator>>(tls::istream& in, ContentType& obj)
{
  uint8_t val;
  in >> val;
  obj = static_cast<ContentType>(val);
  return in;
}

// MLSPlaintext

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
  bytes content;
  if (content_type == ContentType::handshake) {
    content = tls::marshal(operation.value());
  } else if (content_type == ContentType::application) {
    content = application_data.value();
  } else {
    throw InvalidParameterError("Unknown content type");
  }

  uint16_t sig_len = signature.size();
  auto marker = bytes{ 0x01 };
  auto pad = zero_bytes(padding_size);
  content = content + signature + tls::marshal(sig_len) + marker + pad;
  return content;
}

void
MLSPlaintext::unmarshal_content(CipherSuite suite, const bytes& marshaled)
{
  int cut = marshaled.size() - 1;
  for (; marshaled[cut] == 0 && cut >= 0; cut -= 1) {
  }
  if (marshaled[cut] != 0x01) {
    throw ProtocolError("Invalid marker byte");
  }

  uint16_t sig_len;
  auto start = marshaled.begin();
  auto sig_len_bytes = bytes(start + cut - 2, start + cut);
  tls::unmarshal(sig_len_bytes, sig_len);
  cut -= 2;
  if (sig_len > cut) {
    throw ProtocolError("Invalid signature size");
  }

  signature = bytes(start + cut - sig_len, start + cut);
  auto content = bytes(start, start + cut - sig_len);

  switch (content_type) {
    case ContentType::handshake:
      operation = GroupOperation(suite);
      tls::unmarshal(content, operation.value());
      break;

    case ContentType::application:
      application_data = content;
      break;

    default:
      throw InvalidParameterError("Unknown content type");
  }
}

bytes
MLSPlaintext::to_be_signed() const
{
  bytes content;
  switch (content_type) {
    case ContentType::handshake:
      content = tls::marshal(operation.value());
      break;

    case ContentType::application:
      content = tls::marshal(application_data.value());
      break;

    default:
      throw InvalidParameterError("Unknown content type");
  }

  tls::ostream w;
  w << epoch << sender << content_type;
  return w.bytes() + content;
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

tls::ostream&
operator<<(tls::ostream& out, const MLSPlaintext& obj)
{
  out.write_raw(obj.to_be_signed());
  out << obj.signature;
  return out;
}

tls::istream&
operator>>(tls::istream& in, MLSPlaintext& obj)
{
  in >> obj.epoch >> obj.sender >> obj.content_type;

  switch (obj.content_type) {
    case ContentType::handshake:
      obj.operation = GroupOperation(obj._suite);
      in >> obj.operation.value();
      break;

    case ContentType::application:
      obj.application_data = tls::opaque<4>();
      in >> obj.application_data.value();
      break;

    default:
      throw InvalidParameterError("Unknown content type");
  }

  in >> obj.signature;
  return in;
}

// MLSCiphertext

tls::ostream&
operator<<(tls::ostream& out, const MLSCiphertext& obj)
{
  return out << obj.epoch << obj.masked_sender_data << obj.ciphertext;
}

tls::istream&
operator>>(tls::istream& in, MLSCiphertext& obj)
{
  return in >> obj.epoch >> obj.masked_sender_data >> obj.ciphertext;
}

} // namespace mls
