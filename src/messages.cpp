#include "mls/messages.h"
#include "mls/key_schedule.h"
#include "mls/state.h"
#include "mls/treekem.h"

namespace mls {

// GroupInfo

GroupInfo::GroupInfo(CipherSuite suite)
  : suite(suite)
  , epoch(0)
  , tree(suite)
{}

GroupInfo::GroupInfo(bytes group_id_in,
                     epoch_t epoch_in,
                     TreeKEMPublicKey tree_in,
                     bytes confirmed_transcript_hash_in,
                     bytes interim_transcript_hash_in,
                     ExtensionList extensions_in,
                     bytes confirmation_in)
  : suite(tree_in.suite)
  , group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , tree(std::move(tree_in))
  , confirmed_transcript_hash(std::move(confirmed_transcript_hash_in))
  , interim_transcript_hash(std::move(interim_transcript_hash_in))
  , extensions(std::move(extensions_in))
  , confirmation(std::move(confirmation_in))
{}

bytes
GroupInfo::to_be_signed() const
{
  tls::ostream w;
  tls::vector<1>::encode(w, group_id);
  w << epoch << tree;
  tls::vector<1>::encode(w, confirmed_transcript_hash);
  tls::vector<1>::encode(w, interim_transcript_hash);
  tls::vector<1>::encode(w, confirmation);
  w << signer_index;
  return w.bytes();
}

void
GroupInfo::sign(LeafIndex index, const SignaturePrivateKey& priv)
{
  auto maybe_kp = tree.key_package(index);
  if (!maybe_kp.has_value()) {
    throw InvalidParameterError("Cannot sign from a blank leaf");
  }

  auto cred = maybe_kp.value().credential;
  if (cred.public_key() != priv.public_key) {
    throw InvalidParameterError("Bad key for index");
  }

  signer_index = index;
  signature = priv.sign(suite, to_be_signed());
}

bool
GroupInfo::verify() const
{
  auto maybe_kp = tree.key_package(signer_index);
  if (!maybe_kp.has_value()) {
    throw InvalidParameterError("Cannot sign from a blank leaf");
  }

  auto cred = maybe_kp.value().credential;
  return cred.public_key().verify(suite, to_be_signed(), signature);
}

// Welcome

Welcome::Welcome()
  : version(ProtocolVersion::mls10)
  , cipher_suite{ CipherSuite::ID::unknown }
{}

Welcome::Welcome(CipherSuite suite,
                 bytes epoch_secret,
                 const GroupInfo& group_info)
  : version(ProtocolVersion::mls10)
  , cipher_suite(suite)
  , _epoch_secret(std::move(epoch_secret))
{
  auto [key, nonce] = group_info_key_nonce(_epoch_secret);
  auto group_info_data = tls::marshal(group_info);
  encrypted_group_info =
    cipher_suite.get().hpke.aead.seal(key, nonce, {}, group_info_data);
}

std::optional<int>
Welcome::find(const KeyPackage& kp) const
{
  auto hash = kp.hash();
  for (size_t i = 0; i < secrets.size(); i++) {
    if (hash == secrets[i].key_package_hash) {
      return i;
    }
  }
  return std::nullopt;
}

void
Welcome::encrypt(const KeyPackage& kp, const std::optional<bytes>& path_secret)
{
  auto gs = GroupSecrets{ _epoch_secret, std::nullopt };
  if (path_secret.has_value()) {
    gs.path_secret = { path_secret.value() };
  }

  auto gs_data = tls::marshal(gs);
  auto enc_gs = kp.init_key.encrypt(kp.cipher_suite, {}, gs_data);
  secrets.push_back({ kp.hash(), enc_gs });
}

GroupInfo
Welcome::decrypt(const bytes& epoch_secret) const
{
  auto [key, nonce] = group_info_key_nonce(epoch_secret);
  auto group_info_data =
    cipher_suite.get().hpke.aead.open(key, nonce, {}, encrypted_group_info);
  if (!group_info_data.has_value()) {
    throw ProtocolError("Welcome decryption failed");
  }

  return tls::get<GroupInfo>(group_info_data.value(), cipher_suite);
}

std::tuple<bytes, bytes>
Welcome::group_info_key_nonce(const bytes& epoch_secret) const
{
  auto secret_size = cipher_suite.get().hpke.kdf.hash_size();
  auto key_size = cipher_suite.get().hpke.aead.key_size();
  auto nonce_size = cipher_suite.get().hpke.aead.nonce_size();

  auto secret =
    cipher_suite.expand_with_label(epoch_secret, "group info", {}, secret_size);
  auto key = cipher_suite.expand_with_label(secret, "key", {}, key_size);
  auto nonce = cipher_suite.expand_with_label(secret, "nonce", {}, nonce_size);

  return std::make_tuple(key, nonce);
}

// MLSPlaintext

const ProposalType Add::type = ProposalType::add;
const ProposalType Update::type = ProposalType::update;
const ProposalType Remove::type = ProposalType::remove;

ProposalType
Proposal::proposal_type() const
{
  static auto get_type = [](auto&& v) -> ProposalType { return v.type; };
  return std::visit(get_type, content);
}

const ContentType Proposal::type = ContentType::proposal;
const ContentType CommitData::type = ContentType::commit;
const ContentType ApplicationData::type = ContentType::application;

MLSPlaintext::MLSPlaintext(bytes group_id_in,
                           epoch_t epoch_in,
                           Sender sender_in,
                           ContentType content_type_in,
                           bytes authenticated_data_in,
                           const bytes& content_in)
  : group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , sender(sender_in)
  , authenticated_data(std::move(authenticated_data_in))
  , content(ApplicationData())
{
  tls::istream r(content_in);
  switch (content_type_in) {
    case ContentType::application: {
      auto& application_data = content.emplace<ApplicationData>();
      r >> application_data;
      break;
    }

    case ContentType::proposal: {
      auto& proposal = content.emplace<Proposal>();
      r >> proposal;
      break;
    }

    case ContentType::commit: {
      auto& commit_data = content.emplace<CommitData>();
      r >> commit_data;
      break;
    }

    default:
      throw InvalidParameterError("Unknown content type");
  }

  bytes padding;
  tls::vector<2>::decode(r, signature);
  tls::vector<2>::decode(r, padding);
}

MLSPlaintext::MLSPlaintext(bytes group_id_in,
                           epoch_t epoch_in,
                           Sender sender_in,
                           ApplicationData application_data_in)
  : group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , sender(sender_in)
  , content(std::move(application_data_in))
{}

MLSPlaintext::MLSPlaintext(bytes group_id_in,
                           epoch_t epoch_in,
                           Sender sender_in,
                           Proposal proposal)
  : group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , sender(sender_in)
  , content(std::move(proposal))
{}

MLSPlaintext::MLSPlaintext(bytes group_id_in,
                           epoch_t epoch_in,
                           Sender sender_in,
                           const Commit& commit)
  : group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , sender(sender_in)
  , content(CommitData{ commit, {} })
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
  tls::ostream w;
  if (std::holds_alternative<ApplicationData>(content)) {
    w << std::get<ApplicationData>(content);
  } else if (std::holds_alternative<Proposal>(content)) {
    w << std::get<Proposal>(content);
  } else if (std::holds_alternative<CommitData>(content)) {
    w << std::get<CommitData>(content);
  } else {
    throw InvalidParameterError("Unknown content type");
  }

  bytes padding(padding_size, 0);
  tls::vector<2>::encode(w, signature);
  tls::vector<2>::encode(w, padding);
  return w.bytes();
}

bytes
MLSPlaintext::commit_content() const
{
  const auto& commit_data = std::get<CommitData>(content);
  tls::ostream w;
  tls::vector<1>::encode(w, group_id);
  w << epoch << sender << commit_data.commit;
  return w.bytes();
}

// struct {
//   opaque confirmation<0..255>;
//   opaque signature<0..2^16-1>;
// } MLSPlaintextOpAuthData;
bytes
MLSPlaintext::commit_auth_data() const
{
  const auto& commit_data = std::get<CommitData>(content);
  tls::ostream w;
  tls::vector<1>::encode(w, commit_data.confirmation);
  tls::vector<2>::encode(w, signature);
  return w.bytes();
}

bytes
MLSPlaintext::to_be_signed(const GroupContext& context) const
{
  tls::ostream w;
  w << context;
  tls::vector<1>::encode(w, group_id);
  w << epoch << sender;
  tls::vector<4>::encode(w, authenticated_data);
  tls::variant<ContentType>::encode(w, content);
  return w.bytes();
}

void
MLSPlaintext::sign(const CipherSuite& suite,
                   const GroupContext& context,
                   const SignaturePrivateKey& priv)
{
  auto tbs = to_be_signed(context);
  signature = priv.sign(suite, tbs);
}

bool
MLSPlaintext::verify(const CipherSuite& suite,
                     const GroupContext& context,
                     const SignaturePublicKey& pub) const
{
  auto tbs = to_be_signed(context);
  return pub.verify(suite, tbs, signature);
}

} // namespace mls
