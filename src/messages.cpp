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
  if (!maybe_kp) {
    throw InvalidParameterError("Cannot sign from a blank leaf");
  }

  auto cred = opt::get(maybe_kp).credential;
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
  if (!maybe_kp) {
    throw InvalidParameterError("Cannot sign from a blank leaf");
  }

  auto cred = opt::get(maybe_kp).credential;
  return cred.public_key().verify(suite, to_be_signed(), signature);
}

// Welcome

Welcome::Welcome()
  : version(ProtocolVersion::mls10)
  , cipher_suite{ CipherSuite::ID::unknown }
{}

Welcome::Welcome(CipherSuite suite,
                 const bytes& joiner_secret,
                 const bytes& psk_secret,
                 const GroupInfo& group_info)
  : version(ProtocolVersion::mls10)
  , cipher_suite(suite)
  , _joiner_secret(joiner_secret)
{
  auto [key, nonce] = group_info_key_nonce(suite, joiner_secret, psk_secret);
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
  auto gs = GroupSecrets{ _joiner_secret, std::nullopt };
  if (path_secret) {
    gs.path_secret = { opt::get(path_secret) };
  }

  auto gs_data = tls::marshal(gs);
  auto enc_gs = kp.init_key.encrypt(kp.cipher_suite, {}, gs_data);
  secrets.push_back({ kp.hash(), enc_gs });
}

GroupInfo
Welcome::decrypt(const bytes& joiner_secret, const bytes& psk_secret) const
{
  auto [key, nonce] =
    group_info_key_nonce(cipher_suite, joiner_secret, psk_secret);
  auto group_info_data =
    cipher_suite.get().hpke.aead.open(key, nonce, {}, encrypted_group_info);
  if (!group_info_data) {
    throw ProtocolError("Welcome decryption failed");
  }

  return tls::get<GroupInfo>(opt::get(group_info_data), cipher_suite);
}

std::tuple<bytes, bytes>
Welcome::group_info_key_nonce(CipherSuite suite,
                              const bytes& joiner_secret,
                              const bytes& psk_secret)
{
  auto key_size = suite.get().hpke.aead.key_size;
  auto nonce_size = suite.get().hpke.aead.nonce_size;

  auto joiner_expand = suite.derive_secret(joiner_secret, "member");
  auto member_secret = suite.get().hpke.kdf.extract(joiner_expand, psk_secret);

  auto welcome_secret = suite.derive_secret(member_secret, "welcome");
  auto key = suite.expand_with_label(welcome_secret, "key", {}, key_size);
  auto nonce = suite.expand_with_label(welcome_secret, "nonce", {}, nonce_size);

  return std::make_tuple(key, nonce);
}

// MLSPlaintext
ProposalType
Proposal::proposal_type() const
{
  return tls::variant<ProposalType>::type(content);
}

MLSPlaintext::MLSPlaintext()
  : epoch(0)
  , decrypted(false)
{}

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
  , decrypted(true)
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
      auto& commit = content.emplace<Commit>();
      r >> commit;
      break;
    }

    default:
      throw InvalidParameterError("Unknown content type");
  }

  bytes padding;
  tls::vector<2>::decode(r, signature);
  r >> confirmation_tag;
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
  , decrypted(false)
{}

MLSPlaintext::MLSPlaintext(bytes group_id_in,
                           epoch_t epoch_in,
                           Sender sender_in,
                           Proposal proposal)
  : group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , sender(sender_in)
  , content(std::move(proposal))
  , decrypted(false)
{}

MLSPlaintext::MLSPlaintext(bytes group_id_in,
                           epoch_t epoch_in,
                           Sender sender_in,
                           Commit commit)
  : group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , sender(sender_in)
  , content(std::move(commit))
  , decrypted(false)
{}

ContentType
MLSPlaintext::content_type() const
{
  static const auto get_content_type = overloaded{
    [](const ApplicationData& /*unused*/) { return ContentType::application; },
    [](const Proposal& /*unused*/) { return ContentType::proposal; },
    [](const Commit& /*unused*/) { return ContentType::commit; },
  };
  return var::visit(get_content_type, content);
}

bytes
MLSPlaintext::marshal_content(size_t padding_size) const
{
  tls::ostream w;
  var::visit([&](auto&& inner_content) { w << inner_content; }, content);

  bytes padding(padding_size, 0);
  tls::vector<2>::encode(w, signature);
  w << confirmation_tag;
  tls::vector<2>::encode(w, padding);
  return w.bytes();
}

bytes
MLSPlaintext::commit_content() const
{
  tls::ostream w;
  tls::vector<1>::encode(w, group_id);
  w << epoch << sender;
  tls::variant<ContentType>::encode(w, content);
  tls::vector<2>::encode(w, signature);
  return w.bytes();
}

bytes
MLSPlaintext::commit_auth_data() const
{
  return tls::marshal(confirmation_tag);
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

bytes
MLSPlaintext::membership_tag_input(const GroupContext& context) const
{
  tls::ostream w;
  tls::vector<2>::encode(w, signature);
  w << confirmation_tag;
  return to_be_signed(context) + w.bytes();
}

void
MLSPlaintext::set_membership_tag(const CipherSuite& suite,
                                 const GroupContext& context,
                                 const bytes& mac_key)
{
  auto tbm = membership_tag_input(context);
  membership_tag = { suite.get().digest.hmac(mac_key, tbm) };
}

bool
MLSPlaintext::verify_membership_tag(const CipherSuite& suite,
                                    const GroupContext& context,
                                    const bytes& mac_key) const
{
  if (decrypted) {
    return true;
  }

  if (!membership_tag) {
    return false;
  }

  auto tbm = membership_tag_input(context);
  auto mac_value = suite.get().digest.hmac(mac_key, tbm);
  return constant_time_eq(mac_value, opt::get(membership_tag).mac_value);
}

} // namespace mls
