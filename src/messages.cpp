#include <mls/key_schedule.h>
#include <mls/messages.h>
#include <mls/state.h>
#include <mls/treekem.h>

namespace mls {

// Extensions

const uint16_t RatchetTreeExtension::type = ExtensionType::ratchet_tree;
const uint16_t SFrameParameters::type = ExtensionType::sframe_parameters;
const uint16_t SFrameCapabilities::type = ExtensionType::sframe_parameters;

bool
SFrameCapabilities::compatible(const SFrameParameters& params) const
{
  const auto begin = cipher_suites.begin();
  const auto end = cipher_suites.end();
  return std::find(begin, end, params.cipher_suite) != end;
}

// PublicGroupState

PublicGroupState::PublicGroupState(CipherSuite cipher_suite_in,
                                   bytes group_id_in,
                                   epoch_t epoch_in,
                                   bytes tree_hash_in,
                                   bytes interim_transcript_hash_in,
                                   ExtensionList group_context_extensions_in,
                                   ExtensionList other_extensions_in,
                                   HPKEPublicKey external_pub_in)
  : cipher_suite(cipher_suite_in)
  , group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , tree_hash(std::move(tree_hash_in))
  , interim_transcript_hash(std::move(interim_transcript_hash_in))
  , group_context_extensions(std::move(group_context_extensions_in))
  , other_extensions(std::move(other_extensions_in))
  , external_pub(std::move(external_pub_in))
{}

bytes
PublicGroupState::to_be_signed() const
{
  tls::ostream w;
  w << cipher_suite;
  tls::vector<1>::encode(w, group_id);
  w << epoch;
  tls::vector<1>::encode(w, tree_hash);
  tls::vector<1>::encode(w, interim_transcript_hash);
  w << group_context_extensions << other_extensions << external_pub
    << signer_index;
  return w.bytes();
}

void
PublicGroupState::sign(const TreeKEMPublicKey& tree,
                       LeafIndex index,
                       const SignaturePrivateKey& priv)
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
  signature = priv.sign(tree.suite, to_be_signed());
}

bool
PublicGroupState::verify(const TreeKEMPublicKey& tree) const
{
  if (tree.suite != cipher_suite) {
    throw InvalidParameterError("Cipher suite mismatch");
  }

  auto maybe_kp = tree.key_package(signer_index);
  if (!maybe_kp) {
    throw InvalidParameterError("Cannot sign from a blank leaf");
  }

  auto cred = opt::get(maybe_kp).credential;
  return cred.public_key().verify(cipher_suite, to_be_signed(), signature);
}

// GroupInfo

GroupInfo::GroupInfo(bytes group_id_in,
                     epoch_t epoch_in,
                     bytes tree_hash_in,
                     bytes confirmed_transcript_hash_in,
                     ExtensionList group_context_extensions_in,
                     ExtensionList other_extensions_in,
                     MAC confirmation_tag_in)
  : group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , tree_hash(std::move(tree_hash_in))
  , confirmed_transcript_hash(std::move(confirmed_transcript_hash_in))
  , group_context_extensions(std::move(group_context_extensions_in))
  , other_extensions(std::move(other_extensions_in))
  , confirmation_tag(std::move(confirmation_tag_in))
{}

bytes
GroupInfo::to_be_signed() const
{
  tls::ostream w;
  tls::vector<1>::encode(w, group_id);
  w << epoch;
  tls::vector<1>::encode(w, tree_hash);
  tls::vector<1>::encode(w, confirmed_transcript_hash);
  w << group_context_extensions << other_extensions << confirmation_tag
    << signer_index;
  return w.bytes();
}

void
GroupInfo::sign(const TreeKEMPublicKey& tree,
                LeafIndex index,
                const SignaturePrivateKey& priv)
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
  signature = priv.sign(tree.suite, to_be_signed());
}

bool
GroupInfo::verify(const TreeKEMPublicKey& tree) const
{
  auto maybe_kp = tree.key_package(signer_index);
  if (!maybe_kp) {
    throw InvalidParameterError("Cannot sign from a blank leaf");
  }

  auto cred = opt::get(maybe_kp).credential;
  return cred.public_key().verify(tree.suite, to_be_signed(), signature);
}

// Welcome

Welcome::Welcome()
  : version(ProtocolVersion::mls10)
  , cipher_suite(CipherSuite::ID::unknown)
{}

Welcome::Welcome(CipherSuite suite,
                 const bytes& joiner_secret,
                 const std::vector<PSKWithSecret>& psks,
                 const GroupInfo& group_info)
  : version(ProtocolVersion::mls10)
  , cipher_suite(suite)
  , _joiner_secret(joiner_secret)
{
  auto [key, nonce] = group_info_key_nonce(suite, joiner_secret, psks);
  auto group_info_data = tls::marshal(group_info);
  encrypted_group_info =
    cipher_suite.hpke().aead.seal(key, nonce, {}, group_info_data);
}

std::optional<int>
Welcome::find(const KeyPackage& kp) const
{
  auto hash = kp.hash();
  for (size_t i = 0; i < secrets.size(); i++) {
    if (hash == secrets[i].key_package_hash) {
      return static_cast<int>(i);
    }
  }
  return std::nullopt;
}

void
Welcome::encrypt(const KeyPackage& kp, const std::optional<bytes>& path_secret)
{
  auto gs = GroupSecrets{ _joiner_secret, std::nullopt, {} };
  if (path_secret) {
    gs.path_secret = { opt::get(path_secret) };
  }

  auto gs_data = tls::marshal(gs);
  auto enc_gs = kp.init_key.encrypt(kp.cipher_suite, {}, {}, gs_data);
  secrets.push_back({ kp.hash(), enc_gs });
}

GroupInfo
Welcome::decrypt(const bytes& joiner_secret,
                 const std::vector<PSKWithSecret>& psks) const
{
  auto [key, nonce] = group_info_key_nonce(cipher_suite, joiner_secret, psks);
  auto group_info_data =
    cipher_suite.hpke().aead.open(key, nonce, {}, encrypted_group_info);
  if (!group_info_data) {
    throw ProtocolError("Welcome decryption failed");
  }

  return tls::get<GroupInfo>(opt::get(group_info_data));
}

KeyAndNonce
Welcome::group_info_key_nonce(CipherSuite suite,
                              const bytes& joiner_secret,
                              const std::vector<PSKWithSecret>& psks)
{
  static const auto key_label = from_ascii("key");
  static const auto nonce_label = from_ascii("nonce");

  auto welcome_secret =
    KeyScheduleEpoch::welcome_secret(suite, joiner_secret, psks);

  // XXX(RLB): These used to be done with ExpandWithLabel.  Should we do that
  // instead, for better domain separation? (In particular, including "mls10")
  // That is what we do for the sender data key/nonce.
  auto key =
    suite.hpke().kdf.expand(welcome_secret, key_label, suite.key_size());
  auto nonce =
    suite.hpke().kdf.expand(welcome_secret, nonce_label, suite.nonce_size());
  return { std::move(key), std::move(nonce) };
}

// MLSPlaintext
Proposal::Type
Proposal::proposal_type() const
{
  return tls::variant<ProposalType>::type(content).val;
}

MLSPlaintext::MLSPlaintext()
  : wire_format(WireFormat::mls_plaintext)
  , epoch(0)
{}

MLSPlaintext::MLSPlaintext(bytes group_id_in,
                           epoch_t epoch_in,
                           Sender sender_in,
                           ContentType content_type_in,
                           bytes authenticated_data_in,
                           const bytes& content_in)
  : wire_format(WireFormat::mls_ciphertext) // since this is used for decryption
  , group_id(std::move(group_id_in))
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
  : wire_format(WireFormat::mls_plaintext)
  , group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , sender(sender_in)
  , content(std::move(application_data_in))
{}

MLSPlaintext::MLSPlaintext(bytes group_id_in,
                           epoch_t epoch_in,
                           Sender sender_in,
                           Proposal proposal)
  : wire_format(WireFormat::mls_plaintext)
  , group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , sender(sender_in)
  , content(std::move(proposal))
{}

MLSPlaintext::MLSPlaintext(bytes group_id_in,
                           epoch_t epoch_in,
                           Sender sender_in,
                           Commit commit)
  : wire_format(WireFormat::mls_plaintext)
  , group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , sender(sender_in)
  , content(std::move(commit))
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
  w << wire_format;
  tls::vector<1>::encode(w, group_id);
  w << epoch << sender;
  tls::vector<4>::encode(w, authenticated_data);
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
  w << wire_format;
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

bool
MLSPlaintext::verify_membership_tag(const bytes& tag) const
{
  if (wire_format == WireFormat::mls_ciphertext) {
    return true;
  }

  if (!membership_tag) {
    return false;
  }

  return constant_time_eq(tag, opt::get(membership_tag).mac_value);
}

} // namespace mls
