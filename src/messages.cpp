#include <mls/key_schedule.h>
#include <mls/messages.h>
#include <mls/state.h>
#include <mls/treekem.h>

namespace mls {

// Extensions

const uint16_t ExternalPubExtension::type = ExtensionType::external_pub;
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

// GroupInfo

static const auto zero_ref =
  LeafNodeRef{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

GroupInfo::GroupInfo(CipherSuite cipher_suite_in,
                     bytes group_id_in,
                     epoch_t epoch_in,
                     bytes tree_hash_in,
                     bytes confirmed_transcript_hash_in,
                     ExtensionList group_context_extensions_in,
                     ExtensionList other_extensions_in,
                     bytes confirmation_tag_in)
  : cipher_suite(cipher_suite_in)
  , group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , tree_hash(std::move(tree_hash_in))
  , confirmed_transcript_hash(std::move(confirmed_transcript_hash_in))
  , group_context_extensions(std::move(group_context_extensions_in))
  , other_extensions(std::move(other_extensions_in))
  , confirmation_tag(std::move(confirmation_tag_in))
  , signer(zero_ref)
{
}

struct GroupInfoTBS
{
  CipherSuite cipher_suite;
  const bytes& group_id;
  epoch_t epoch{ 0 };
  const bytes& tree_hash;
  const bytes& confirmed_transcript_hash;
  const ExtensionList& group_context_extensions;
  const ExtensionList& other_extensions;

  const bytes& confirmation_tag;
  const LeafNodeRef& signer;

  TLS_SERIALIZABLE(cipher_suite,
                   group_id,
                   epoch,
                   tree_hash,
                   confirmed_transcript_hash,
                   group_context_extensions,
                   other_extensions,
                   confirmation_tag,
                   signer)
};

bytes
GroupInfo::to_be_signed() const
{
  return tls::marshal(GroupInfoTBS{ cipher_suite,
                                    group_id,
                                    epoch,
                                    tree_hash,
                                    confirmed_transcript_hash,
                                    group_context_extensions,
                                    other_extensions,
                                    confirmation_tag,
                                    signer });
}

void
GroupInfo::sign(const TreeKEMPublicKey& tree,
                LeafNodeRef signer_ref,
                const SignaturePrivateKey& priv)
{
  auto maybe_leaf = tree.leaf_node(signer_ref);
  if (!maybe_leaf) {
    throw InvalidParameterError("Cannot sign from a blank leaf");
  }

  auto cred = opt::get(maybe_leaf).credential;
  if (cred.public_key() != priv.public_key) {
    throw InvalidParameterError("Bad key for index");
  }

  signer = signer_ref;
  signature = priv.sign(tree.suite, to_be_signed());
}

bool
GroupInfo::verify(const TreeKEMPublicKey& tree) const
{
  auto maybe_leaf = tree.leaf_node(signer);
  if (!maybe_leaf) {
    throw InvalidParameterError("Signer not found");
  }

  auto cred = opt::get(maybe_leaf).credential;
  return cred.public_key().verify(tree.suite, to_be_signed(), signature);
}

// Welcome

Welcome::Welcome()
  : version(ProtocolVersion::mls10)
  , cipher_suite(CipherSuite::ID::unknown)
{
}

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
  auto ref = kp.ref();
  for (size_t i = 0; i < secrets.size(); i++) {
    if (ref == secrets[i].new_member) {
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
  secrets.push_back({ kp.ref(), enc_gs });
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

// Commit

template<typename P>
std::vector<std::reference_wrapper<const P>>
filter_inline(const std::vector<ProposalOrRef>& prop_or_refs)
{
  auto selected = std::vector<std::reference_wrapper<const P>>{};
  for (const auto& prop_or_ref : prop_or_refs) {
    const auto* by_value = var::get_if<Proposal>(&prop_or_ref.content);
    if (!by_value) {
      continue;
    }

    const auto* correct_type = var::get_if<P>(&by_value->content);
    if (!correct_type) {
      continue;
    }

    selected.push_back(*correct_type);
  }

  return selected;
}

std::optional<bytes>
Commit::valid_external() const
{
  // There MUST be a single Add proposal
  if (filter_inline<Add>(proposals).size() != 1) {
    return std::nullopt;
  }

  // There MUST NOT be any Update proposals
  if (!filter_inline<Update>(proposals).empty()) {
    return std::nullopt;
  }

  // If a Remove proposal is present, then the `credential` and `endpoint_id` of
  // the removed leaf MUST be the same as the corresponding values in the Add
  // KeyPackage.
  auto removes = filter_inline<Remove>(proposals);
  if (removes.size() > 1) {
    return std::nullopt;
  }

  if (removes.size() == 1) {
    // TODO(RLB) Implement identity match once endpoint_id is implemented
  }

  // There MUST be a single ExternalInit proposal
  auto ext_inits = filter_inline<ExternalInit>(proposals);
  if (ext_inits.size() != 1) {
    return std::nullopt;
  }

  return ext_inits[0].get().kem_output;
}

// MLSPlaintext
Proposal::Type
Proposal::proposal_type() const
{
  return tls::variant<ProposalType>::type(content).val;
}

SenderType
Sender::sender_type() const
{
  return tls::variant<SenderType>::type(sender);
}

MLSPlaintext::MLSPlaintext()
  : wire_format(WireFormat::mls_plaintext)
  , epoch(0)
{
}

MLSPlaintext::MLSPlaintext(bytes group_id_in,
                           epoch_t epoch_in,
                           Sender sender_in,
                           ContentType content_type_in,
                           bytes authenticated_data_in,
                           const bytes& content_in)
  : wire_format(WireFormat::mls_ciphertext) // since this is used for decryption
  , group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , sender(std::move(sender_in))
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
  r >> signature >> confirmation_tag >> padding;
}

MLSPlaintext::MLSPlaintext(bytes group_id_in,
                           epoch_t epoch_in,
                           Sender sender_in,
                           ApplicationData application_data_in)
  : wire_format(WireFormat::mls_plaintext)
  , group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , sender(std::move(sender_in))
  , content(std::move(application_data_in))
{
}

MLSPlaintext::MLSPlaintext(bytes group_id_in,
                           epoch_t epoch_in,
                           Sender sender_in,
                           Proposal proposal)
  : wire_format(WireFormat::mls_plaintext)
  , group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , sender(std::move(sender_in))
  , content(std::move(proposal))
{
}

MLSPlaintext::MLSPlaintext(bytes group_id_in,
                           epoch_t epoch_in,
                           Sender sender_in,
                           Commit commit)
  : wire_format(WireFormat::mls_plaintext)
  , group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , sender(std::move(sender_in))
  , content(std::move(commit))
{
}

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

  w << signature << confirmation_tag << bytes(padding_size, 0);
  return w.bytes();
}

bytes
MLSPlaintext::commit_content() const
{
  tls::ostream w;
  w << wire_format << group_id << epoch << sender << authenticated_data;
  tls::variant<ContentType>::encode(w, content);
  w << signature;
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
  w << context << wire_format << group_id << epoch << sender
    << authenticated_data;
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
  w << signature << confirmation_tag;
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

  return tag == opt::get(membership_tag);
}

} // namespace mls
