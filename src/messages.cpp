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
                                   ExtensionList extensions_in,
                                   HPKEPublicKey external_pub_in)
  : cipher_suite(cipher_suite_in)
  , group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , tree_hash(std::move(tree_hash_in))
  , interim_transcript_hash(std::move(interim_transcript_hash_in))
  , extensions(std::move(extensions_in))
  , external_pub(std::move(external_pub_in))
{}

struct PublicGroupStateTBS {
  const CipherSuite& cipher_suite;
  const bytes& group_id;
  const epoch_t& epoch;
  const bytes& tree_hash;
  const bytes& interim_transcript_hash;
  const ExtensionList& extensions;
  const HPKEPublicKey& external_pub;
  const LeafIndex& signer_index;

  TLS_SERIALIZABLE(cipher_suite,
                   group_id,
                   epoch,
                   tree_hash,
                   interim_transcript_hash,
                   extensions,
                   external_pub,
                   signer_index)
  TLS_TRAITS(tls::pass,
             tls::vector<1>,
             tls::pass,
             tls::vector<1>,
             tls::vector<1>,
             tls::pass,
             tls::pass,
             tls::pass)

};

bytes
PublicGroupState::to_be_signed() const
{
  return tls::marshal(PublicGroupStateTBS{cipher_suite,
                   group_id,
                   epoch,
                   tree_hash,
                   interim_transcript_hash,
                   extensions,
                   external_pub,
                   signer_index});
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
                     ExtensionList extensions_in,
                     MAC confirmation_tag_in)
  : group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , tree_hash(std::move(tree_hash_in))
  , confirmed_transcript_hash(std::move(confirmed_transcript_hash_in))
  , extensions(std::move(extensions_in))
  , confirmation_tag(std::move(confirmation_tag_in))
{}

struct GroupInfoTBS {
  const bytes& group_id;
  const epoch_t& epoch;
  const bytes& tree_hash;
  const bytes& confirmed_transcript_hash;
  const MAC& confirmation_tag;
  const LeafIndex& signer_index;

  TLS_SERIALIZABLE(group_id, epoch, tree_hash, confirmed_transcript_hash, confirmation_tag, signer_index)
  TLS_TRAITS(tls::vector<1>, tls::pass, tls::vector<1>, tls::vector<1>, tls::pass, tls::pass)
};

bytes
GroupInfo::to_be_signed() const
{
  return tls::marshal(GroupInfoTBS{group_id, epoch, tree_hash, confirmed_transcript_hash, confirmation_tag, signer_index});
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
                 const bytes& psk_secret,
                 const GroupInfo& group_info)
  : version(ProtocolVersion::mls10)
  , cipher_suite(suite)
  , _joiner_secret(joiner_secret)
{
  auto [key, nonce] = group_info_key_nonce(suite, joiner_secret, psk_secret);
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
  auto gs = GroupSecrets{ _joiner_secret, std::nullopt, std::nullopt };
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
    cipher_suite.hpke().aead.open(key, nonce, {}, encrypted_group_info);
  if (!group_info_data) {
    throw ProtocolError("Welcome decryption failed");
  }

  return tls::get<GroupInfo>(opt::get(group_info_data));
}

KeyAndNonce
Welcome::group_info_key_nonce(CipherSuite suite,
                              const bytes& joiner_secret,
                              const bytes& psk_secret)
{
  auto welcome_secret =
    KeyScheduleEpoch::welcome_secret(suite, joiner_secret, psk_secret);
  auto key =
    suite.expand_with_label(welcome_secret, "key", {}, suite.key_size());
  auto nonce =
    suite.expand_with_label(welcome_secret, "nonce", {}, suite.nonce_size());
  return { std::move(key), std::move(nonce) };
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

struct MLSPlaintextContentExtra {
  const bytes& signature;
  const std::optional<MAC>& confirmation_tag;
  const bytes& padding;

  TLS_SERIALIZABLE(signature, confirmation_tag, padding)
  TLS_TRAITS(tls::vector<2>, tls::pass, tls::vector<2>)
};

bytes
MLSPlaintext::marshal_content(size_t padding_size) const
{
  static const auto marshal_content = [](const auto& val) {
    return tls::marshal(val);
  };

  bytes padding(padding_size, 0);
  auto content_data = var::visit(marshal_content, content);
  auto extra_data = tls::marshal(MLSPlaintextContentExtra{signature, confirmation_tag, padding});
  return content_data + extra_data;
}

struct MLSPlaintextCommitContent {
  const bytes& group_id;
  const epoch_t& epoch;
  const Sender& sender;
  // TODO(RLB) Include authenticated_data;
  const var::variant<ApplicationData, Proposal, Commit>& content;

  TLS_SERIALIZABLE(group_id, epoch, sender, content)
  TLS_TRAITS(tls::vector<1>, tls::pass, tls::pass, tls::variant<ContentType>)
};

bytes
MLSPlaintext::commit_content() const
{
  return tls::marshal(MLSPlaintextCommitContent{group_id, epoch, sender, content});
}

bytes
MLSPlaintext::commit_auth_data() const
{
  // XXX(RLB): This construction means that the hashed transcript differs from
  // the wire transcript by one byte -- the optional indicator on the
  // confirmation tag is missing.  It's always 0x01, so it shouldn't matter, but
  // it might be clearer to fix this.
  return tls::marshal(opt::get(confirmation_tag));
}

struct MLSPlaintextTBS {
  const GroupContext& context;
  const bytes& group_id;
  const epoch_t& epoch;
  const Sender& sender;
  const bytes& authenticated_data;
  const var::variant<ApplicationData, Proposal, Commit>& content;

  TLS_SERIALIZABLE(group_id, epoch, sender, authenticated_data, content)
  TLS_TRAITS(tls::vector<1>, tls::pass, tls::pass, tls::vector<4>, tls::variant<ContentType>)
};

bytes
MLSPlaintext::to_be_signed(const GroupContext& context) const
{
  return tls::marshal(MLSPlaintextTBS{context, group_id, epoch, sender, authenticated_data, content});
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

struct AuthData {
  const bytes& signature;
  const std::optional<MAC>& confirmation_tag;

  TLS_SERIALIZABLE(signature, confirmation_tag)
  TLS_TRAITS(tls::vector<2>, tls::pass)
};

bytes
MLSPlaintext::membership_tag_input(const GroupContext& context) const
{
  auto auth_data = tls::marshal(AuthData{signature, confirmation_tag});
  return to_be_signed(context) + auth_data;
}

bool
MLSPlaintext::verify_membership_tag(const bytes& tag) const
{
  if (decrypted) {
    return true;
  }

  if (!membership_tag) {
    return false;
  }

  return constant_time_eq(tag, opt::get(membership_tag).mac_value);
}

} // namespace mls
