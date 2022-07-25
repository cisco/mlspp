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

tls::ostream&
operator<<(tls::ostream& str, const MLSMessageAuth& obj)
{
  switch (obj.content_type) {
    case ContentType::proposal:
    case ContentType::application:
      return str << obj.signature;

    case ContentType::commit:
      return str << obj.signature << opt::get(obj.confirmation_tag);

    default:
      throw InvalidParameterError("Invalid content type");
  }
}

tls::istream&
operator>>(tls::istream& str, MLSMessageAuth& obj)
{
  switch (obj.content_type) {
    case ContentType::proposal:
    case ContentType::application:
      return str >> obj.signature;

    case ContentType::commit:
      obj.confirmation_tag.emplace();
      return str >> obj.signature >> opt::get(obj.confirmation_tag);

    default:
      throw InvalidParameterError("Invalid content type");
  }
}

bool
operator==(const MLSMessageAuth& lhs, const MLSMessageAuth& rhs)
{
  return lhs.content_type == rhs.content_type &&
         lhs.signature == rhs.signature &&
         lhs.confirmation_tag == rhs.confirmation_tag;
}

MLSMessageContent::MLSMessageContent(bytes group_id_in,
                                     epoch_t epoch_in,
                                     Sender sender_in,
                                     bytes authenticated_data_in,
                                     RawContent content_in)
  : group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , sender(std::move(sender_in))
  , authenticated_data(std::move(authenticated_data_in))
  , content(std::move(content_in))
{
}

MLSMessageContent::MLSMessageContent(bytes group_id_in,
                                     epoch_t epoch_in,
                                     Sender sender_in,
                                     bytes authenticated_data_in,
                                     ContentType content_type)
  : group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , sender(std::move(sender_in))
  , authenticated_data(std::move(authenticated_data_in))
{
  switch (content_type) {
    case ContentType::commit:
      content.emplace<Commit>();
      break;

    case ContentType::proposal:
      content.emplace<Proposal>();
      break;

    case ContentType::application:
      content.emplace<ApplicationData>();
      break;

    default:
      throw InvalidParameterError("Invalid content type");
  }
}

ContentType
MLSMessageContent::content_type() const
{
  return tls::variant<ContentType>::type(content);
}

MLSMessageContentAuth
MLSMessageContentAuth::sign(WireFormat wire_format,
                            MLSMessageContent content,
                            CipherSuite suite,
                            const SignaturePrivateKey& sig_priv,
                            const std::optional<GroupContext>& context)
{
  if (wire_format == WireFormat::mls_plaintext &&
      content.content_type() == ContentType::application) {
    throw InvalidParameterError(
      "Application data cannot be sent as MLSPlaintext");
  }

  auto content_auth = MLSMessageContentAuth{ wire_format, std::move(content) };
  auto tbs = content_auth.to_be_signed(context);
  content_auth.auth.signature = sig_priv.sign(suite, tbs);
  return content_auth;
}

bool
MLSMessageContentAuth::verify(CipherSuite suite,
                              const SignaturePublicKey& sig_pub,
                              const std::optional<GroupContext>& context) const
{
  if (wire_format == WireFormat::mls_plaintext &&
      content.content_type() == ContentType::application) {
    return false;
  }

  auto tbs = to_be_signed(context);
  return sig_pub.verify(suite, tbs, auth.signature);
}

struct MLSMessageCommitContent
{
  WireFormat wire_format;
  const MLSMessageContent& content;
  const bytes& signature;

  TLS_SERIALIZABLE(wire_format, content, signature);
};

struct MLSMessageCommitAuthData
{
  const bytes& confirmation_tag;

  TLS_SERIALIZABLE(confirmation_tag);
};

bytes
MLSMessageContentAuth::commit_content() const
{
  return tls::marshal(MLSMessageCommitContent{
    wire_format,
    content,
    auth.signature,
  });
}

bytes
MLSMessageContentAuth::commit_auth_data() const
{
  return tls::marshal(
    MLSMessageCommitAuthData{ opt::get(auth.confirmation_tag) });
}

void
MLSMessageContentAuth::set_confirmation_tag(const bytes& confirmation_tag)
{
  auth.confirmation_tag = confirmation_tag;
}

bool
MLSMessageContentAuth::check_confirmation_tag(
  const bytes& confirmation_tag) const
{
  return confirmation_tag == opt::get(auth.confirmation_tag);
}

tls::ostream&
operator<<(tls::ostream& str, const MLSMessageContentAuth& obj)
{
  return str << obj.wire_format << obj.content << obj.auth;
}

tls::istream&
operator>>(tls::istream& str, MLSMessageContentAuth& obj)
{
  str >> obj.wire_format >> obj.content;

  obj.auth.content_type = obj.content.content_type();
  return str >> obj.auth;
}

bool
operator==(const MLSMessageContentAuth& lhs, const MLSMessageContentAuth& rhs)
{
  return lhs.wire_format == rhs.wire_format && lhs.content == rhs.content &&
         lhs.auth == rhs.auth;
}

MLSMessageContentAuth::MLSMessageContentAuth(WireFormat wire_format_in,
                                             MLSMessageContent content_in)
  : wire_format(wire_format_in)
  , content(std::move(content_in))
{
  auth.content_type = content.content_type();
}

MLSMessageContentAuth::MLSMessageContentAuth(WireFormat wire_format_in,
                                             MLSMessageContent content_in,
                                             MLSMessageAuth auth_in)
  : wire_format(wire_format_in)
  , content(std::move(content_in))
  , auth(std::move(auth_in))
{
}

struct MLSMessageContentTBS
{
  WireFormat wire_format = WireFormat::reserved;
  const MLSMessageContent& content;
  const std::optional<GroupContext>& context;
};

static tls::ostream&
operator<<(tls::ostream& str, const MLSMessageContentTBS& obj)
{
  str << ProtocolVersion::mls10 << obj.wire_format << obj.content;

  switch (obj.content.sender.sender_type()) {
    case SenderType::member:
    case SenderType::new_member:
      str << opt::get(obj.context);
      break;

    default:
      break;
  }

  return str;
}

bytes
MLSMessageContentAuth::to_be_signed(
  const std::optional<GroupContext>& context) const
{
  return tls::marshal(MLSMessageContentTBS{
    wire_format,
    content,
    context,
  });
}

MLSPlaintext
MLSPlaintext::protect(MLSMessageContentAuth content_auth,
                      CipherSuite suite,
                      const std::optional<bytes>& membership_key,
                      const std::optional<GroupContext>& context)
{
  auto pt = MLSPlaintext(std::move(content_auth));

  // Add the membership_mac if required
  switch (pt.content.sender.sender_type()) {
    case SenderType::member:
      pt.membership_tag =
        pt.membership_mac(suite, opt::get(membership_key), context);
      break;

    default:
      break;
  }

  return pt;
}

std::optional<MLSMessageContentAuth>
MLSPlaintext::unprotect(CipherSuite suite,
                        const std::optional<bytes>& membership_key,
                        const std::optional<GroupContext>& context) const
{
  // Verify the membership_tag if the message was sent within the group
  switch (content.sender.sender_type()) {
    case SenderType::member: {
      auto candidate = membership_mac(suite, opt::get(membership_key), context);
      if (candidate != opt::get(membership_tag)) {
        return std::nullopt;
      }
      break;
    }

    default:
      break;
  }

  return MLSMessageContentAuth{
    WireFormat::mls_plaintext,
    content,
    auth,
  };
}

MLSPlaintext::MLSPlaintext(MLSMessageContentAuth content_auth)
  : content(std::move(content_auth.content))
  , auth(std::move(content_auth.auth))
{
  if (content_auth.wire_format != WireFormat::mls_plaintext) {
    throw InvalidParameterError("Wire format mismatch (not mls_plaintext)");
  }
}

struct MLSMessageContentTBM
{
  MLSMessageContentTBS content_tbs;
  MLSMessageAuth auth;

  TLS_SERIALIZABLE(content_tbs, auth);
};

bytes
MLSPlaintext::membership_mac(CipherSuite suite,
                             const bytes& membership_key,
                             const std::optional<GroupContext>& context) const
{
  auto tbm = tls::marshal(MLSMessageContentTBM{
    { WireFormat::mls_plaintext, content, context },
    auth,
  });

  return suite.digest().hmac(membership_key, tbm);
}

tls::ostream&
operator<<(tls::ostream& str, const MLSPlaintext& obj)
{
  switch (obj.content.sender.sender_type()) {
    case SenderType::member:
      return str << obj.content << obj.auth << opt::get(obj.membership_tag);

    case SenderType::new_member:
    case SenderType::preconfigured:
      return str << obj.content << obj.auth;

    default:
      throw InvalidParameterError("Invalid sender type");
  }
}

tls::istream&
operator>>(tls::istream& str, MLSPlaintext& obj)
{
  str >> obj.content;

  obj.auth.content_type = obj.content.content_type();
  str >> obj.auth;

  if (obj.content.sender.sender_type() == SenderType::member) {
    obj.membership_tag.emplace();
    str >> opt::get(obj.membership_tag);
  }

  return str;
}

static bytes
marshal_ciphertext_content(const MLSMessageContent& content,
                           const MLSMessageAuth& auth,
                           size_t padding_size)
{
  auto w = tls::ostream{};
  var::visit([&w](const auto& val) { w << val; }, content.content);
  w << auth << bytes(padding_size, 0);
  return w.bytes();
}

static void
unmarshal_ciphertext_content(const bytes& content_pt,
                             MLSMessageContent& content,
                             MLSMessageAuth& auth)
{
  auto r = tls::istream(content_pt);

  auto padding = bytes{};
  var::visit([&r](auto& val) { r >> val; }, content.content);
  r >> auth >> padding;

  if (!r.empty()) {
    throw ProtocolError("Malformed MLSCiphertextContent");
  }
}

struct MLSCiphertextContentAAD
{
  const bytes& group_id;
  const epoch_t epoch;
  const ContentType content_type;
  const bytes& authenticated_data;

  TLS_SERIALIZABLE(group_id, epoch, content_type, authenticated_data)
};

struct MLSSenderData
{
  LeafNodeRef sender{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
  uint32_t generation{ 0 };
  ReuseGuard reuse_guard{ 0, 0, 0, 0 };

  TLS_SERIALIZABLE(sender, generation, reuse_guard)
};

struct MLSSenderDataAAD
{
  const bytes& group_id;
  const epoch_t epoch;
  const ContentType content_type;

  TLS_SERIALIZABLE(group_id, epoch, content_type)
};

MLSCiphertext
MLSCiphertext::protect(MLSMessageContentAuth content_auth,
                       CipherSuite suite,
                       const LeafIndex& index,
                       GroupKeySource& keys,
                       const bytes& sender_data_secret,
                       size_t padding_size)
{
  // Pull keys from the secret tree
  auto content_type = content_auth.content.content_type();
  auto [generation, reuse_guard, content_keys] = keys.next(content_type, index);

  // Encrypt the content
  auto content_pt = marshal_ciphertext_content(
    content_auth.content, content_auth.auth, padding_size);
  auto content_aad = tls::marshal(MLSCiphertextContentAAD{
    content_auth.content.group_id,
    content_auth.content.epoch,
    content_auth.content.content_type(),
    content_auth.content.authenticated_data,
  });

  auto content_ct = suite.hpke().aead.seal(
    content_keys.key, content_keys.nonce, content_aad, content_pt);

  // Encrypt the sender data
  auto sender_data_pt = tls::marshal(MLSSenderData{
    var::get<LeafNodeRef>(content_auth.content.sender.sender),
    generation,
    reuse_guard,
  });
  auto sender_data_aad = tls::marshal(MLSSenderDataAAD{
    content_auth.content.group_id,
    content_auth.content.epoch,
    content_auth.content.content_type(),
  });

  auto sender_data_keys =
    KeyScheduleEpoch::sender_data_keys(suite, sender_data_secret, content_ct);

  auto sender_data_ct = suite.hpke().aead.seal(sender_data_keys.key,
                                               sender_data_keys.nonce,
                                               sender_data_aad,
                                               sender_data_pt);

  return MLSCiphertext{
    std::move(content_auth.content),
    std::move(sender_data_ct),
    std::move(content_ct),
  };
}

std::optional<MLSMessageContentAuth>
MLSCiphertext::unprotect(CipherSuite suite,
                         const TreeKEMPublicKey& tree,
                         GroupKeySource& keys,
                         const bytes& sender_data_secret) const
{
  // Decrypt and parse the sender data
  auto sender_data_keys =
    KeyScheduleEpoch::sender_data_keys(suite, sender_data_secret, ciphertext);
  auto sender_data_aad = tls::marshal(MLSSenderDataAAD{
    group_id,
    epoch,
    content_type,
  });

  auto sender_data_pt = suite.hpke().aead.open(sender_data_keys.key,
                                               sender_data_keys.nonce,
                                               sender_data_aad,
                                               encrypted_sender_data);
  if (!sender_data_pt) {
    return std::nullopt;
  }

  auto sender_data = tls::get<MLSSenderData>(opt::get(sender_data_pt));
  auto maybe_sender = tree.find(sender_data.sender);
  if (!maybe_sender) {
    return std::nullopt;
  }

  auto sender = opt::get(maybe_sender);

  // Decrypt the content
  auto content_keys = keys.get(
    content_type, sender, sender_data.generation, sender_data.reuse_guard);
  keys.erase(content_type, sender, sender_data.generation);

  auto content_aad = tls::marshal(MLSCiphertextContentAAD{
    group_id,
    epoch,
    content_type,
    authenticated_data,
  });

  auto content_pt = suite.hpke().aead.open(
    content_keys.key, content_keys.nonce, content_aad, ciphertext);
  if (!content_pt) {
    return std::nullopt;
  }

  // Parse the content
  auto content = MLSMessageContent{
    group_id, epoch, { sender_data.sender }, authenticated_data, content_type
  };
  auto auth = MLSMessageAuth{ content_type, {}, {} };

  unmarshal_ciphertext_content(opt::get(content_pt), content, auth);

  return MLSMessageContentAuth{
    WireFormat::mls_ciphertext,
    std::move(content),
    std::move(auth),
  };
}

MLSCiphertext::MLSCiphertext(MLSMessageContent content,
                             bytes encrypted_sender_data_in,
                             bytes ciphertext_in)
  : group_id(std::move(content.group_id))
  , epoch(content.epoch)
  , content_type(content.content_type())
  , authenticated_data(std::move(content.authenticated_data))
  , encrypted_sender_data(std::move(encrypted_sender_data_in))
  , ciphertext(std::move(ciphertext_in))
{
}

epoch_t
MLSMessage::epoch() const
{
  return var::visit(
    overloaded{
      [](const MLSPlaintext& pt) -> epoch_t { return pt.get_epoch(); },
      [](const MLSCiphertext& pt) -> epoch_t { return pt.get_epoch(); },
      [](const auto& /* unused */) -> epoch_t {
        throw InvalidParameterError("MLSMessage has no epoch");
      },
    },
    message);
}

WireFormat
MLSMessage::wire_format() const
{
  return tls::variant<WireFormat>::type(message);
}

MLSMessage::MLSMessage(MLSPlaintext mls_plaintext)
  : message(std::move(mls_plaintext))
{
}

MLSMessage::MLSMessage(MLSCiphertext mls_ciphertext)
  : message(std::move(mls_ciphertext))
{
}

MLSMessage::MLSMessage(Welcome welcome)
  : message(std::move(welcome))
{
}

MLSMessage::MLSMessage(GroupInfo group_info)
  : message(std::move(group_info))
{
}

MLSMessage::MLSMessage(KeyPackage key_package)
  : message(std::move(key_package))
{
}

} // namespace mls
