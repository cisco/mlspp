#include "messages.h"
#include "key_schedule.h"
#include "state.h"

// Variant type selectors in the `tls` namespace
namespace tls {
using namespace mls;

// ProposalType
template<>
ProposalType variant_value<ProposalType, Add> = ProposalType::add;

template<>
ProposalType variant_value<ProposalType, Update> = ProposalType::update;

template<>
ProposalType variant_value<ProposalType, Remove> = ProposalType::remove;

// ContentType
template<>
ContentType variant_value<ContentType, ApplicationData> =
  ContentType::application;

template<>
ContentType variant_value<ContentType, Proposal> = ContentType::proposal;

template<>
ContentType variant_value<ContentType, CommitData> = ContentType::commit;

} // namespace tls

namespace mls {

// KeyPackage

KeyPackage::KeyPackage()
  : version(ProtocolVersion::mls10)
  , cipher_suite(CipherSuite::unknown)
{}

KeyPackage::KeyPackage(CipherSuite suite_in,
                       const HPKEPublicKey& init_key_in,
                       const SignaturePrivateKey& sig_priv_in,
                       const Credential& credential_in)
  : version(ProtocolVersion::mls10)
  , cipher_suite(suite_in)
  , init_key(init_key_in)
  , credential(credential_in)
{
  auto tbs = to_be_signed();
  signature = sig_priv_in.sign(tbs);
}

bytes
KeyPackage::hash() const
{
  auto marshaled = tls::marshal(*this);
  return Digest(cipher_suite).write(marshaled).digest();
}

bool
KeyPackage::verify() const
{
  auto tbs = to_be_signed();
  auto identity_key = credential.public_key();
  return identity_key.verify(tbs, signature);
}

bytes
KeyPackage::to_be_signed() const
{
  tls::ostream out;
  out << version << cipher_suite << init_key << credential;
  return out.bytes();
}

// GroupInfo

GroupInfo::GroupInfo(CipherSuite suite)
  : epoch(0)
  , tree(suite)
{}

GroupInfo::GroupInfo(bytes group_id_in,
                     epoch_t epoch_in,
                     RatchetTree tree_in,
                     bytes prior_confirmed_transcript_hash_in,
                     bytes confirmed_transcript_hash_in,
                     bytes interim_transcript_hash_in,
                     DirectPath path_in,
                     bytes confirmation_in)
  : group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , tree(std::move(tree_in))
  , prior_confirmed_transcript_hash(
      std::move(prior_confirmed_transcript_hash_in))
  , confirmed_transcript_hash(std::move(confirmed_transcript_hash_in))
  , interim_transcript_hash(std::move(interim_transcript_hash_in))
  , path(std::move(path_in))
  , confirmation(std::move(confirmation_in))
{}

bytes
GroupInfo::to_be_signed() const
{
  tls::ostream w;
  tls::vector<1>{}.encode(w, group_id);
  w << epoch << tree;
  tls::vector<1>{}.encode(w, confirmed_transcript_hash);
  tls::vector<1>{}.encode(w, interim_transcript_hash);
  w << path;
  tls::vector<1>{}.encode(w, confirmation);
  w << signer_index;
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

// Welcome

Welcome::Welcome()
  : version(ProtocolVersion::mls10)
  , cipher_suite(CipherSuite::unknown)
{}

Welcome::Welcome(CipherSuite suite,
                 bytes init_secret,
                 const GroupInfo& group_info)
  : version(ProtocolVersion::mls10)
  , cipher_suite(suite)
  , _init_secret(std::move(init_secret))
{
  auto first_epoch = FirstEpoch::create(cipher_suite, _init_secret);
  auto group_info_data = tls::marshal(group_info);
  encrypted_group_info = seal(cipher_suite,
                              first_epoch.group_info_key,
                              first_epoch.group_info_nonce,
                              {},
                              group_info_data);
}

void
Welcome::encrypt(const KeyPackage& kp)
{
  auto gs = GroupSecrets{ _init_secret };
  auto gs_data = tls::marshal(gs);
  auto enc_gs = kp.init_key.encrypt(kp.cipher_suite, {}, gs_data);
  secrets.push_back({ kp.hash(), enc_gs });
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

// MLSPlaintext

MLSPlaintext::MLSPlaintext(bytes group_id_in,
                           epoch_t epoch_in,
                           LeafIndex sender_in,
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
  tls::vector<2>{}.decode(r, signature);
  tls::vector<2>{}.decode(r, padding);
}

MLSPlaintext::MLSPlaintext(bytes group_id_in,
                           epoch_t epoch_in,
                           LeafIndex sender_in,
                           const ApplicationData& application_data_in)
  : group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , sender(sender_in)
  , content(application_data_in)
{}

MLSPlaintext::MLSPlaintext(bytes group_id_in,
                           epoch_t epoch_in,
                           LeafIndex sender_in,
                           const Proposal& proposal)
  : group_id(std::move(group_id_in))
  , epoch(epoch_in)
  , sender(sender_in)
  , content(proposal)
{}

MLSPlaintext::MLSPlaintext(bytes group_id_in,
                           epoch_t epoch_in,
                           LeafIndex sender_in,
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
  tls::vector<2>{}.encode(w, signature);
  tls::vector<2>{}.encode(w, padding);
  return w.bytes();
}

bytes
MLSPlaintext::commit_content() const
{
  auto& commit_data = std::get<CommitData>(content);
  tls::ostream w;
  tls::vector<1>{}.encode(w, group_id);
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
  auto& commit_data = std::get<CommitData>(content);
  tls::ostream w;
  tls::vector<1>{}.encode(w, commit_data.confirmation);
  tls::vector<2>{}.encode(w, signature);
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
MLSPlaintext::sign(const GroupContext& context, const SignaturePrivateKey& priv)
{
  auto tbs = to_be_signed(context);
  signature = priv.sign(tbs);
}

bool
MLSPlaintext::verify(const GroupContext& context,
                     const SignaturePublicKey& pub) const
{
  auto tbs = to_be_signed(context);
  return pub.verify(tbs, signature);
}

} // namespace mls
