#include "common.h"
#include <mls_vectors/mls_vectors.h>

namespace mls_vectors {

using namespace mls;

MessageProtectionTestVector::MessageProtectionTestVector(CipherSuite suite)
  : PseudoRandom(suite, "message-protection")
  , cipher_suite(suite)
  , group_id(prg.secret("group_id"))
  , epoch(prg.uint64("epoch"))
  , tree_hash(prg.secret("tree_hash"))
  , confirmed_transcript_hash(prg.secret("confirmed_transcript_hash"))
  , signature_priv(prg.signature_key("signature_priv"))
  , signature_pub(signature_priv.public_key)
  , encryption_secret(prg.secret("encryption_secret"))
  , sender_data_secret(prg.secret("sender_data_secret"))
  , membership_key(prg.secret("membership_key"))
  , proposal{ GroupContextExtensions{} }
  , commit{ /* XXX(RLB) this is technically invalid, empty w/o path */ }
  , application{ prg.secret("application") }
{
  proposal_pub = protect_pub(proposal);
  proposal_priv = protect_priv(proposal);

  commit_pub = protect_pub(commit);
  commit_priv = protect_priv(commit);

  application_priv = protect_priv(ApplicationData{ application });
}

std::optional<std::string>
MessageProtectionTestVector::verify()
{
  // Initialize fields that don't get set from JSON
  prg = PseudoRandom::Generator(cipher_suite, "message-protection");
  signature_priv.set_public_key(cipher_suite);

  // Sanity check the key pairs
  VERIFY_EQUAL("sig kp", signature_priv.public_key, signature_pub);

  // Verify proposal unprotect as PublicMessage
  auto proposal_pub_unprotected = unprotect(proposal_pub);
  VERIFY("proposal pub unprotect auth", proposal_pub_unprotected);
  VERIFY_EQUAL("proposal pub unprotect",
               opt::get(proposal_pub_unprotected).content,
               proposal);

  // Verify proposal unprotect as PrivateMessage
  auto proposal_priv_unprotected = unprotect(proposal_priv);
  VERIFY("proposal priv unprotect auth", proposal_priv_unprotected);
  VERIFY_EQUAL("proposal priv unprotect",
               opt::get(proposal_priv_unprotected).content,
               proposal);

  // Verify commit unprotect as PublicMessage
  auto commit_pub_unprotected = unprotect(commit_pub);
  VERIFY("commit pub unprotect auth", commit_pub_unprotected);
  VERIFY_EQUAL(
    "commit pub unprotect", opt::get(commit_pub_unprotected).content, commit);

  // Verify commit unprotect as PrivateMessage
  auto commit_priv_unprotected = unprotect(commit_priv);
  VERIFY("commit priv unprotect auth", commit_priv_unprotected);
  VERIFY_EQUAL(
    "commit priv unprotect", opt::get(commit_priv_unprotected).content, commit);

  // Verify application data unprotect as PrivateMessage
  auto app_unprotected = unprotect(application_priv);
  VERIFY("app priv unprotect auth", app_unprotected);
  VERIFY_EQUAL("app priv unprotect",
               opt::get(app_unprotected).content,
               ApplicationData{ application });

  // Verify protect/unprotect round-trips
  // XXX(RLB): Note that because (a) unprotect() deletes keys from the ratchet
  // and (b) we are using the same ratchet to send and receive, we need to do
  // these round-trip tests after all the unprotect tests are done.  Otherwise
  // the protect() calls here will re-use generations used the test vector, and
  // then unprotect() will delete the keys, then when you go to decrypt the test
  // vector object, you'll get "expired key".  It might be good to have better
  // safeguards around such reuse.
  auto proposal_pub_protected = protect_pub(proposal);
  auto proposal_pub_protected_unprotected = unprotect(proposal_pub_protected);
  VERIFY("proposal pub protect/unprotect auth",
         proposal_pub_protected_unprotected);
  VERIFY_EQUAL("proposal pub protect/unprotect",
               opt::get(proposal_pub_protected_unprotected).content,
               proposal);

  auto proposal_priv_protected = protect_priv(proposal);
  auto proposal_priv_protected_unprotected = unprotect(proposal_priv_protected);
  VERIFY("proposal priv protect/unprotect auth",
         proposal_priv_protected_unprotected);
  VERIFY_EQUAL("proposal priv protect/unprotect",
               opt::get(proposal_priv_protected_unprotected).content,
               proposal);

  auto commit_pub_protected = protect_pub(commit);
  auto commit_pub_protected_unprotected = unprotect(commit_pub_protected);
  VERIFY("commit pub protect/unprotect auth", commit_pub_protected_unprotected);
  VERIFY_EQUAL("commit pub protect/unprotect",
               opt::get(commit_pub_protected_unprotected).content,
               commit);

  auto commit_priv_protected = protect_priv(commit);
  auto commit_priv_protected_unprotected = unprotect(commit_priv_protected);
  VERIFY("commit priv protect/unprotect auth",
         commit_priv_protected_unprotected);
  VERIFY_EQUAL("commit priv protect/unprotect",
               opt::get(commit_priv_protected_unprotected).content,
               commit);

  auto app_protected = protect_priv(ApplicationData{ application });
  auto app_protected_unprotected = unprotect(app_protected);
  VERIFY("app priv protect/unprotect auth", app_protected_unprotected);
  VERIFY_EQUAL("app priv protect/unprotect",
               opt::get(app_protected_unprotected).content,
               ApplicationData{ application });

  return std::nullopt;
}

GroupKeySource
MessageProtectionTestVector::group_keys() const
{
  return { cipher_suite, LeafCount{ 2 }, encryption_secret };
}

GroupContext
MessageProtectionTestVector::group_context() const
{
  return GroupContext{
    cipher_suite, group_id, epoch, tree_hash, confirmed_transcript_hash, {}
  };
}

MLSMessage
MessageProtectionTestVector::protect_pub(
  const mls::GroupContent::RawContent& raw_content) const
{
  auto sender = Sender{ MemberSender{ LeafIndex{ 1 } } };
  auto authenticated_data = bytes{};

  auto content =
    GroupContent{ group_id, epoch, sender, authenticated_data, raw_content };

  auto auth_content = AuthenticatedContent::sign(WireFormat::mls_plaintext,
                                                 content,
                                                 cipher_suite,
                                                 signature_priv,
                                                 group_context());
  if (content.content_type() == ContentType::commit) {
    auto confirmation_tag = prg.secret("confirmation_tag");
    auth_content.set_confirmation_tag(confirmation_tag);
  }

  return PublicMessage::protect(
    auth_content, cipher_suite, membership_key, group_context());
}

MLSMessage
MessageProtectionTestVector::protect_priv(
  const mls::GroupContent::RawContent& raw_content)
{
  auto sender = Sender{ MemberSender{ LeafIndex{ 1 } } };
  auto authenticated_data = bytes{};
  auto padding_size = size_t(0);

  auto content =
    GroupContent{ group_id, epoch, sender, authenticated_data, raw_content };

  auto auth_content = AuthenticatedContent::sign(WireFormat::mls_ciphertext,
                                                 content,
                                                 cipher_suite,
                                                 signature_priv,
                                                 group_context());
  if (content.content_type() == ContentType::commit) {
    auto confirmation_tag = prg.secret("confirmation_tag");
    auth_content.set_confirmation_tag(confirmation_tag);
  }

  auto keys = group_keys();
  return PrivateMessage::protect(
    auth_content, cipher_suite, keys, sender_data_secret, padding_size);
}

std::optional<GroupContent>
MessageProtectionTestVector::unprotect(const MLSMessage& message)
{
  auto do_unprotect = overloaded{
    [&](const PublicMessage& pt) {
      return pt.unprotect(cipher_suite, membership_key, group_context());
    },
    [&](const PrivateMessage& ct) {
      auto keys = group_keys();
      return ct.unprotect(cipher_suite, keys, sender_data_secret);
    },
    [](const auto& /* other */) -> std::optional<AuthenticatedContent> {
      return std::nullopt;
    }
  };

  auto maybe_auth_content = var::visit(do_unprotect, message.message);
  if (!maybe_auth_content) {
    return std::nullopt;
  }

  auto auth_content = opt::get(maybe_auth_content);
  if (!auth_content.verify(cipher_suite, signature_pub, group_context())) {
    return std::nullopt;
  }

  return auth_content.content;
}

} // namespace mls_vectors
