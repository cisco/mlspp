#include "common.h"
#include <mls_vectors/mls_vectors.h>

namespace mls_vectors {

using namespace mls;

TranscriptTestVector::TranscriptTestVector(CipherSuite suite)
  : PseudoRandom(suite, "transcript")
  , cipher_suite(suite)
  , interim_transcript_hash_before(prg.secret("interim_transcript_hash_before"))
{
  auto transcript = TranscriptHash(suite);
  transcript.interim = interim_transcript_hash_before;

  auto group_id = prg.secret("group_id");
  auto epoch = prg.uint64("epoch");
  auto group_context_obj =
    GroupContext{ suite,
                  group_id,
                  epoch,
                  prg.secret("tree_hash_before"),
                  prg.secret("confirmed_transcript_hash_before"),
                  {} };
  auto group_context = tls::marshal(group_context_obj);

  auto init_secret = prg.secret("init_secret");
  auto ks_epoch = KeyScheduleEpoch(suite, init_secret, group_context);

  auto sig_priv = prg.signature_key("sig_priv");
  auto leaf_index = LeafIndex{ 0 };

  authenticated_content = AuthenticatedContent::sign(
    WireFormat::mls_plaintext,
    GroupContent{
      group_id, epoch, { MemberSender{ leaf_index } }, {}, Commit{} },
    suite,
    sig_priv,
    group_context_obj);

  transcript.update_confirmed(authenticated_content);

  const auto confirmation_tag = ks_epoch.confirmation_tag(transcript.confirmed);
  authenticated_content.set_confirmation_tag(confirmation_tag);

  transcript.update_interim(authenticated_content);

  // Store the required data
  confirmation_key = ks_epoch.confirmation_key;
  confirmed_transcript_hash_after = transcript.confirmed;
  interim_transcript_hash_after = transcript.interim;
}

std::optional<std::string>
TranscriptTestVector::verify() const
{
  auto transcript = TranscriptHash(cipher_suite);
  transcript.interim = interim_transcript_hash_before;

  transcript.update(authenticated_content);
  VERIFY_EQUAL(
    "confirmed", transcript.confirmed, confirmed_transcript_hash_after);
  VERIFY_EQUAL("interim", transcript.interim, interim_transcript_hash_after);

  auto confirmation_tag =
    cipher_suite.digest().hmac(confirmation_key, transcript.confirmed);
  VERIFY_EQUAL("confirmation tag",
               confirmation_tag,
               authenticated_content.auth.confirmation_tag);

  return std::nullopt;
}

} // namespace mls_vectors
