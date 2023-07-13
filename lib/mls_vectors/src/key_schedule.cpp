#include "common.h"
#include <mls_vectors/mls_vectors.h>

namespace mls_vectors {

using namespace mls;

KeyScheduleTestVector::KeyScheduleTestVector(CipherSuite suite,
                                             uint32_t n_epochs)
  : PseudoRandom(suite, "key-schedule")
  , cipher_suite(suite)
  , group_id(prg.secret("group_id"))
  , initial_init_secret(prg.secret("group_id"))
{
  auto group_context = GroupContext{ suite, group_id, 0, {}, {}, {} };
  auto epoch = KeyScheduleEpoch(cipher_suite);
  epoch.init_secret = initial_init_secret;

  for (uint64_t i = 0; i < n_epochs; i++) {
    auto epoch_prg = prg.sub(to_hex(tls::marshal(i)));

    group_context.tree_hash = epoch_prg.secret("tree_hash");
    group_context.confirmed_transcript_hash =
      epoch_prg.secret("confirmed_transcript_hash");
    auto ctx = tls::marshal(group_context);

    // TODO(RLB) Add Test case for externally-driven epoch change
    auto commit_secret = epoch_prg.secret("commit_secret");
    auto psk_secret = epoch_prg.secret("psk_secret");
    epoch = epoch.next_raw(commit_secret, psk_secret, std::nullopt, ctx);

    auto welcome_secret = KeyScheduleEpoch::welcome_secret_raw(
      cipher_suite, epoch.joiner_secret, psk_secret);

    auto exporter_prg = epoch_prg.sub("exporter");
    auto exporter_label = to_hex(exporter_prg.secret("label"));
    auto exporter_context = exporter_prg.secret("context");
    auto exporter_length = cipher_suite.secret_size();
    auto exported =
      epoch.do_export(exporter_label, exporter_context, exporter_length);

    epochs.push_back({ group_context.tree_hash,
                       commit_secret,
                       psk_secret,
                       group_context.confirmed_transcript_hash,

                       ctx,

                       epoch.joiner_secret,
                       welcome_secret,
                       epoch.init_secret,

                       epoch.sender_data_secret,
                       epoch.encryption_secret,
                       epoch.exporter_secret,
                       epoch.epoch_authenticator,
                       epoch.external_secret,
                       epoch.confirmation_key,
                       epoch.membership_key,
                       epoch.resumption_psk,

                       epoch.external_priv.public_key,

                       {
                         exporter_label,
                         exporter_context,
                         exporter_length,
                         exported,
                       } });

    group_context.epoch += 1;
  }
}

std::optional<std::string>
KeyScheduleTestVector::verify() const
{
  auto group_context = GroupContext{ cipher_suite, group_id, 0, {}, {}, {} };
  auto epoch = KeyScheduleEpoch(cipher_suite);
  epoch.init_secret = initial_init_secret;

  for (const auto& tve : epochs) {
    group_context.tree_hash = tve.tree_hash;
    group_context.confirmed_transcript_hash = tve.confirmed_transcript_hash;
    auto ctx = tls::marshal(group_context);
    VERIFY_EQUAL("group context", ctx, tve.group_context);

    epoch =
      epoch.next_raw(tve.commit_secret, tve.psk_secret, std::nullopt, ctx);

    // Verify the rest of the epoch
    VERIFY_EQUAL("joiner secret", epoch.joiner_secret, tve.joiner_secret);

    auto welcome_secret = KeyScheduleEpoch::welcome_secret_raw(
      cipher_suite, tve.joiner_secret, tve.psk_secret);
    VERIFY_EQUAL("welcome secret", welcome_secret, tve.welcome_secret);

    VERIFY_EQUAL(
      "sender data secret", epoch.sender_data_secret, tve.sender_data_secret);
    VERIFY_EQUAL(
      "encryption secret", epoch.encryption_secret, tve.encryption_secret);
    VERIFY_EQUAL("exporter secret", epoch.exporter_secret, tve.exporter_secret);
    VERIFY_EQUAL("epoch authenticator",
                 epoch.epoch_authenticator,
                 tve.epoch_authenticator);
    VERIFY_EQUAL("external secret", epoch.external_secret, tve.external_secret);
    VERIFY_EQUAL(
      "confirmation key", epoch.confirmation_key, tve.confirmation_key);
    VERIFY_EQUAL("membership key", epoch.membership_key, tve.membership_key);
    VERIFY_EQUAL("resumption psk", epoch.resumption_psk, tve.resumption_psk);
    VERIFY_EQUAL("init secret", epoch.init_secret, tve.init_secret);

    VERIFY_EQUAL(
      "external pub", epoch.external_priv.public_key, tve.external_pub);

    auto exported = epoch.do_export(
      tve.exporter.label, tve.exporter.context, tve.exporter.length);
    VERIFY_EQUAL("exported", exported, tve.exporter.secret);

    group_context.epoch += 1;
  }

  return std::nullopt;
}

} // namespace mls_vectors
