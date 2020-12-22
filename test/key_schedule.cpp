#include "test_vectors.h"
#include <doctest/doctest.h>
#include <mls/state.h>
#include <mls_vectors/mls_vectors.h>

using namespace mls;
using namespace mls_vectors;

TEST_CASE("Encryption Keys Interop")
{
  for (auto suite : all_cipher_suites) {
    const auto tv = EncryptionKeyTestVector(suite, 15, 10);
    REQUIRE(tv.verify() == std::nullopt);
  }
}

TEST_CASE("Key Schedule Interop")
{
  const auto& tv = TestLoader<KeyScheduleTestVectors>::get();

  for (const auto& tc : tv.cases) {
    auto suite = tc.cipher_suite;
    auto secret_size = suite.get().hpke.kdf.hash_size();
    bytes init_secret(secret_size, 0);

    auto group_context = tls::get<GroupContext>(tv.base_group_context);

    KeyScheduleEpoch my_epoch;
    my_epoch.suite = suite;
    my_epoch.init_secret = tv.base_init_secret;

    for (const auto& epoch : tc.epochs) {
      auto ctx = tls::marshal(group_context);
      my_epoch = my_epoch.next(epoch.commit_secret, {}, ctx, epoch.n_members);

      // Check the secrets
      REQUIRE(my_epoch.epoch_secret == epoch.epoch_secret);
      REQUIRE(my_epoch.sender_data_secret == epoch.sender_data_secret);
      REQUIRE(my_epoch.encryption_secret == epoch.encryption_secret);
      REQUIRE(my_epoch.exporter_secret == epoch.exporter_secret);
      REQUIRE(my_epoch.authentication_secret == epoch.authentication_secret);
      REQUIRE(my_epoch.external_secret == epoch.external_secret);
      REQUIRE(my_epoch.confirmation_key == epoch.confirmation_key);
      REQUIRE(my_epoch.membership_key == epoch.membership_key);
      REQUIRE(my_epoch.resumption_secret == epoch.resumption_secret);
      REQUIRE(my_epoch.init_secret == epoch.init_secret);

      // Check the derived keys
      REQUIRE(my_epoch.external_priv.public_key == epoch.external_pub);

      static const auto key_type_hs = GroupKeySource::RatchetType::handshake;
      static const auto key_type_app = GroupKeySource::RatchetType::application;
      for (LeafIndex i{ 0 }; i.val < epoch.n_members.val; i.val += 1) {
        auto hs = my_epoch.keys.get(key_type_hs, i, tv.target_generation);
        REQUIRE(hs.key == epoch.handshake_keys[i.val].key);
        REQUIRE(hs.nonce == epoch.handshake_keys[i.val].nonce);

        auto app = my_epoch.keys.get(key_type_app, i, tv.target_generation);
        REQUIRE(app.key == epoch.application_keys[i.val].key);
        REQUIRE(app.nonce == epoch.application_keys[i.val].nonce);
      }

      auto [sender_data_key, sender_data_nonce] =
        my_epoch.sender_data(tv.ciphertext);
      REQUIRE(sender_data_key == epoch.sender_data_key);
      REQUIRE(sender_data_nonce == epoch.sender_data_nonce);

      group_context.epoch += 1;
    }
  }
}
