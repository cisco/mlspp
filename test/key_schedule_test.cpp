#include "state.h"
#include "test_vectors.h"
#include <gtest/gtest.h>

using namespace mls;

class HashRatchetTest : public ::testing::Test
{
protected:
  const HashRatchetTestVectors& tv;

  HashRatchetTest()
    : tv(TestLoader<HashRatchetTestVectors>::get())
  {}

  void interop(CipherSuite suite, const HashRatchetTestVectors::TestCase& tc)
  {
    ASSERT_EQ(tc.size(), tv.n_members);
    for (uint32_t j = 0; j < tv.n_members; ++j) {
      HashRatchet ratchet{ suite, NodeIndex{ LeafIndex{ j } }, tv.base_secret };
      ASSERT_EQ(tc[j].size(), tv.n_generations);
      for (uint32_t k = 0; k < tv.n_generations; ++k) {
        auto kn = ratchet.get(k);
        ASSERT_EQ(tc[j][k].key, kn.key);
        ASSERT_EQ(tc[j][k].nonce, kn.nonce);
      }
    }
  }
};

TEST_F(HashRatchetTest, Interop)
{
  interop(CipherSuite::P256_SHA256_AES128GCM, tv.case_p256);
  interop(CipherSuite::X25519_SHA256_AES128GCM, tv.case_x25519);
}

class KeyScheduleTest : public ::testing::Test
{
protected:
  const KeyScheduleTestVectors& tv;

  KeyScheduleTest()
    : tv(TestLoader<KeyScheduleTestVectors>::get())
  {}

  void interop(const KeyScheduleTestVectors::TestCase& test_case)
  {
    auto suite = test_case.suite;
    auto secret_size = Digest(suite).output_size();
    bytes init_secret(secret_size, 0);

    auto group_context = tls::get<GroupContext>(tv.base_group_context);

    KeyScheduleEpoch my_epoch;
    my_epoch.suite = suite;
    my_epoch.init_secret = tv.base_init_secret;

    for (const auto& epoch : test_case.epochs) {
      auto ctx = tls::marshal(group_context);
      my_epoch = my_epoch.next(epoch.n_members, epoch.update_secret, ctx);

      // Check the secrets
      ASSERT_EQ(my_epoch.epoch_secret, epoch.epoch_secret);
      ASSERT_EQ(my_epoch.sender_data_secret, epoch.sender_data_secret);
      ASSERT_EQ(my_epoch.sender_data_key, epoch.sender_data_key);

      ASSERT_EQ(my_epoch.handshake_secret, epoch.handshake_secret);
      ASSERT_EQ(my_epoch.application_secret, epoch.application_secret);

      ASSERT_EQ(my_epoch.confirmation_key, epoch.confirmation_key);
      ASSERT_EQ(my_epoch.init_secret, epoch.init_secret);

      // Check the derived keys
      for (LeafIndex i{ 0 }; i.val < epoch.n_members.val; i.val += 1) {
        auto hs = my_epoch.handshake_keys.get(i, tv.target_generation);
        ASSERT_EQ(hs.key, epoch.handshake_keys[i.val].key);
        ASSERT_EQ(hs.nonce, epoch.handshake_keys[i.val].nonce);

        auto app = my_epoch.application_keys.get(i, tv.target_generation);
        ASSERT_EQ(app.key, epoch.application_keys[i.val].key);
        ASSERT_EQ(app.nonce, epoch.application_keys[i.val].nonce);
      }

      group_context.epoch += 1;
    }
  }
};

TEST_F(KeyScheduleTest, Interop)
{
  interop(tv.case_p256);
  interop(tv.case_x25519);
}
