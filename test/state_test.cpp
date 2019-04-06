#include "state.h"
#include "test_vectors.h"
#include <gtest/gtest.h>

using namespace mls;

class AppKeyScheduleTest : public ::testing::Test
{
protected:
  const AppKeyScheduleTestVectors& tv;

  AppKeyScheduleTest()
    : tv(TestLoader<AppKeyScheduleTestVectors>::get())
  {}

  void interop(CipherSuite suite, const AppKeyScheduleTestVectors::TestCase& tc)
  {
    ASSERT_EQ(tc.size(), tv.n_members);
    for (uint32_t j = 0; j < tv.n_members; ++j) {
      ApplicationKeyChain chain(suite, j, tv.application_secret);

      ASSERT_EQ(tc[j].size(), tv.n_generations);
      for (uint32_t k = 0; k < tv.n_generations; ++k) {
        auto kn = chain.get(k);
        ASSERT_EQ(tc[j][k].secret, kn.secret);
        ASSERT_EQ(tc[j][k].key, kn.key);
        ASSERT_EQ(tc[j][k].nonce, kn.nonce);
      }
    }
  }
};

TEST_F(AppKeyScheduleTest, Interop)
{
  interop(CipherSuite::P256_SHA256_AES128GCM, tv.case_p256);
  interop(CipherSuite::X25519_SHA256_AES128GCM, tv.case_x25519);
}

class StateTest : public ::testing::Test
{
protected:
  const CipherSuite suite = CipherSuite::P256_SHA256_AES128GCM;
  const SignatureScheme scheme = SignatureScheme::P256_SHA256;

  const size_t group_size = 5;
  const bytes group_id = { 0, 1, 2, 3 };
  const bytes user_id = { 4, 5, 6, 7 };
};

class GroupCreationTest : public StateTest
{
protected:
  std::vector<SignaturePrivateKey> identity_privs;
  std::vector<Credential> credentials;
  std::vector<bytes> init_secrets;
  std::vector<UserInitKey> user_init_keys;
  std::vector<State> states;

  GroupCreationTest()
  {
    for (size_t i = 0; i < group_size; i += 1) {
      auto identity_priv = SignaturePrivateKey::generate(scheme);
      auto credential = Credential::basic(user_id, identity_priv);
      auto init_secret = random_bytes(32);
      auto init_priv = DHPrivateKey::node_derive(suite, init_secret);

      auto user_init_key = UserInitKey{};
      user_init_key.add_init_key(init_priv.public_key());
      user_init_key.sign(identity_priv, credential);

      identity_privs.push_back(identity_priv);
      credentials.push_back(credential);
      init_secrets.push_back(init_secret);
      user_init_keys.push_back(user_init_key);
    }
  }
};

TEST_F(GroupCreationTest, TwoPerson)
{
  // Initialize the creator's state
  auto first = State{
    group_id, suite, init_secrets[0], identity_privs[0], credentials[0]
  };

  // Create a Add for the new participant
  auto welcome_add = first.add(user_init_keys[1]);
  auto welcome = welcome_add.first;
  auto add = welcome_add.second;

  // Process the Add
  first = first.handle(add);
  auto second =
    State{ identity_privs[1], credentials[1], init_secrets[1], welcome, add };

  ASSERT_EQ(first, second);
}

TEST_F(GroupCreationTest, FullSize)
{
  // Initialize the creator's state
  states.emplace_back(
    group_id, suite, init_secrets[0], identity_privs[0], credentials[0]);

  // Each participant invites the next
  for (size_t i = 1; i < group_size; i += 1) {
    auto welcome_add = states[i - 1].add(user_init_keys[i]);
    auto welcome = welcome_add.first;
    auto add = welcome_add.second;

    for (auto& state : states) {
      state = state.handle(add);
    }

    states.emplace_back(
      identity_privs[i], credentials[i], init_secrets[i], welcome, add);

    // Check that everyone ended up in the same place
    for (const auto& state : states) {
      ASSERT_EQ(state, states[0]);
    }
  }
}

class RunningGroupTest : public StateTest
{
protected:
  std::vector<State> states;

  RunningGroupTest()
  {
    states.reserve(group_size);

    auto init_secret_0 = random_bytes(32);
    auto identity_priv_0 = SignaturePrivateKey::generate(scheme);
    auto credential_0 = Credential::basic(user_id, identity_priv_0);
    states.emplace_back(
      group_id, suite, init_secret_0, identity_priv_0, credential_0);

    for (size_t i = 1; i < group_size; i += 1) {
      auto init_secret = random_bytes(32);
      auto init_priv = DHPrivateKey::node_derive(suite, init_secret);
      auto identity_priv = SignaturePrivateKey::generate(scheme);
      auto credential = Credential::basic(user_id, identity_priv);

      UserInitKey uik;
      uik.add_init_key(init_priv.public_key());
      uik.sign(identity_priv, credential);

      auto welcome_add = states[0].add(uik);
      for (auto& state : states) {
        state = state.handle(welcome_add.second);
      }

      states.emplace_back(identity_priv,
                          credential,
                          init_secret,
                          welcome_add.first,
                          welcome_add.second);
    }
  }

  void SetUp() override { check_consistency(); }

  void check_consistency()
  {
    for (const auto& state : states) {
      ASSERT_EQ(state, states[0]);
    }
  }
};

TEST_F(RunningGroupTest, Update)
{
  for (size_t i = 0; i < group_size; i += 1) {
    auto new_leaf = random_bytes(32);
    auto update = states[i].update(new_leaf);

    for (size_t j = 0; j < group_size; j += 1) {
      states[j] = states[j].handle(update);
    }

    check_consistency();
  }
}

TEST_F(RunningGroupTest, Remove)
{
  for (int i = group_size - 2; i > 0; i -= 1) {
    auto evict_secret = random_bytes(32);
    auto remove = states[i].remove(evict_secret, i + 1);
    states.pop_back();

    for (auto& state : states) {
      state = state.handle(remove);
    }

    check_consistency();
  }
}

TEST(OtherStateTest, CipherNegotiation)
{
  // Alice supports P-256 and X25519
  auto idkA = SignaturePrivateKey::generate(SignatureScheme::Ed25519);
  auto credA = Credential::basic({ 0, 1, 2, 3 }, idkA);
  auto insA = bytes{ 0, 1, 2, 3 };
  auto inkA1 =
    DHPrivateKey::node_derive(CipherSuite::P256_SHA256_AES128GCM, insA);
  auto inkA2 =
    DHPrivateKey::node_derive(CipherSuite::X25519_SHA256_AES128GCM, insA);

  auto uikA = UserInitKey{};
  uikA.add_init_key(inkA1.public_key());
  uikA.add_init_key(inkA2.public_key());
  uikA.sign(idkA, credA);

  // Bob spuports P-256 and P-521
  auto supported_ciphers =
    std::vector<CipherSuite>{ CipherSuite::P256_SHA256_AES128GCM,
                              CipherSuite::P521_SHA512_AES256GCM };
  auto idkB = SignaturePrivateKey::generate(SignatureScheme::Ed25519);
  auto credB = Credential::basic({ 4, 5, 6, 7 }, idkB);
  auto insB = bytes{ 4, 5, 6, 7 };
  auto group_id = bytes{ 0, 1, 2, 3, 4, 5, 6, 7 };

  // Bob should choose P-256
  auto initialB =
    State::negotiate(group_id, supported_ciphers, insB, idkB, credB, uikA);
  auto stateB = initialB.first;
  ASSERT_EQ(stateB.cipher_suite(), CipherSuite::P256_SHA256_AES128GCM);

  // Alice should also arrive at P-256 when initialized
  auto welcome = initialB.second.first;
  auto add = initialB.second.second;
  auto stateA = State(idkA, credA, insA, welcome, add);
  ASSERT_EQ(stateA, stateB);
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

    GroupState group_state(suite);
    tls::unmarshal(tv.base_group_state, group_state);

    for (const auto& epoch : test_case.epochs) {
      auto secrets = State::derive_epoch_secrets(
        suite, init_secret, epoch.update_secret, group_state);
      ASSERT_EQ(epoch.epoch_secret, secrets.epoch_secret);
      ASSERT_EQ(epoch.application_secret, secrets.application_secret);
      ASSERT_EQ(epoch.confirmation_key, secrets.confirmation_key);
      ASSERT_EQ(epoch.init_secret, secrets.init_secret);

      group_state.epoch += 1;
      init_secret = secrets.init_secret;
    }
  }
};

TEST_F(KeyScheduleTest, Interop)
{
  interop(tv.case_p256);
  interop(tv.case_x25519);
}
