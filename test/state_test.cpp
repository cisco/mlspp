#include "state.h"
#include <gtest/gtest.h>

using namespace mls;

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
      auto init_priv = DHPrivateKey::derive(suite, init_secret);

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
  auto first = State{ group_id, suite, identity_privs[0], credentials[0] };

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
  states.emplace_back(group_id, suite, identity_privs[0], credentials[0]);

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

    auto identity_priv = SignaturePrivateKey::generate(scheme);
    auto credential = Credential::basic(user_id, identity_priv);
    states.emplace_back(group_id, suite, identity_priv, credential);

    for (size_t i = 1; i < group_size; i += 1) {
      auto init_secret = random_bytes(32);
      auto init_priv = DHPrivateKey::derive(suite, init_secret);
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
    auto remove = states[i].remove(i + 1);
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
  auto inkA1 = DHPrivateKey::derive(CipherSuite::P256_SHA256_AES128GCM, insA);
  auto inkA2 = DHPrivateKey::derive(CipherSuite::X25519_SHA256_AES128GCM, insA);

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
  auto group_id = from_hex("0001020304");

  // Bob should choose P-256
  auto initialB =
    State::negotiate(group_id, supported_ciphers, idkB, credB, uikA);
  auto stateB = initialB.first;
  ASSERT_EQ(stateB.cipher_suite(), CipherSuite::P256_SHA256_AES128GCM);

  // Alice should also arrive at P-256 when initialized
  auto welcome = initialB.second.first;
  auto add = initialB.second.second;
  auto stateA = State(idkA, credA, insA, welcome, add);
  ASSERT_EQ(stateA, stateB);
}
