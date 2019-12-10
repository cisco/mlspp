#include "state.h"
#include "test_vectors.h"
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
  const bytes test_message = from_hex("01020304");

  std::vector<SignaturePrivateKey> identity_privs;
  std::vector<Credential> credentials;
  std::vector<DHPrivateKey> init_privs;
  std::vector<ClientInitKey> client_init_keys;
  std::vector<State> states;

  StateTest()
  {
    for (size_t i = 0; i < group_size; i += 1) {
      auto identity_priv = SignaturePrivateKey::generate(scheme);
      auto credential = Credential::basic(user_id, identity_priv);
      auto init_priv = DHPrivateKey::generate(suite);

      auto client_init_key = ClientInitKey{ init_priv, credential };

      identity_privs.push_back(identity_priv);
      credentials.push_back(credential);
      init_privs.push_back(init_priv);
      client_init_keys.push_back(client_init_key);
    }
  }

  bytes fresh_secret() const
  {
    return random_bytes(Digest(suite).output_size());
  }
};

TEST_F(StateTest, TwoPerson)
{
  // Initialize the creator's state
  auto first0 = State{ group_id, suite, init_privs[0], credentials[0] };

  // Create an Add proposal for the new participant
  auto add = first0.add(client_init_keys[1]);

  // Handle the Add proposal and create a Commit
  first0.handle(add);
  auto [commit, welcome, first1] = first0.commit(fresh_secret());
  silence_unused(commit);

  // Initialize the second participant from the Welcome
  auto second0 = State{ { client_init_keys[1] }, welcome };
  ASSERT_EQ(first1, second0);

  /// Verify that they can exchange protected messages
  auto encrypted = first1.protect(test_message);
  auto decrypted = second0.unprotect(encrypted);
  ASSERT_EQ(decrypted, test_message);
}

TEST_F(StateTest, Multi)
{
  // Initialize the creator's state
  states.emplace_back(group_id, suite, init_privs[0], credentials[0]);

  // Create and process an Add proposal for each new participant
  for (size_t i = 1; i < group_size; i += 1) {
    auto add = states[0].add(client_init_keys[i]);
    states[0].handle(add);
  }

  // Create a Commit that adds everybody
  auto [commit, welcome, new_state] = states[0].commit(fresh_secret());
  silence_unused(commit);
  states[0] = new_state;

  // Initialize the new joiners from the welcome
  for (size_t i = 1; i < group_size; i += 1) {
    states.emplace_back(std::vector<ClientInitKey>{ client_init_keys[i] },
                        welcome);
  }

  // Verify that everyone can send and be received
  for (auto& state : states) {
    auto encrypted = state.protect(test_message);
    for (auto& other : states) {
      auto decrypted = other.unprotect(encrypted);
      ASSERT_EQ(decrypted, test_message);
    }
  }
}

TEST_F(StateTest, FullSize)
{
  // Initialize the creator's state
  states.emplace_back(group_id, suite, init_privs[0], credentials[0]);

  // Each participant invites the next
  for (size_t i = 1; i < group_size; i += 1) {
    auto sender = i - 1;

    auto add = states[sender].add(client_init_keys[i]);
    states[sender].handle(add);

    auto [commit, welcome, new_state] = states[sender].commit(fresh_secret());
    for (size_t j = 0; j < states.size(); j += 1) {
      if (j == sender) {
        states[j] = new_state;
      } else {
        states[j].handle(add);
        states[j] = states[j].handle(commit).value();
      }
    }

    states.emplace_back(std::vector<ClientInitKey>{ client_init_keys[i] },
                        welcome);

    // Check that everyone ended up in the same place
    for (const auto& state : states) {
      ASSERT_EQ(state, states[0]);
    }

    // Check that everyone can send and be received
    for (auto& state : states) {
      auto encrypted = state.protect(test_message);
      for (auto& other : states) {
        auto decrypted = other.unprotect(encrypted);
        ASSERT_EQ(decrypted, test_message);
      }
    }
  }
}

class RunningGroupTest : public StateTest
{
protected:
  std::vector<State> states;

  RunningGroupTest()
    : StateTest()
  {
    states.emplace_back(group_id, suite, init_privs[0], credentials[0]);

    for (size_t i = 1; i < group_size; i += 1) {
      auto add = states[0].add(client_init_keys[i]);
      states[0].handle(add);
    }

    auto [commit, welcome, new_state] = states[0].commit(fresh_secret());
    silence_unused(commit);
    states[0] = new_state;
    for (size_t i = 1; i < group_size; i += 1) {
      states.emplace_back(std::vector<ClientInitKey>{ client_init_keys[i] },
                          welcome);
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
    auto new_leaf = fresh_secret();
    auto update = states[i].update(new_leaf);
    states[i].handle(update);
    auto [commit, welcome, new_state] = states[i].commit(new_leaf);
    silence_unused(welcome);

    for (auto& state : states) {
      if (state.index().val == i) {
        state = new_state;
      } else {
        state.handle(update);
        state = state.handle(commit).value();
      }
    }

    check_consistency();
  }
}

TEST_F(RunningGroupTest, Remove)
{
  for (int i = group_size - 2; i > 0; i -= 1) {
    auto remove = states[i].remove(LeafIndex{ uint32_t(i + 1) });
    states[i].handle(remove);
    auto [commit, welcome, new_state] = states[i].commit(fresh_secret());
    silence_unused(welcome);

    states.pop_back();
    for (auto& state : states) {
      if (state.index().val == size_t(i)) {
        state = new_state;
      } else {
        state.handle(remove);
        state = state.handle(commit).value();
      }
    }

    check_consistency();
  }
}

TEST_F(StateTest, CipherNegotiation)
{
  // Alice supports P-256 and X25519
  auto idkA = SignaturePrivateKey::generate(SignatureScheme::Ed25519);
  auto credA = Credential::basic({ 0, 1, 2, 3 }, idkA);
  std::vector<CipherSuite> ciphersA{ CipherSuite::P256_SHA256_AES128GCM,
                                     CipherSuite::X25519_SHA256_AES128GCM };
  std::vector<ClientInitKey> ciksA;
  for (auto suiteA : ciphersA) {
    auto init_key = HPKEPrivateKey::generate(suiteA);
    ciksA.emplace_back(init_key, credA);
  }

  // Bob spuports P-256 and P-521
  auto supported_ciphers =
    std::vector<CipherSuite>{ CipherSuite::P256_SHA256_AES128GCM,
                              CipherSuite::P521_SHA512_AES256GCM };
  auto idkB = SignaturePrivateKey::generate(SignatureScheme::Ed25519);
  auto credB = Credential::basic({ 4, 5, 6, 7 }, idkB);
  std::vector<CipherSuite> ciphersB{ CipherSuite::P256_SHA256_AES128GCM,
                                     CipherSuite::X25519_SHA256_AES128GCM };
  std::vector<ClientInitKey> ciksB;
  for (auto suiteB : ciphersB) {
    auto init_key = HPKEPrivateKey::generate(suiteB);
    ciksB.emplace_back(init_key, credB);
  }

  // Bob should choose P-256
  auto [welcome, stateB] =
    State::negotiate(group_id, ciksB, ciksA, fresh_secret());
  ASSERT_EQ(stateB.cipher_suite(), CipherSuite::P256_SHA256_AES128GCM);

  // Alice should also arrive at P-256 when initialized
  auto stateA = State(ciksA, welcome);
  ASSERT_EQ(stateA, stateB);
}
