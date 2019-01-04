#include "session.h"
#include <gtest/gtest.h>

using namespace mls;

class SessionTest : public ::testing::Test {
protected:
  const CipherList suites{ CipherSuite::P256_SHA256_AES128GCM,
                           CipherSuite::X25519_SHA256_AES128GCM };
  const SignatureScheme scheme = SignatureScheme::Ed25519;
  const size_t group_size = 5;
  const bytes group_id = {0, 1, 2, 3};

  std::vector<Session> sessions;

  SessionTest() {
    sessions.push_back({ suites, new_identity_key() });
  }

  SignaturePrivateKey new_identity_key() {
    return SignaturePrivateKey::generate(scheme);
  }

  void broadcast(const bytes& message) {
    auto initial_epoch = sessions[0].current_epoch();
    for (auto& session : sessions) {
      session.handle(message);
    }
    check(initial_epoch);
  }

  void broadcast_add() {
    auto initial_epoch = sessions[0].current_epoch();
    Session next{ suites, new_identity_key() };
    auto last = sessions.size() - 1;
    std::pair<bytes, bytes> welcome_add;

    // Initial add is different
    if (sessions.size() == 1) {
      welcome_add = sessions[last].start(group_id, next.user_init_key());
      next.join(welcome_add.first, welcome_add.second);
      sessions.push_back(next);
      // NB: Don't check epoch change, because it doesn't
      return;
    }

    welcome_add = sessions[last].add(next.user_init_key());
    next.join(welcome_add.first, welcome_add.second);
    broadcast(welcome_add.second);
    sessions.push_back(next);
    check(initial_epoch);
  }

  void check(epoch_t initial_epoch) const {
    // Verify that everyone ended up in consistent states
    for (const auto& session : sessions) {
      ASSERT_EQ(session, sessions[0]);
    }

    // Verify that the epoch got updated
    ASSERT_NE(sessions[0].current_epoch(), initial_epoch);
  }
};

TEST_F(SessionTest, CreateTwoPerson)
{
  broadcast_add();
}

TEST_F(SessionTest, CreateFullSize)
{
  for (int i = 0; i < group_size - 1; i += 1) {
    broadcast_add();
  }
}

TEST_F(SessionTest, CiphersuiteNegotiation)
{
  // Alice supports P-256 and X25519
  Session alice{ { CipherSuite::P256_SHA256_AES128GCM,
                   CipherSuite::X25519_SHA256_AES128GCM },
                 new_identity_key() };

  // Bob supports P-256 and P-521
  Session bob{ { CipherSuite::P256_SHA256_AES128GCM,
                 CipherSuite::X25519_SHA256_AES128GCM },
               new_identity_key() };

  auto welcome_add = alice.start({ 0, 1, 2, 3 }, bob.user_init_key());
  bob.join(welcome_add.first, welcome_add.second);
  ASSERT_EQ(alice, bob);
  ASSERT_EQ(alice.cipher_suite(), CipherSuite::P256_SHA256_AES128GCM);
}

class RunningSessionTest : public SessionTest {
protected:
  RunningSessionTest()
    : SessionTest()
  {
    for (int i = 0; i < group_size - 1; i += 1) {
      broadcast_add();
    }
  }
};

TEST_F(RunningSessionTest, Update)
{
  for (int i = 0; i < group_size; i += 1) {
    auto initial_epoch = sessions[0].current_epoch();
    auto update = sessions[i].update();
    broadcast(update);
    check(initial_epoch);
  }
}

TEST_F(RunningSessionTest, Remove)
{
  for (int i = group_size - 1; i > 0; i -= 1) {
    auto initial_epoch = sessions[0].current_epoch();
    auto remove = sessions[i - 1].remove(i);
    sessions.pop_back();
    broadcast(remove);
    check(initial_epoch);
  }
}

TEST_F(RunningSessionTest, FullLifeCycle)
{
  // 1. Group is created in the ctor

  // 2. Have everyone update
  for (int i = 0; i < group_size - 1; i += 1) {
    auto initial_epoch = sessions[0].current_epoch();
    auto update = sessions[i].update();
    broadcast(update);
    check(initial_epoch);
  }

  // 3. Remove everyone but the creator
  for (int i = group_size - 1; i > 0; i -= 1) {
    auto initial_epoch = sessions[0].current_epoch();
    auto remove = sessions[i - 1].remove(i);
    sessions.pop_back();
    broadcast(remove);
    check(initial_epoch);
  }
}
