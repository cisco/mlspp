#include "session.h"
#include "test_vectors.h"
#include <gtest/gtest.h>

using namespace mls;
using namespace mls::test;

class SessionTest : public ::testing::Test
{
protected:
  const CipherList suites{ CipherSuite::P256_SHA256_AES128GCM,
                           CipherSuite::X25519_SHA256_AES128GCM };
  const SignatureScheme scheme = SignatureScheme::Ed25519;
  const size_t group_size = 5;
  const size_t secret_size = 32;
  const bytes group_id = { 0, 1, 2, 3 };
  const bytes user_id = { 4, 5, 6, 7 };

  static const uint32_t no_except = 0xffffffff;

  std::vector<TestSession> sessions;

  SessionTest()
  {
    auto init_secret = fresh_secret();
    auto id_priv = new_identity_key();
    auto cred = Credential::basic(user_id, id_priv);
    sessions.push_back({ suites, init_secret, id_priv, cred });
  }

  SignaturePrivateKey new_identity_key()
  {
    return SignaturePrivateKey::generate(scheme);
  }

  bytes fresh_secret() const { return random_bytes(secret_size); }

  void broadcast(const bytes& message) { broadcast(message, no_except); }

  void broadcast(const bytes& message, const uint32_t except)
  {
    auto initial_epoch = sessions[0].current_epoch();
    for (auto& session : sessions) {
      if (except != no_except && session.index() == except) {
        continue;
      }

      session.handle(message);
    }
    check(initial_epoch, except);
  }

  void broadcast_add()
  {
    auto size = sessions.size();
    broadcast_add(size - 1, size);
  }

  void broadcast_add(uint32_t from, uint32_t index)
  {
    auto init_secret = fresh_secret();
    auto id_priv = new_identity_key();
    auto cred = Credential::basic(user_id, id_priv);
    auto initial_epoch = sessions[0].current_epoch();

    TestSession next{ suites, init_secret, id_priv, cred };

    // Initial add is different
    if (sessions.size() == 1) {
      auto welcome_add = sessions[0].start(group_id, next.user_init_key());
      next.join(welcome_add.first, welcome_add.second);
      sessions.push_back(next);
      // NB: Don't check epoch change, because it doesn't
      return;
    }

    auto welcome_add = sessions[from].add(next.user_init_key());
    next.join(welcome_add.first, welcome_add.second);
    broadcast(welcome_add.second, index);

    // Add-in-place vs. add-at-edge
    if (index == sessions.size()) {
      sessions.push_back(next);
    } else if (index < sessions.size()) {
      sessions[index] = next;
    } else {
      throw InvalidParameterError("Index too large for group");
    }

    check(initial_epoch);
  }

  void check(epoch_t initial_epoch) const { check(initial_epoch, no_except); }

  void check(epoch_t initial_epoch, uint32_t except) const
  {
    uint32_t ref = 0;
    if (except == 0 && sessions.size() > 1) {
      ref = 1;
    }

    // Verify that everyone ended up in consistent states
    for (const auto& session : sessions) {
      if (except != no_except && session.index() == except) {
        continue;
      }

      ASSERT_EQ(session, sessions[ref]);
    }

    // Verify that the epoch got updated
    ASSERT_NE(sessions[ref].current_epoch(), initial_epoch);
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
  auto idA = new_identity_key();
  auto initA = fresh_secret();
  auto credA = Credential::basic(user_id, idA);
  TestSession alice{ { CipherSuite::P256_SHA256_AES128GCM,
                       CipherSuite::X25519_SHA256_AES128GCM },
                     initA,
                     idA,
                     credA };

  // Bob supports P-256 and P-521
  auto idB = new_identity_key();
  auto initB = fresh_secret();
  auto credB = Credential::basic(user_id, idB);
  TestSession bob{ { CipherSuite::P256_SHA256_AES128GCM,
                     CipherSuite::X25519_SHA256_AES128GCM },
                   initB,
                   idB,
                   credB };

  auto welcome_add = alice.start({ 0, 1, 2, 3 }, bob.user_init_key());
  bob.join(welcome_add.first, welcome_add.second);
  ASSERT_EQ(alice, bob);
  ASSERT_EQ(alice.cipher_suite(), CipherSuite::P256_SHA256_AES128GCM);
}

class RunningSessionTest : public SessionTest
{
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
    auto update_secret = fresh_secret();
    auto update = sessions[i].update(update_secret);
    broadcast(update);
    check(initial_epoch);
  }
}

TEST_F(RunningSessionTest, Remove)
{
  for (int i = group_size - 1; i > 0; i -= 1) {
    auto initial_epoch = sessions[0].current_epoch();
    auto evict_secret = fresh_secret();
    auto remove = sessions[i - 1].remove(evict_secret, i);
    sessions.pop_back();
    broadcast(remove);
    check(initial_epoch);
  }
}

TEST_F(RunningSessionTest, Replace)
{
  for (int i = 0; i < group_size; ++i) {
    auto target = (i + 1) % group_size;

    // Remove target
    auto initial_epoch = sessions[i].current_epoch();
    auto evict_secret = fresh_secret();
    auto remove = sessions[i].remove(evict_secret, target);
    broadcast(remove, target);
    check(initial_epoch, target);

    // Re-add at target
    initial_epoch = sessions[i].current_epoch();
    broadcast_add(i, target);
  }
}

TEST_F(RunningSessionTest, FullLifeCycle)
{
  // 1. Group is created in the ctor

  // 2. Have everyone update
  for (int i = 0; i < group_size - 1; i += 1) {
    auto initial_epoch = sessions[0].current_epoch();
    auto update_secret = fresh_secret();
    auto update = sessions[i].update(update_secret);
    broadcast(update);
    check(initial_epoch);
  }

  // 3. Remove everyone but the creator
  for (int i = group_size - 1; i > 0; i -= 1) {
    auto initial_epoch = sessions[0].current_epoch();
    auto evict_secret = fresh_secret();
    auto remove = sessions[i - 1].remove(evict_secret, i);
    sessions.pop_back();
    broadcast(remove);
    check(initial_epoch);
  }
}

class SessionInteropTest : public ::testing::Test
{
protected:
  const BasicSessionTestVectors& basic_tv;

  SessionInteropTest()
    : basic_tv(TestLoader<BasicSessionTestVectors>::get())
  {}

  void assert_consistency(const TestSession& session,
                          const SessionTestVectors::Epoch& epoch)
  {
    ASSERT_EQ(session.current_epoch(), epoch.epoch);
    ASSERT_EQ(session.current_epoch_secret(), epoch.epoch_secret);
    ASSERT_EQ(session.current_application_secret(), epoch.application_secret);
    ASSERT_EQ(session.current_confirmation_key(), epoch.confirmation_key);
    ASSERT_EQ(session.current_init_secret(), epoch.init_secret);
  }

  void follow_basic(uint32_t index,
                    TestSession& session,
                    const SessionTestVectors::TestCase& tc)
  {
    int curr = 0;
    if (index == 0) {
      // Member 0 creates the group
      session.start(basic_tv.group_id, tc.user_init_keys[1]);
      curr = 1;
    } else {
      // Member i>0 is initialized with a welcome on step i-1
      auto& epoch = tc.transcript[index - 1];
      session.join(epoch.welcome, epoch.handshake);
      assert_consistency(session, epoch);
      curr = index;
    }

    // Process the adds after join
    for (; curr < basic_tv.group_size - 1; curr += 1) {
      auto& epoch = tc.transcript[curr];
      session.handle(epoch.handshake);
      assert_consistency(session, epoch);
    }

    // Process updates
    for (int i = 0; i < basic_tv.group_size; ++i, ++curr) {
      auto& epoch = tc.transcript[curr];

      // Generate an update to cache the secret
      if (i == index) {
        session.update({ uint8_t(i), 1 });
      }

      session.handle(epoch.handshake);
      assert_consistency(session, epoch);
    }

    // Process removes until this member has been removed
    for (int i = 0; i < basic_tv.group_size - 1; ++i, ++curr) {
      if (index >= basic_tv.group_size - 1 - i) {
        break;
      }

      auto& epoch = tc.transcript[curr];
      session.handle(epoch.handshake);
      assert_consistency(session, epoch);
    }
  }

  void follow_all(CipherSuite suite,
                  SignatureScheme scheme,
                  const SessionTestVectors::TestCase& tc)
  {
    CipherList ciphers{ suite };
    for (uint32_t i = 0; i < basic_tv.group_size; ++i) {
      bytes seed = { uint8_t(i), 0 };
      auto identity_priv = SignaturePrivateKey::derive(scheme, seed);
      auto cred = Credential::basic(seed, identity_priv);
      auto session = TestSession{ ciphers, seed, identity_priv, cred };
      follow_basic(i, session, tc);
    }
  }
};

TEST_F(SessionInteropTest, BasicP256)
{
  follow_all(CipherSuite::P256_SHA256_AES128GCM,
             SignatureScheme::P256_SHA256,
             basic_tv.case_p256_p256);
}

TEST_F(SessionInteropTest, BasicX25519)
{
  follow_all(CipherSuite::X25519_SHA256_AES128GCM,
             SignatureScheme::Ed25519,
             basic_tv.case_x25519_ed25519);
}
