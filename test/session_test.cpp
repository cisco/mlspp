#include "session.h"
#include "test_vectors.h"
#include <gtest/gtest.h>

using namespace mls;

class SessionTest : public ::testing::Test
{
protected:
  const CipherSuite suite = CipherSuite::P256_SHA256_AES128GCM;
  const SignatureScheme scheme = SignatureScheme::Ed25519;
  const int group_size = 5;
  const size_t secret_size = 32;
  const bytes group_id = { 0, 1, 2, 3 };
  const bytes user_id = { 4, 5, 6, 7 };

  static const uint32_t no_except = 0xffffffff;

  std::vector<TestSession> sessions;

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
    auto init_key = HPKEPrivateKey::derive(suite, init_secret);
    auto cred = Credential::basic(user_id, id_priv);
    auto client_init_key = ClientInitKey{ suite, init_key, cred };

    // Initial add is different
    if (sessions.size() == 0) {
      auto my_init_secret = fresh_secret();
      auto my_id_priv = new_identity_key();
      auto my_init_key = HPKEPrivateKey::derive(suite, my_init_secret);
      auto my_cred = Credential::basic(user_id, id_priv);
      auto my_client_init_key = ClientInitKey{ suite, my_init_key, my_cred };

      auto commit_secret = fresh_secret();
      auto [creator, welcome] = Session::start(
        group_id, { my_client_init_key }, { client_init_key }, commit_secret);
      auto joiner = Session::join({ client_init_key }, welcome);
      sessions.push_back(creator);
      sessions.push_back(joiner);
      return;
    }

    auto initial_epoch = sessions[0].current_epoch();

    auto add_secret = fresh_secret();
    auto [welcome, add] = sessions[from].add(add_secret, client_init_key);
    auto next = Session::join({ client_init_key }, welcome);
    broadcast(add, index);

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

  void check(epoch_t initial_epoch) { check(initial_epoch, no_except); }

  void check(epoch_t initial_epoch, uint32_t except)
  {
    uint32_t ref = 0;
    if (except == 0 && sessions.size() > 1) {
      ref = 1;
    }

    // Verify that everyone ended up in consistent states, and that
    // they can send and be received.
    for (auto& session : sessions) {
      if (except != no_except && session.index() == except) {
        continue;
      }

      ASSERT_EQ(session, sessions[ref]);

      auto plaintext = bytes{ 0, 1, 2, 3 };
      auto encrypted = session.protect(plaintext);
      for (auto& other : sessions) {
        if (except != no_except && other.index() == except) {
          continue;
        }

        auto decrypted = other.unprotect(encrypted);
        ASSERT_EQ(plaintext, decrypted);
      }
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
  auto credA = Credential::basic(user_id, idA);
  std::vector<CipherSuite> ciphersA{ CipherSuite::P256_SHA256_AES128GCM,
                                     CipherSuite::X25519_SHA256_AES128GCM };
  std::vector<ClientInitKey> ciksA;
  for (auto suiteA : ciphersA) {
    auto init_key = HPKEPrivateKey::generate(suiteA);
    ciksA.emplace_back(suiteA, init_key, credA);
  }

  // Bob supports P-256 and P-521
  auto idB = new_identity_key();
  auto credB = Credential::basic(user_id, idB);
  std::vector<CipherSuite> ciphersB{ CipherSuite::P256_SHA256_AES128GCM,
                                     CipherSuite::X25519_SHA256_AES128GCM };
  std::vector<ClientInitKey> ciksB;
  for (auto suiteB : ciphersB) {
    auto init_key = HPKEPrivateKey::generate(suiteB);
    ciksB.emplace_back(suiteB, init_key, credB);
  }

  auto init_secret = fresh_secret();
  auto session_welcome_add =
    Session::start({ 0, 1, 2, 3 }, ciksA, ciksB, init_secret);
  TestSession alice = std::get<0>(session_welcome_add);
  TestSession bob = Session::join(ciksB, std::get<1>(session_welcome_add));
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
                    const ClientInitKey& my_client_init_key,
                    const SessionTestVectors::TestCase& tc)
  {
    size_t curr = 0;
    std::optional<Session> session;
    if (index == 0) {
      // Member 0 creates the group
      auto [session_init, unused_welcome] =
        Session::start(basic_tv.group_id,
                       { my_client_init_key },
                       { tc.client_init_keys[1] },
                       tc.transcript.at(0).commit_secret);
      session_init.encrypt_handshake(tc.encrypt);
      silence_unused(unused_welcome);
      session = session_init;
      curr = 1;
    } else {
      // Member i>0 is initialized with a welcome on step i-1
      auto& epoch = tc.transcript.at(index - 1);
      session = Session::join({ my_client_init_key }, epoch.welcome.value());
      session->encrypt_handshake(tc.encrypt);
      assert_consistency(*session, epoch);
      curr = index;
    }

    // Process the adds after join
    for (; curr < basic_tv.group_size - 1; curr += 1) {
      auto& epoch = tc.transcript.at(curr);

      // Generate an add to cache the next state
      if (curr == index) {
        auto [unused_welcome, add] =
          session->add(epoch.commit_secret, tc.client_init_keys[curr + 1]);
        silence_unused(unused_welcome);
        session->handle(add);
      } else {
        session->handle(epoch.handshake);
      }

      assert_consistency(*session, epoch);
    }

    // Process updates
    for (size_t i = 0; i < basic_tv.group_size; ++i, ++curr) {
      auto& epoch = tc.transcript.at(curr);

      // Generate an update to cache next state
      if (i == index) {
        auto msg = session->update(epoch.commit_secret);
        session->handle(msg);
      } else {
        session->handle(epoch.handshake);
      }

      assert_consistency(*session, epoch);
    }

    // Process removes until this member has been removed
    for (int sender = basic_tv.group_size - 2; sender >= 0; --sender, ++curr) {
      auto& epoch = tc.transcript.at(curr);
      if (int(index) > sender) {
        break;
      }

      // Generate a remove to cache next state
      if (int(index) == sender) {
        auto msg = session->remove(epoch.commit_secret, sender + 1);
        session->handle(msg);
      } else {
        session->handle(epoch.handshake);
      }

      assert_consistency(*session, epoch);
    }
  }

  void follow_all(const SessionTestVectors::TestCase& tc)
  {
    auto suite = tc.cipher_suite;
    auto scheme = tc.signature_scheme;
    DeterministicHPKE lock;
    for (uint32_t i = 0; i < basic_tv.group_size; ++i) {
      bytes seed = { uint8_t(i), 0 };
      auto init_priv = HPKEPrivateKey::derive(suite, seed);
      auto identity_priv = SignaturePrivateKey::derive(scheme, seed);
      auto cred = Credential::basic(seed, identity_priv);
      auto my_client_init_key = ClientInitKey{ suite, init_priv, cred };
      ASSERT_EQ(my_client_init_key, tc.client_init_keys[i]);
      follow_basic(i, my_client_init_key, tc);
    }
  }
};

TEST_F(SessionInteropTest, Basic)
{
  for (const auto& tc : basic_tv.cases) {
    // XXX(rlb@ipv.sx): Tests with randomized signature schemes are disabled for
    // the moment because the testing scheme here requires signatures to be
    // reprodudible.  Otherwise, the following endpoint will generate a
    // different message than the other endpoints have seen.
    //
    // Note that encrypted tests are still OK (with deterministic signatures),
    // since the transcript doesn't cover the MLSCiphertext, in particular, the
    // sender data nonce and encrypted sender data.
    if (!deterministic_signature_scheme(tc.signature_scheme)) {
      continue;
    }

    follow_all(tc);
  }
}
