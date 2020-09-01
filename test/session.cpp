#include "test_vectors.h"
#include <doctest/doctest.h>
#include <mls/session.h>

using namespace mls;

class SessionTest
{
protected:
  const CipherSuite suite = CipherSuite::P256_AES128GCM_SHA256_P256;
  const int group_size = 5;
  const size_t secret_size = 32;
  const bytes group_id = { 0, 1, 2, 3 };
  const bytes user_id = { 4, 5, 6, 7 };

  static const uint32_t no_except = 0xffffffff;

  std::vector<TestSession> sessions;

  SignaturePrivateKey new_identity_key()
  {
    return SignaturePrivateKey::generate(suite);
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
    auto init_priv = HPKEPrivateKey::derive(suite, init_secret);
    auto cred = Credential::basic(user_id, id_priv.public_key());
    auto key_package =
      KeyPackage{ suite, init_priv.public_key(), cred, id_priv };
    auto init_info = Session::InitInfo{ init_secret, id_priv, key_package };

    // Initial add is different
    if (sessions.size() == 0) {
      auto my_init_secret = fresh_secret();
      auto my_id_priv = new_identity_key();
      auto my_init_priv = HPKEPrivateKey::derive(suite, my_init_secret);
      auto my_cred = Credential::basic(user_id, my_id_priv.public_key());
      auto my_key_package =
        KeyPackage{ suite, my_init_priv.public_key(), my_cred, my_id_priv };
      auto my_info =
        Session::InitInfo{ my_init_secret, my_id_priv, my_key_package };

      auto commit_secret = fresh_secret();
      auto [creator, welcome] =
        Session::start(group_id, { my_info }, { key_package }, commit_secret);
      auto joiner = Session::join({ init_info }, welcome);
      sessions.push_back(creator);
      sessions.push_back(joiner);
      return;
    }

    auto initial_epoch = sessions[0].current_epoch();

    auto add_secret = fresh_secret();
    auto [welcome, add] = sessions[from].add(add_secret, key_package);
    auto next = Session::join({ init_info }, welcome);
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

      REQUIRE(session == sessions[ref]);

      auto plaintext = bytes{ 0, 1, 2, 3 };
      auto encrypted = session.protect(plaintext);
      for (auto& other : sessions) {
        if (except != no_except && other.index() == except) {
          continue;
        }

        auto decrypted = other.unprotect(encrypted);
        REQUIRE(plaintext == decrypted);
      }
    }

    // Verify that the epoch got updated
    REQUIRE(sessions[ref].current_epoch() != initial_epoch);
  }
};

TEST_CASE_FIXTURE(SessionTest, "Two-Person Session Creation")
{
  broadcast_add();
}

TEST_CASE_FIXTURE(SessionTest, "Full-Size Session Creation")
{
  for (int i = 0; i < group_size - 1; i += 1) {
    broadcast_add();
  }
}

TEST_CASE_FIXTURE(SessionTest, "Ciphersuite Negotiation")
{
  // Alice supports P-256 and X25519
  auto idA = new_identity_key();
  auto credA = Credential::basic(user_id, idA.public_key());
  std::vector<CipherSuite> ciphersA{
    CipherSuite::P256_AES128GCM_SHA256_P256,
    CipherSuite::X25519_AES128GCM_SHA256_Ed25519
  };
  std::vector<KeyPackage> kpsA;
  std::vector<Session::InitInfo> infosA;
  for (auto suiteA : ciphersA) {
    auto init_secret = random_bytes(32);
    auto init_priv = HPKEPrivateKey::derive(suiteA, init_secret);
    auto kp = KeyPackage{ suiteA, init_priv.public_key(), credA, idA };
    auto info = Session::InitInfo{ init_secret, idA, kp };
    kpsA.emplace_back(suiteA, init_priv.public_key(), credA, idA);
    infosA.emplace_back(init_secret, idA, kpsA.back());
  }

  // Bob supports P-256 and P-521
  auto idB = new_identity_key();
  auto credB = Credential::basic(user_id, idB.public_key());
  std::vector<CipherSuite> ciphersB{
    CipherSuite::P256_AES128GCM_SHA256_P256,
    CipherSuite::X25519_AES128GCM_SHA256_Ed25519
  };
  std::vector<KeyPackage> kpsB;
  std::vector<Session::InitInfo> infosB;
  for (auto suiteB : ciphersB) {
    auto init_secret = random_bytes(32);
    auto init_priv = HPKEPrivateKey::derive(suiteB, init_secret);
    auto kp = KeyPackage{ suiteB, init_priv.public_key(), credB, idB };
    auto info = Session::InitInfo{ init_secret, idB, kp };
    kpsB.emplace_back(suiteB, init_priv.public_key(), credB, idB);
    infosB.emplace_back(init_secret, idB, kpsB.back());
  }

  auto init_secret = fresh_secret();
  auto session_welcome_add =
    Session::start({ 0, 1, 2, 3 }, infosA, kpsB, init_secret);
  TestSession alice = std::get<0>(session_welcome_add);
  TestSession bob = Session::join(infosB, std::get<1>(session_welcome_add));
  REQUIRE(alice == bob);
  REQUIRE(alice.cipher_suite() == CipherSuite::P256_AES128GCM_SHA256_P256);
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

TEST_CASE_FIXTURE(RunningSessionTest, "Update within Session")
{
  for (int i = 0; i < group_size; i += 1) {
    auto initial_epoch = sessions[0].current_epoch();
    auto update_secret = fresh_secret();
    auto update = sessions[i].update(update_secret);
    broadcast(update);
    check(initial_epoch);
  }
}

TEST_CASE_FIXTURE(RunningSessionTest, "Remove within Session")
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

TEST_CASE_FIXTURE(RunningSessionTest, "Replace within Session")
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

TEST_CASE_FIXTURE(RunningSessionTest, "Full Session Life-Cycle")
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

class SessionInteropTest
{
protected:
  const BasicSessionTestVectors& basic_tv;

  SessionInteropTest()
    : basic_tv(TestLoader<BasicSessionTestVectors>::get())
  {}

  void assert_consistency(const TestSession& session,
                          const SessionTestVectors::Epoch& epoch)
  {
    REQUIRE(session.current_epoch() == epoch.epoch);
    REQUIRE(session.current_epoch_secret() == epoch.epoch_secret);
    REQUIRE(session.current_application_secret() == epoch.application_secret);
    REQUIRE(session.current_confirmation_key() == epoch.confirmation_key);
    REQUIRE(session.current_init_secret() == epoch.init_secret);
  }

  void follow_basic(uint32_t index,
                    const Session::InitInfo& my_init_info,
                    const SessionTestVectors::TestCase& tc)
  {
    size_t curr = 0;
    std::optional<Session> session;
    if (index == 0) {
      // Member 0 creates the group
      auto [session_init, unused_welcome] =
        Session::start(basic_tv.group_id,
                       { my_init_info },
                       { tc.key_packages[1] },
                       tc.transcript.at(0).commit_secret);
      session_init.encrypt_handshake(tc.encrypt);
      silence_unused(unused_welcome);
      session = session_init;
      curr = 1;
    } else {
      // Member i>0 is initialized with a welcome on step i-1
      auto& epoch = tc.transcript.at(index - 1);
      session = Session::join({ my_init_info }, epoch.welcome.value());
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
          session->add(epoch.commit_secret, tc.key_packages[curr + 1]);
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
    DeterministicHPKE lock;
    for (uint32_t i = 0; i < basic_tv.group_size; ++i) {
      bytes init_secret = { uint8_t(i), 0 };
      auto init_priv = HPKEPrivateKey::derive(suite, init_secret);
      auto identity_priv = SignaturePrivateKey::derive(suite, init_secret);
      auto cred = Credential::basic(init_secret, identity_priv.public_key());
      auto key_package =
        KeyPackage{ suite, init_priv.public_key(), cred, identity_priv };
      auto init_info =
        Session::InitInfo{ init_secret, identity_priv, key_package };
      REQUIRE(key_package == tc.key_packages[i]);
      follow_basic(i, init_info, tc);
    }
  }
};

TEST_CASE_FIXTURE(SessionInteropTest, "Basic Session Interop")
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
    if (!deterministic_signature_scheme(tc.cipher_suite)) {
      continue;
    }

    follow_all(tc);
  }
}
