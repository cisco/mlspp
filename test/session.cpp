#include "test_vectors.h"
#include <doctest/doctest.h>
#include <hpke/random.h>
#include <mls/session.h>

#include <iostream> // XXX

using namespace mls;

class SessionTest
{
protected:
  const CipherSuite suite{ CipherSuite::ID::P256_AES128GCM_SHA256_P256 };
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
    for (auto& session : sessions) {
      if (except != no_except && session.index() == except) {
        continue;
      }

      session.handle(message);
    }
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
    auto cred = Credential::basic(user_id, id_priv.public_key);
    auto key_package = KeyPackage{ suite, init_priv.public_key, cred, id_priv };
    auto init_info = Session::InitInfo{ init_secret, id_priv, key_package };

    // Initial add is different
    if (sessions.empty()) {
      auto my_init_secret = fresh_secret();
      auto my_id_priv = new_identity_key();
      auto my_init_priv = HPKEPrivateKey::derive(suite, my_init_secret);
      auto my_cred = Credential::basic(user_id, my_id_priv.public_key);
      auto my_key_package =
        KeyPackage{ suite, my_init_priv.public_key, my_cred, my_id_priv };
      auto my_info =
        Session::InitInfo{ my_init_secret, my_id_priv, my_key_package };

      auto commit_secret = fresh_secret();
      auto [creator, welcome] =
        Session::start(group_id, { my_info }, { key_package }, commit_secret);
      auto joiner = Session::join({ init_info }, welcome);
      sessions.emplace_back(creator);
      sessions.emplace_back(joiner);
      return;
    }

    auto initial_epoch = sessions[0].current_epoch();

    auto add = sessions[from].add(key_package);
    broadcast(add, index);

    auto [welcome, commit] = sessions[from].commit();
    broadcast(commit, index);

    // XXX
    auto commit_pt = tls::get<MLSPlaintext>(commit);
    auto commit_data = std::get<CommitData>(commit_pt.content);
    auto commit_content = commit_data.commit;
    std::cout << "proposals.updates = " << commit_content.updates.size() << std::endl;
    std::cout << "proposals.removes = " << commit_content.removes.size() << std::endl;
    std::cout << "proposals.adds    = " << commit_content.adds.size() << std::endl;

    auto next = Session::join({ init_info }, welcome);

    // Add-in-place vs. add-at-edge
    if (index == sessions.size()) {
      sessions.emplace_back(next);
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
  auto credA = Credential::basic(user_id, idA.public_key);
  std::vector<CipherSuite> ciphersA{
    { CipherSuite::ID::P256_AES128GCM_SHA256_P256 },
    { CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519 }
  };
  std::vector<KeyPackage> kpsA;
  std::vector<Session::InitInfo> infosA;
  for (auto suiteA : ciphersA) {
    auto init_secret = random_bytes(32);
    auto init_priv = HPKEPrivateKey::derive(suiteA, init_secret);
    auto kp = KeyPackage{ suiteA, init_priv.public_key, credA, idA };
    auto info = Session::InitInfo{ init_secret, idA, kp };
    kpsA.emplace_back(suiteA, init_priv.public_key, credA, idA);
    infosA.emplace_back(init_secret, idA, kpsA.back());
  }

  // Bob supports P-256 and P-521
  auto idB = new_identity_key();
  auto credB = Credential::basic(user_id, idB.public_key);
  std::vector<CipherSuite> ciphersB{
    { CipherSuite::ID::P256_AES128GCM_SHA256_P256 },
    { CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519 }
  };
  std::vector<KeyPackage> kpsB;
  std::vector<Session::InitInfo> infosB;
  for (auto suiteB : ciphersB) {
    auto init_secret = random_bytes(32);
    auto init_priv = HPKEPrivateKey::derive(suiteB, init_secret);
    auto kp = KeyPackage{ suiteB, init_priv.public_key, credB, idB };
    auto info = Session::InitInfo{ init_secret, idB, kp };
    kpsB.emplace_back(suiteB, init_priv.public_key, credB, idB);
    infosB.emplace_back(init_secret, idB, kpsB.back());
  }

  auto init_secret = fresh_secret();
  auto session_welcome_add =
    Session::start({ 0, 1, 2, 3 }, infosA, kpsB, init_secret);
  TestSession alice = std::get<0>(session_welcome_add);
  TestSession bob = Session::join(infosB, std::get<1>(session_welcome_add));
  REQUIRE(alice == bob);
  REQUIRE(alice.cipher_suite().id ==
          CipherSuite::ID::P256_AES128GCM_SHA256_P256);
}

class RunningSessionTest : public SessionTest
{
protected:
  RunningSessionTest()
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

    auto update = sessions[i].update();
    broadcast(update);

    auto [_welcome, commit] = sessions[i].commit();
    broadcast(commit);

    check(initial_epoch);
  }
}

TEST_CASE_FIXTURE(RunningSessionTest, "Remove within Session")
{
  for (int i = group_size - 1; i > 0; i -= 1) {
    auto initial_epoch = sessions[0].current_epoch();
    auto evict_secret = fresh_secret();
    sessions.pop_back();

    auto remove = sessions[i - 1].remove(i);
    broadcast(remove);

    auto [_welcome, commit] = sessions[i - 1].commit();
    broadcast(commit);

    check(initial_epoch);
  }
}

TEST_CASE_FIXTURE(RunningSessionTest, "Replace within Session")
{
  for (int i = 0; i < group_size; ++i) {
    auto target = (i + 1) % group_size;

    // Remove target
    auto initial_epoch = sessions[i].current_epoch();
    auto remove = sessions[i].remove(target);
    broadcast(remove, target);
    auto [_welcome, commit] = sessions[i].commit();
    broadcast(commit, target);
    check(initial_epoch, target);

    // Re-add at target
    initial_epoch = sessions[i].current_epoch();
    broadcast_add(i, target);
    check(initial_epoch, target);
  }
}

TEST_CASE_FIXTURE(RunningSessionTest, "Full Session Life-Cycle")
{
  // 1. Group is created in the ctor

  // 2. Have everyone update
  for (int i = 0; i < group_size - 1; i += 1) {
    auto initial_epoch = sessions[0].current_epoch();
    auto update = sessions[i].update();
    broadcast(update);
    auto [_welcome, commit] = sessions[i].commit();
    broadcast(commit);
    check(initial_epoch);
  }

  // 3. Remove everyone but the creator
  for (int i = group_size - 1; i > 0; i -= 1) {
    auto initial_epoch = sessions[0].current_epoch();
    sessions.pop_back();
    auto remove = sessions[i - 1].remove(i);
    broadcast(remove);
    auto [_welcome, commit] = sessions[i-1].commit();
    broadcast(commit);
    check(initial_epoch);
  }
}
