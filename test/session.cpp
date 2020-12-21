#include "test_vectors.h"
#include <doctest/doctest.h>
#include <hpke/random.h>
#include <mls/session.h>

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

  std::vector<Session> sessions;

  HPKEPrivateKey new_init_key() { return HPKEPrivateKey::generate(suite); }

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
    const auto size = static_cast<uint32_t>(sessions.size());
    broadcast_add(size - 1, size);
  }

  void broadcast_add(uint32_t from, uint32_t index)
  {
    auto id_priv = new_identity_key();
    auto init_priv = new_init_key();
    auto cred = Credential::basic(user_id, id_priv.public_key);
    auto client = Client(suite, id_priv, cred, std::nullopt);

    // Initial add is different
    if (sessions.empty()) {
      auto creator = client.begin_session(group_id);
      sessions.emplace_back(std::move(creator));
      return;
    }

    auto initial_epoch = sessions[0].current_epoch();

    auto join = client.start_join();

    auto add = sessions[from].add(join.key_package());
    broadcast(add, index);

    auto [welcome, commit] = sessions[from].commit();
    broadcast(commit, index);

    auto next = join.complete(welcome);

    // Add-in-place vs. add-at-edge
    if (index == sessions.size()) {
      sessions.emplace_back(std::move(next));
    } else if (index < sessions.size()) {
      sessions[index] = std::move(next);
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

    auto label = std::string("test");
    auto context = bytes{ 4, 5, 6, 7 };
    auto size = 16;
    auto ref_export = sessions[ref].do_export(label, context, size);

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

      REQUIRE(ref_export == session.do_export(label, context, size));
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

class RunningSessionTest : public SessionTest
{
protected:
  RunningSessionTest()
  {
    for (int i = 0; i < group_size; i += 1) {
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

    auto welcome_commit = sessions[i].commit();
    broadcast(std::get<1>(welcome_commit));

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

    auto welcome_commit = sessions[i - 1].commit();
    broadcast(std::get<1>(welcome_commit));

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
    auto welcome_commit = sessions[i].commit();
    broadcast(std::get<1>(welcome_commit), target);
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
    auto welcome_commit = sessions[i].commit();
    broadcast(std::get<1>(welcome_commit));
    check(initial_epoch);
  }

  // 3. Remove everyone but the creator
  for (int i = group_size - 1; i > 0; i -= 1) {
    auto initial_epoch = sessions[0].current_epoch();
    sessions.pop_back();
    auto remove = sessions[i - 1].remove(i);
    broadcast(remove);
    auto welcome_commit = sessions[i - 1].commit();
    broadcast(std::get<1>(welcome_commit));
    check(initial_epoch);
  }
}
