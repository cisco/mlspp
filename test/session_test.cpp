#include "session.h"
#include <catch.hpp>

using namespace mls;

const size_t group_size = 5;
const bytes group_id{ 0, 1, 2, 3 };

void
broadcast(std::vector<Session>& sessions, const bytes& message)
{
  for (auto& session : sessions) {
    session.handle(message);
  }
}

void
broadcast_add(std::vector<Session>& sessions)
{
  Session next;
  auto last = sessions.size() - 1;
  auto welcome_add = sessions[last].add(next.user_init_key());

  next.join(welcome_add.first, welcome_add.second);
  broadcast(sessions, welcome_add.second);
  sessions.push_back(next);
}

void
check(std::vector<Session> sessions, epoch_t initial_epoch)
{
  // Verify that everyone ended up in consistent states
  for (const auto& session : sessions) {
    REQUIRE(session == sessions[0]);
  }

  // Verify that the epoch got updated
  REQUIRE(sessions[0].current_epoch() != initial_epoch);
}

TEST_CASE("Session creation", "[session]")
{
  std::vector<Session> sessions;
  sessions.push_back({ group_id, SignaturePrivateKey::generate() });

  SECTION("Two person")
  {
    auto initial_epoch = sessions[0].current_epoch();
    broadcast_add(sessions);
    check(sessions, initial_epoch);
  }

  SECTION("Full-size")
  {
    for (int i = 0; i < group_size - 1; i += 1) {
      auto initial_epoch = sessions[0].current_epoch();
      broadcast_add(sessions);
      check(sessions, initial_epoch);
    }
  }
}

TEST_CASE("Session update and removal", "[session]")
{
  std::vector<Session> sessions;
  sessions.push_back({ group_id, SignaturePrivateKey::generate() });

  for (int i = 0; i < group_size - 1; i += 1) {
    auto initial_epoch = sessions[0].current_epoch();
    broadcast_add(sessions);
    check(sessions, initial_epoch);
  }

  SECTION("Update")
  {
    for (int i = 0; i < group_size; i += 1) {
      auto initial_epoch = sessions[0].current_epoch();
      auto update = sessions[i].update();
      broadcast(sessions, update);
      check(sessions, initial_epoch);
    }
  }

  SECTION("Removal")
  {
    for (int i = group_size - 1; i > 0; i -= 1) {
      auto initial_epoch = sessions[0].current_epoch();
      auto remove = sessions[i - 1].remove(i);
      sessions.resize(i);
      broadcast(sessions, remove);
      check(sessions, initial_epoch);
    }
  }
}

TEST_CASE("Full life-cycle", "[session]")
{
  std::vector<Session> sessions;
  sessions.push_back({ group_id, SignaturePrivateKey::generate() });

  // Create the group
  for (int i = 0; i < group_size - 1; i += 1) {
    auto initial_epoch = sessions[0].current_epoch();
    broadcast_add(sessions);
    check(sessions, initial_epoch);
  }

  // Have everyone update
  for (int i = 0; i < group_size - 1; i += 1) {
    auto initial_epoch = sessions[0].current_epoch();
    auto update = sessions[i].update();
    broadcast(sessions, update);
    check(sessions, initial_epoch);
  }

  // Remove everyone but the creator
  for (int i = group_size - 1; i > 0; i -= 1) {
    auto initial_epoch = sessions[0].current_epoch();
    auto remove = sessions[i - 1].remove(i);
    sessions.resize(i);
    broadcast(sessions, remove);
    check(sessions, initial_epoch);
  }
}
