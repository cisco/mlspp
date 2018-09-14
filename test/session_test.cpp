#include "session.h"
#include <catch.hpp>

using namespace mls;

const size_t group_size = 5;
const bytes group_id{ 0, 1, 2, 3 };

void
broadcast_and_check(std::vector<Session>& sessions, const bytes& message)
{
  auto initial_epoch = sessions[0].current_epoch();

  for (auto& session : sessions) {
    session.handle(message);
  }

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

  SECTION("Two person, group-initiated")
  {
    sessions.push_back({});
    auto group_add = sessions[0].add(sessions[1].user_init_key());
    broadcast_and_check(sessions, group_add);
  }

  SECTION("Full-size, group-initiated")
  {
    for (int i = 0; i < group_size - 1; i += 1) {
      sessions.push_back({});
      auto group_add = sessions[i].add(sessions[i + 1].user_init_key());
      broadcast_and_check(sessions, group_add);
    }
  }
}

TEST_CASE("Session update and removal", "[session]")
{
  std::vector<Session> sessions;
  sessions.push_back({ group_id, SignaturePrivateKey::generate() });

  for (int i = 0; i < group_size - 1; i += 1) {
    sessions.push_back({});
    auto group_add = sessions[i].add(sessions[i + 1].user_init_key());
    broadcast_and_check(sessions, group_add);
  }

  SECTION("Update")
  {
    for (int i = 0; i < group_size; i += 1) {
      auto update = sessions[i].update();
      broadcast_and_check(sessions, update);
    }
  }

  SECTION("Removal")
  {
    for (int i = group_size - 1; i > 0; i -= 1) {
      auto remove = sessions[i - 1].remove(i);
      sessions.resize(i);
      broadcast_and_check(sessions, remove);
    }
  }
}

TEST_CASE("Full life-cycle", "[session]")
{
  std::vector<Session> sessions;
  sessions.push_back({ group_id, SignaturePrivateKey::generate() });

  // Create the group
  for (int i = 0; i < group_size - 1; i += 1) {
    sessions.push_back({});
    auto group_add = sessions[i].add(sessions[i + 1].user_init_key());
    broadcast_and_check(sessions, group_add);
  }

  // Have everyone update
  for (int i = 0; i < group_size - 1; i += 1) {
    auto update = sessions[i].update();
    broadcast_and_check(sessions, update);
  }

  // Remove everyone but the creator
  for (int i = group_size - 1; i > 0; i -= 1) {
    auto remove = sessions[i - 1].remove(i);
    sessions.resize(i);
    broadcast_and_check(sessions, remove);
  }
}
