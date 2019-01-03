#include "session.h"
#include <catch.hpp>

#include <iostream>

using namespace mls;

const CipherList ciphersuites{ CipherSuite::P256_SHA256_AES128GCM,
                               CipherSuite::X25519_SHA256_AES128GCM };

SignaturePrivateKey
new_identity_key()
{
  return SignaturePrivateKey::generate(SignatureScheme::Ed25519);
}

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
  Session next{ ciphersuites, new_identity_key() };
  auto last = sessions.size() - 1;
  std::pair<bytes, bytes> welcome_add;

  // Initial add is different
  if (sessions.size() == 1) {
    welcome_add = sessions[last].start(group_id, next.user_init_key());
    next.join(welcome_add.first, welcome_add.second);
    sessions.push_back(next);
    return;
  }

  welcome_add = sessions[last].add(next.user_init_key());
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
  sessions.push_back({ ciphersuites, new_identity_key() });

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

  SECTION("With Ciphersuite Negotiation")
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
    REQUIRE(alice == bob);
  }
}

TEST_CASE("Session update and removal", "[session]")
{
  std::vector<Session> sessions;
  sessions.push_back({ ciphersuites, new_identity_key() });

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
      sessions.pop_back();
      broadcast(sessions, remove);
      check(sessions, initial_epoch);
    }
  }
}

TEST_CASE("Full life-cycle", "[session]")
{
  std::vector<Session> sessions;
  sessions.push_back({ ciphersuites, new_identity_key() });

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
    sessions.pop_back();
    broadcast(sessions, remove);
    check(sessions, initial_epoch);
  }
}
