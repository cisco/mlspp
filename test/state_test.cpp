#include "state.h"
#include <catch.hpp>

using namespace mls;

#define CIPHERSUITE CipherSuite::P256_SHA256_AES128GCM
#define SIG_SCHEME SignatureScheme::P256_SHA256

const size_t group_size = 5;
const bytes group_id{ 0, 1, 2, 3 };

TEST_CASE("Group creation", "[state]")
{
  std::vector<SignaturePrivateKey> identity_privs;
  std::vector<UserInitKey> user_init_keys;
  std::vector<bytes> init_secrets;
  std::vector<State> states;

  identity_privs.reserve(group_size);
  user_init_keys.reserve(group_size);
  init_secrets.reserve(group_size);
  states.reserve(group_size);

  auto idp = identity_privs.begin();
  auto uik = user_init_keys.begin();
  auto inp = init_secrets.begin();
  auto stp = states.begin();
  for (size_t i = 0; i < group_size; i += 1) {
    identity_privs.emplace(idp + i, SignaturePrivateKey::generate(SIG_SCHEME));
    auto init_secret = random_bytes(32);
    auto init_priv = DHPrivateKey::derive(CIPHERSUITE, init_secret);
    user_init_keys.emplace(uik + i);
    user_init_keys[i].init_keys = { init_priv.public_key() };
    user_init_keys[i].sign(identity_privs[i]);
    init_secrets.emplace(inp + i, init_secret);
  }

  SECTION("Two person")
  {
    // Initialize the creator's state
    states.emplace(stp, group_id, CIPHERSUITE, identity_privs[0]);

    // Create a Add for the new participant
    auto welcome_add = states[0].add(user_init_keys[1]);
    auto welcome = welcome_add.first;
    auto add = welcome_add.second;

    // Process the Add
    states[0] = states[0].handle(add);
    states.emplace(stp + 1, identity_privs[1], init_secrets[1], welcome, add);

    REQUIRE(states[0] == states[1]);
  }

  SECTION("Full size")
  {
    // Initialize the creator's state
    states.emplace(stp, group_id, CIPHERSUITE, identity_privs[0]);

    // Each participant invites the next
    for (size_t i = 1; i < group_size; i += 1) {
      auto welcome_add = states[i - 1].add(user_init_keys[i]);
      auto welcome = welcome_add.first;
      auto add = welcome_add.second;

      for (auto& state : states) {
        state = state.handle(add);
      }

      states.emplace(stp + i, identity_privs[i], init_secrets[i], welcome, add);

      // Check that everyone ended up in the same place
      for (const auto& state : states) {
        REQUIRE(state == states[0]);
      }
    }
  }
}

TEST_CASE("Operations on a running group", "[state]")
{
  std::vector<State> states;
  states.reserve(group_size);

  auto stp = states.begin();
  states.emplace(
    stp, group_id, CIPHERSUITE, SignaturePrivateKey::generate(SIG_SCHEME));

  for (size_t i = 1; i < group_size; i += 1) {
    auto init_secret = random_bytes(32);
    auto init_priv = DHPrivateKey::derive(CIPHERSUITE, init_secret);
    auto identity_priv = SignaturePrivateKey::generate(SIG_SCHEME);

    UserInitKey uik;
    uik.init_keys = { init_priv.public_key() };
    uik.sign(identity_priv);

    auto welcome_add = states[0].add(uik);
    for (auto& state : states) {
      state = state.handle(welcome_add.second);
    }

    states.emplace(stp + i,
                   identity_priv,
                   init_secret,
                   welcome_add.first,
                   welcome_add.second);
  }

  for (const auto& state : states) {
    REQUIRE(state == states[0]);
  }

  SECTION("Each node can update its leaf key")
  {
    for (size_t i = 0; i < group_size; i += 1) {
      auto new_leaf = random_bytes(32);
      auto update = states[i].update(new_leaf);

      for (size_t j = 0; j < group_size; j += 1) {
        states[j] = states[j].handle(update);
      }

      for (const auto& state : states) {
        REQUIRE(state == states[0]);
      }
    }
  }

  SECTION("Each node can remove its successor")
  {
    for (int i = group_size - 2; i > 0; i -= 1) {
      auto remove = states[i].remove(i + 1);

      for (size_t j = 0; j < i; j += 1) {
        states[j] = states[j].handle(remove);
      }

      for (size_t j = 0; j < i; j += 1) {
        REQUIRE(states[j] == states[0]);
      }
    }
  }
}
