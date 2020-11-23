#include "test_vectors.h"
#include <doctest/doctest.h>
#include <hpke/random.h>
#include <mls/state.h>

using namespace mls;

class StateTest
{
public:
  StateTest()
  {
    for (size_t i = 0; i < group_size; i += 1) {
      auto init_secret = random_bytes(32);
      auto identity_priv = SignaturePrivateKey::generate(suite);
      auto credential = Credential::basic(user_id, identity_priv.public_key);
      auto init_priv = HPKEPrivateKey::derive(suite, init_secret);
      auto key_package = KeyPackage{
        suite, init_priv.public_key, credential, identity_priv, std::nullopt
      };

      init_privs.push_back(init_priv);
      identity_privs.push_back(identity_priv);
      key_packages.push_back(key_package);
    }
  }

protected:
  const CipherSuite suite{ CipherSuite::ID::P256_AES128GCM_SHA256_P256 };

  const size_t group_size = 5;
  const bytes group_id = { 0, 1, 2, 3 };
  const bytes user_id = { 4, 5, 6, 7 };
  const bytes test_message = from_hex("01020304");
  const std::string export_label = "test";
  const bytes export_context = from_hex("05060708");
  const size_t export_size = 16;

  std::vector<HPKEPrivateKey> init_privs;
  std::vector<SignaturePrivateKey> identity_privs;
  std::vector<KeyPackage> key_packages;
  std::vector<State> states;

  bytes fresh_secret() const
  {
    return random_bytes(suite.secret_size());
  }

  void verify_group_functionality(std::vector<State>& states)
  {
    if (states.empty()) {
      return;
    }

    // Verify that they can all send and be received
    for (auto& state : states) {
      auto encrypted = state.protect(test_message);
      for (auto& other : states) {
        auto decrypted = other.unprotect(encrypted);
        REQUIRE(decrypted == test_message);
      }
    }

    // Verify that they produce the same value for export
    auto ref = states[0].do_export(export_label, export_context, export_size);
    REQUIRE(ref.size() == export_size);
    for (auto& state : states) {
      REQUIRE(ref ==
              state.do_export(export_label, export_context, export_size));
    }

    // Verify roster
    auto roster_ref = states[0].roster();
    for (const auto& state : states) {
      REQUIRE(roster_ref == state.roster());
    }
  }
};

TEST_CASE_FIXTURE(StateTest, "Two Person")
{
  // Initialize the creator's state
  auto first0 =
    State{ group_id, suite, init_privs[0], identity_privs[0], key_packages[0] };

  // Create an Add proposal for the new participant
  auto add = first0.add(key_packages[1]);

  // Handle the Add proposal and create a Commit
  first0.handle(add);
  auto [commit, welcome, first1] = first0.commit(fresh_secret());
  silence_unused(commit);

  // Initialize the second participant from the Welcome
  auto second0 =
    State{ init_privs[1], identity_privs[1], key_packages[1], welcome };
  REQUIRE(first1 == second0);

  auto group = std::vector<State>{ first1, second0 };
  verify_group_functionality(group);
}

TEST_CASE_FIXTURE(StateTest, "Add Multiple Members")
{
  // Initialize the creator's state
  states.emplace_back(
    group_id, suite, init_privs[0], identity_privs[0], key_packages[0]);

  // Create and process an Add proposal for each new participant
  for (size_t i = 1; i < group_size; i += 1) {
    auto add = states[0].add(key_packages[i]);
    states[0].handle(add);
  }

  // Create a Commit that adds everybody
  auto [commit, welcome, new_state] = states[0].commit(fresh_secret());
  silence_unused(commit);
  states[0] = new_state;

  // Initialize the new joiners from the welcome
  for (size_t i = 1; i < group_size; i += 1) {
    states.emplace_back(
      init_privs[i], identity_privs[i], key_packages[i], welcome);
  }

  verify_group_functionality(states);
}

TEST_CASE_FIXTURE(StateTest, "Full Size Group")
{
  // Initialize the creator's state
  states.emplace_back(
    group_id, suite, init_privs[0], identity_privs[0], key_packages[0]);

  // Each participant invites the next
  for (size_t i = 1; i < group_size; i += 1) {
    auto sender = i - 1;

    auto add = states[sender].add(key_packages[i]);
    states[sender].handle(add);

    auto [commit, welcome, new_state] = states[sender].commit(fresh_secret());
    for (size_t j = 0; j < states.size(); j += 1) {
      if (j == sender) {
        states[j] = new_state;
      } else {
        states[j].handle(add);
        states[j] = opt::get(states[j].handle(commit));
      }
    }

    states.emplace_back(
      init_privs[i], identity_privs[i], key_packages[i], welcome);

    // Check that everyone ended up in the same place
    for (const auto& state : states) {
      REQUIRE(state == states[0]);
    }

    verify_group_functionality(states);
  }
}

class RunningGroupTest : public StateTest
{
protected:
  std::vector<State> states;

  RunningGroupTest()
  {
    states.emplace_back(
      group_id, suite, init_privs[0], identity_privs[0], key_packages[0]);

    for (size_t i = 1; i < group_size; i += 1) {
      auto add = states[0].add(key_packages[i]);
      states[0].handle(add);
    }

    auto [commit, welcome, new_state] = states[0].commit(fresh_secret());
    silence_unused(commit);
    states[0] = new_state;
    for (size_t i = 1; i < group_size; i += 1) {
      states.emplace_back(
        init_privs[i], identity_privs[i], key_packages[i], welcome);
    }

    check_consistency();
  }

  void check_consistency()
  {
    for (const auto& state : states) {
      REQUIRE(state == states[0]);
    }

    verify_group_functionality(states);
  }
};

TEST_CASE_FIXTURE(RunningGroupTest, "Update Everyone in a Group")
{
  for (size_t i = 0; i < group_size; i += 1) {
    auto new_leaf = fresh_secret();
    auto update = states[i].update(new_leaf);
    states[i].handle(update);
    auto [commit, welcome, new_state] = states[i].commit(new_leaf);
    silence_unused(welcome);

    for (auto& state : states) {
      if (state.index().val == i) {
        state = new_state;
      } else {
        state.handle(update);
        state = opt::get(state.handle(commit));
      }
    }

    check_consistency();
  }
}

TEST_CASE_FIXTURE(RunningGroupTest, "Remove Members from a Group")
{
  for (int i = static_cast<int>(group_size) - 2; i > 0; i -= 1) {
    auto remove = states[i].remove(LeafIndex{ uint32_t(i + 1) });
    states[i].handle(remove);
    auto [commit, welcome, new_state] = states[i].commit(fresh_secret());
    silence_unused(welcome);

    states.pop_back();
    for (auto& state : states) {
      if (state.index().val == size_t(i)) {
        state = new_state;
      } else {
        state.handle(remove);
        state = opt::get(state.handle(commit));
      }
    }

    check_consistency();
  }
}

TEST_CASE_FIXTURE(RunningGroupTest, "Roster Updates")
{
  // remove member at position 1
  auto remove_1 = states[0].remove(RosterIndex{ 1 });
  states[0].handle(remove_1);
  // commit to new state
  auto [commit_1, welcome_1, new_state_1] = states[0].commit(fresh_secret());
  silence_unused(welcome_1);
  silence_unused(commit_1);
  // roster should be 0, 2, 3, 4
  auto expected_creds = std::vector<Credential>{
    key_packages[0].credential,
    key_packages[2].credential,
    key_packages[3].credential,
    key_packages[4].credential,
  };
  auto roster = new_state_1.roster();
  auto roster_creds = std::vector<Credential>(roster.size());
  std::transform(roster.begin(),
                 roster.end(),
                 roster_creds.begin(),
                 [](const auto& kp) { return kp.credential; });
  REQUIRE(expected_creds == roster_creds);

  // remove member at position 2
  auto remove_2 = new_state_1.remove(RosterIndex{ 2 });
  new_state_1.handle(remove_2);
  // commit to new state
  auto [commit_2, welcome_2, new_state_2] = new_state_1.commit(fresh_secret());
  silence_unused(commit_2);
  silence_unused(welcome_2);
  // roster should be 0, 2, 4
  expected_creds = std::vector<Credential>{
    key_packages[0].credential,
    key_packages[2].credential,
    key_packages[4].credential,
  };
  roster = new_state_2.roster();
  roster_creds = std::vector<Credential>(roster.size());
  std::transform(roster.begin(),
                 roster.end(),
                 roster_creds.begin(),
                 [](const auto& kp) { return kp.credential; });
  REQUIRE(expected_creds == roster_creds);
}
