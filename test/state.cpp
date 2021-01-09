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

  bytes fresh_secret() const { return random_bytes(suite.secret_size()); }

  void verify_group_functionality(std::vector<State>& group_states)
  {
    if (group_states.empty()) {
      return;
    }

    // Verify that they can all send and be received
    for (auto& state : group_states) {
      auto encrypted = state.protect(test_message);
      for (auto& other : group_states) {
        auto decrypted = other.unprotect(encrypted);
        REQUIRE(decrypted == test_message);
      }
    }

    // Verify that they produce the same value for export
    auto ref =
      group_states[0].do_export(export_label, export_context, export_size);
    REQUIRE(ref.size() == export_size);
    for (auto& state : group_states) {
      REQUIRE(ref ==
              state.do_export(export_label, export_context, export_size));
    }

    // Verify roster
    auto roster_ref = group_states[0].roster();
    for (const auto& state : group_states) {
      REQUIRE(roster_ref == state.roster());
    }
  }
};

TEST_CASE_FIXTURE(StateTest, "Two Person")
{
  // Initialize the creator's state
  auto first0 =
    State{ group_id, suite, init_privs[0], identity_privs[0], key_packages[0] };

  // Handle the Add proposal and create a Commit
  auto add = first0.add_proposal(key_packages[1]);
  auto [commit, welcome, first1] = first0.commit(fresh_secret(), { add });
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
  auto adds = std::vector<Proposal>{};
  for (size_t i = 1; i < group_size; i += 1) {
    adds.push_back(states[0].add_proposal(key_packages[i]));
  }

  // Create a Commit that adds everybody
  auto [commit, welcome, new_state] = states[0].commit(fresh_secret(), adds);
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

    auto add = states[sender].add_proposal(key_packages[i]);
    auto [commit, welcome, new_state] =
      states[sender].commit(fresh_secret(), { add });
    for (size_t j = 0; j < states.size(); j += 1) {
      if (j == sender) {
        states[j] = new_state;
      } else {
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

    auto adds = std::vector<Proposal>{};
    for (size_t i = 1; i < group_size; i += 1) {
      adds.push_back(states[0].add_proposal(key_packages[i]));
    }

    auto [commit, welcome, new_state] =
      states[0].commit(fresh_secret(), { adds });
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

TEST_CASE_FIXTURE(RunningGroupTest, "Update Everyone via Empty Commit")
{
  for (size_t i = 0; i < group_size; i += 1) {
    auto new_leaf = fresh_secret();
    auto [commit, welcome, new_state] = states[i].commit(new_leaf, {});
    silence_unused(welcome);

    for (auto& state : states) {
      if (state.index().val == i) {
        state = new_state;
      } else {
        state = state.handle(commit).value();
      }
    }

    check_consistency();
  }
}

TEST_CASE_FIXTURE(RunningGroupTest, "Update Everyone in a Group")
{
  for (size_t i = 0; i < group_size; i += 1) {
    auto new_leaf = fresh_secret();
    auto update = states[i].update_proposal(new_leaf);
    auto [commit, welcome, new_state] = states[i].commit(new_leaf, { update });
    silence_unused(welcome);

    for (auto& state : states) {
      if (state.index().val == i) {
        state = new_state;
      } else {
        state = opt::get(state.handle(commit));
      }
    }

    check_consistency();
  }
}

TEST_CASE_FIXTURE(RunningGroupTest, "Remove Members from a Group")
{
  for (int i = static_cast<int>(group_size) - 2; i > 0; i -= 1) {
    auto remove = states[i].remove_proposal(LeafIndex{ uint32_t(i + 1) });
    auto [commit, welcome, new_state] =
      states[i].commit(fresh_secret(), { remove });
    silence_unused(welcome);

    states.pop_back();
    for (auto& state : states) {
      if (state.index().val == size_t(i)) {
        state = new_state;
      } else {
        state = opt::get(state.handle(commit));
      }
    }

    check_consistency();
  }
}

TEST_CASE_FIXTURE(RunningGroupTest, "Roster Updates")
{
  static const auto get_creds = [](const auto& kps) {
    auto creds = std::vector<Credential>(kps.size());
    std::transform(kps.begin(), kps.end(), creds.begin(), [](auto&& kp) {
      return kp.credential;
    });
    return creds;
  };

  // remove member at position 1
  auto remove_1 = states[0].remove_proposal(RosterIndex{ 1 });
  auto [commit_1, welcome_1, new_state_1] =
    states[0].commit(fresh_secret(), { remove_1 });
  silence_unused(welcome_1);
  silence_unused(commit_1);
  // roster should be 0, 2, 3, 4
  auto expected_creds = std::vector<Credential>{
    key_packages[0].credential,
    key_packages[2].credential,
    key_packages[3].credential,
    key_packages[4].credential,
  };
  REQUIRE(expected_creds == get_creds(new_state_1.roster()));

  // remove member at position 2
  auto remove_2 = new_state_1.remove_proposal(RosterIndex{ 2 });
  auto [commit_2, welcome_2, new_state_2] =
    new_state_1.commit(fresh_secret(), { remove_2 });
  silence_unused(welcome_2);
  // roster should be 0, 2, 4
  expected_creds = std::vector<Credential>{
    key_packages[0].credential,
    key_packages[2].credential,
    key_packages[4].credential,
  };

  REQUIRE(expected_creds == get_creds(new_state_2.roster()));

  // handle remove by remaining clients and verify the roster
  for (int i = 2; i < static_cast<int>(group_size); i += 1) {
    if (i == 3) {
      // skip since we removed
      continue;
    }
    states[i] = states[i].handle(commit_1).value();
    states[i] = states[i].handle(commit_2).value();
    REQUIRE(expected_creds == get_creds(states[i].roster()));
  }
}
