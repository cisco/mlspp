#include <catch2/catch_all.hpp>
#include <mls/state.h>
#include <mls_ds/tree_follower.h>

using namespace MLS_NAMESPACE;
using namespace MLS_NAMESPACE::mls_ds;

class TreeFollowerTest
{
public:
  TreeFollowerTest()
  {
    for (size_t i = 0; i < group_size; i += 1) {
      auto [init_priv, leaf_priv, identity_priv, key_package] = make_client();
      init_privs.push_back(init_priv);
      leaf_privs.push_back(leaf_priv);
      identity_privs.push_back(identity_priv);
      key_packages.push_back(key_package);
    }
  }

protected:
  const CipherSuite suite{ CipherSuite::ID::P256_AES128GCM_SHA256_P256 };

  const size_t group_size = 5;
  const bytes group_id = { 0, 1, 2, 3 };
  const bytes user_id = { 4, 5, 6, 7 };
  const bytes test_aad = from_hex("01020304");
  const bytes test_message = from_hex("11121314");
  const std::string export_label = "test";
  const bytes export_context = from_hex("05060708");
  const size_t export_size = 16;

  std::vector<HPKEPrivateKey> init_privs;
  std::vector<HPKEPrivateKey> leaf_privs;
  std::vector<SignaturePrivateKey> identity_privs;
  std::vector<KeyPackage> key_packages;
  std::vector<State> states;

  bytes fresh_secret() const { return random_bytes(suite.secret_size()); }

  std::tuple<HPKEPrivateKey, HPKEPrivateKey, SignaturePrivateKey, KeyPackage>
  make_client()
  {
    auto identity_priv = SignaturePrivateKey::generate(suite);
    auto credential = Credential::basic(user_id);
    auto init_priv = HPKEPrivateKey::generate(suite);
    auto leaf_priv = HPKEPrivateKey::generate(suite);
    auto leaf_node = LeafNode{ suite,
                               leaf_priv.public_key,
                               identity_priv.public_key,
                               credential,
                               Capabilities::create_default(),
                               Lifetime::create_default(),
                               {},
                               identity_priv };
    auto key_package =
      KeyPackage{ suite, init_priv.public_key, leaf_node, {}, identity_priv };

    return std::make_tuple(init_priv, leaf_priv, identity_priv, key_package);
  }
};

TEST_CASE_METHOD(TreeFollowerTest, "DS Follows Tree through Group Lifecycle")
{
  // Initialize a one-member group and a tree follower
  states.emplace_back(group_id,
                      suite,
                      leaf_privs[0],
                      identity_privs[0],
                      key_packages[0].leaf_node,
                      ExtensionList{});

  auto follower = TreeFollower(key_packages[0]);

  REQUIRE(follower.cipher_suite() == states[0].cipher_suite());
  REQUIRE(follower.tree() == states[0].tree());

  // Add the remaining members in a single commit
  auto adds = std::vector<Proposal>{};
  for (size_t i = 1; i < group_size; i += 1) {
    adds.push_back(states[0].add_proposal(key_packages[i]));
  }

  auto [commit1, welcome1, new_state1] =
    states[0].commit(fresh_secret(), CommitOpts{ adds, true, false, {} }, {});
  silence_unused(commit1);
  states[0] = new_state1;

  for (size_t i = 1; i < group_size; i += 1) {
    states.push_back({ init_privs[i],
                       leaf_privs[i],
                       identity_privs[i],
                       key_packages[i],
                       welcome1,
                       std::nullopt,
                       {} });
  }

  follower.update(commit1, {});
  REQUIRE(follower.tree() == states[0].tree());

  // Members 1..4 update, member 0 commits
  auto updates = std::vector<MLSMessage>{};
  for (size_t i = 1; i < group_size; i += 1) {
    const auto leaf_priv = HPKEPrivateKey::generate(suite);
    const auto update = states[i].update(leaf_priv, {}, {});
    updates.push_back(update);

    for (auto& state : states) {
      state.handle(update);
    }
  }

  auto [commit2, welcome2, new_state2] =
    states[0].commit(fresh_secret(), {}, {});
  states[0] = new_state2;
  for (size_t i = 1; i < group_size; i += 1) {
    states[i] = opt::get(states[i].handle(commit2));
  }

  follower.update(commit2, updates);
  REQUIRE(follower.tree() == states[0].tree());

  // Member 4 removes members 0..3 one by one
  for (uint32_t i = 1; i < group_size - 1; i += 1) {
    const auto remove = states[group_size - 1].remove_proposal(LeafIndex{ i });

    auto [commit, welcome, new_state] = states[group_size - 1].commit(
      fresh_secret(), CommitOpts{ { remove }, false, false, {} }, {});
    silence_unused(commit);
    silence_unused(welcome);
    states[group_size - 1] = new_state;

    follower.update(commit, {});
    REQUIRE(follower.tree() == states[group_size - 1].tree());
  }
}
