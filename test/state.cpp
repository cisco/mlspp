#include <doctest/doctest.h>
#include <hpke/random.h>
#include <mls/common.h>
#include <mls/state.h>

using namespace mls;

struct CustomExtension
{
  uint8_t value;

  static constexpr Extension::Type type = 0xfffe;
  TLS_SERIALIZABLE(value);
};

struct CustomExtension2
{
  uint8_t value;

  static constexpr Extension::Type type = 0xfffd;
  TLS_SERIALIZABLE(value);
};

class StateTest
{
public:
  StateTest()
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
  const MessageOpts msg_opts{ false, {}, 0 };

  std::vector<HPKEPrivateKey> init_privs;
  std::vector<HPKEPrivateKey> leaf_privs;
  std::vector<SignaturePrivateKey> identity_privs;
  std::vector<KeyPackage> key_packages;
  std::vector<State> states;

  bytes fresh_secret() const { return random_bytes(suite.secret_size()); }

  std::tuple<HPKEPrivateKey, HPKEPrivateKey, SignaturePrivateKey, KeyPackage>
  make_client()
  {
    auto ext_list = ExtensionList{};

    auto capas = Capabilities::create_default();
    capas.extensions.push_back(CustomExtension::type);
    capas.extensions.push_back(CustomExtension2::type);

    auto identity_priv = SignaturePrivateKey::generate(suite);
    auto credential = Credential::basic(user_id);
    auto init_priv = HPKEPrivateKey::generate(suite);
    auto leaf_priv = HPKEPrivateKey::generate(suite);
    auto leaf_node = LeafNode{ suite,
                               leaf_priv.public_key,
                               identity_priv.public_key,
                               credential,
                               capas,
                               Lifetime::create_default(),
                               {},
                               identity_priv };
    auto key_package =
      KeyPackage{ suite, init_priv.public_key, leaf_node, {}, identity_priv };

    return std::make_tuple(init_priv, leaf_priv, identity_priv, key_package);
  }

  void verify_group_functionality(std::vector<State>& group_states)
  {
    if (group_states.empty()) {
      return;
    }

    // Verify that they can all send and be received
    for (auto& state : group_states) {
      auto encrypted = state.protect(test_aad, test_message, 0);
      for (auto& other : group_states) {
        auto [aad_, decrypted_] = other.unprotect(encrypted);
        auto aad = aad_;
        auto decrypted = decrypted_;

        REQUIRE(aad == test_aad);
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
  auto first0 = State{ group_id,
                       suite,
                       leaf_privs[0],
                       identity_privs[0],
                       key_packages[0].leaf_node,
                       {} };

  // Handle the Add proposal and create a Commit
  auto add = first0.add_proposal(key_packages[1]);
  auto [commit, welcome, first1_] =
    first0.commit(fresh_secret(), CommitOpts{ { add }, true, false, {} }, {});
  silence_unused(commit);
  auto first1 = first1_;

  // Initialize the second participant from the Welcome
  auto second0 = State{ init_privs[1],
                        leaf_privs[1],
                        identity_privs[1],
                        key_packages[1],
                        welcome,
                        std::nullopt,
                        {} };
  REQUIRE(first1 == second0);

  auto group = std::vector<State>{ first1, second0 };
  verify_group_functionality(group);
}

TEST_CASE_FIXTURE(StateTest, "Two Person with New Member Add")
{
  // Initialize the creator's state
  auto first0 = State{ group_id,
                       suite,
                       leaf_privs[0],
                       identity_privs[0],
                       key_packages[0].leaf_node,
                       {} };

  // Have the new member create an Add proposal
  auto add =
    State::new_member_add(group_id, 0, key_packages[1], identity_privs[1]);
  first0.handle(add);
  auto opts = CommitOpts{ {}, true, false, {} };
  auto [commit, welcome, first1_] = first0.commit(fresh_secret(), opts, {});
  silence_unused(commit);
  auto first1 = first1_;

  // Initialize the second participant from the Welcome
  auto second0 = State{ init_privs[1],
                        leaf_privs[1],
                        identity_privs[1],
                        key_packages[1],
                        welcome,
                        std::nullopt,
                        {} };
  REQUIRE(first1 == second0);

  auto group = std::vector<State>{ first1, second0 };
  verify_group_functionality(group);
}

TEST_CASE_FIXTURE(StateTest, "Two Person with External Proposal")
{
  // Initialize the creator's state, with two trusted external parties
  auto external_priv_0 = SignaturePrivateKey::generate(suite);
  auto external_priv_1 = SignaturePrivateKey::generate(suite);

  auto ext_list = ExtensionList{};
  ext_list.add(ExternalSendersExtension{ {
    { external_priv_0.public_key, Credential::basic({ 0 }) },
    { external_priv_1.public_key, Credential::basic({ 1 }) },
  } });

  auto first0 = State{ group_id,
                       suite,
                       leaf_privs[0],
                       identity_privs[0],
                       key_packages[0].leaf_node,
                       ext_list };

  // Have the first external signer generate an add proposal
  auto add_proposal = Proposal{ Add{ key_packages[1] } };
  auto add =
    external_proposal(suite, group_id, 0, add_proposal, 1, external_priv_1);

  // Handle the Add proposal and create a Commit
  first0.handle(add);
  auto opts = CommitOpts{ {}, true, false, {} };
  auto [commit, welcome, first1_] = first0.commit(fresh_secret(), opts, {});
  silence_unused(commit);
  auto first1 = first1_;

  // Initialize the second participant from the Welcome
  auto second0 = State{ init_privs[1],
                        leaf_privs[1],
                        identity_privs[1],
                        key_packages[1],
                        welcome,
                        std::nullopt,
                        {} };
  REQUIRE(first1 == second0);

  auto group = std::vector<State>{ first1, second0 };
  verify_group_functionality(group);
}

TEST_CASE_FIXTURE(StateTest, "Two Person with custom extensions")
{
  // Initialize the creator's state
  auto first_exts = ExtensionList{};
  first_exts.add(CustomExtension{ 0xa0 });

  auto first0 = State{ group_id,
                       suite,
                       leaf_privs[0],
                       identity_privs[0],
                       key_packages[0].leaf_node,
                       first_exts };

  // Handle the Add proposal and create a Commit
  auto add = first0.add_proposal(key_packages[1]);
  auto [commit1, welcome1, first1_] =
    first0.commit(fresh_secret(), CommitOpts{ { add }, true, false, {} }, {});
  auto first1 = first1_;
  silence_unused(commit1);

  // Initialize the second participant from the Welcome
  auto second1 = State{ init_privs[1],
                        leaf_privs[1],
                        identity_privs[1],
                        key_packages[1],
                        welcome1,
                        std::nullopt,
                        {} };
  REQUIRE(first1 == second1);
  REQUIRE(first1.extensions() == first_exts);

  auto group = std::vector<State>{ first1, second1 };
  verify_group_functionality(group);

  // Change the group's extensions
  auto second_exts = ExtensionList{};
  second_exts.add(CustomExtension2{ 0xb0 });

  auto gce = first1.group_context_extensions_proposal(second_exts);
  auto [commit2, welcome2, first2_] =
    first1.commit(fresh_secret(), CommitOpts{ { gce }, false, false, {} }, {});
  auto second2 = second1.handle(commit2);
  silence_unused(welcome2);
  auto first2 = first2_;
  REQUIRE(first2 == second2);
  REQUIRE(first2.extensions() == second_exts);
}

TEST_CASE_FIXTURE(StateTest, "Two Person with external tree for welcome")
{
  // Initialize the creator's state
  auto first0 = State{ group_id,
                       suite,
                       leaf_privs[0],
                       identity_privs[0],
                       key_packages[0].leaf_node,
                       {} };

  // Handle the Add proposal and create a Commit
  auto add = first0.add_proposal(key_packages[1]);
  // Don't generate RatchetTree extension
  auto [commit, welcome_, first1_] =
    first0.commit(fresh_secret(), CommitOpts{ { add }, false, false, {} }, {});
  auto welcome = welcome_;
  auto first1 = first1_;
  silence_unused(commit);

  // Initialize the second participant from the Welcome, pass in the
  // tree externally
  // NOLINTNEXTLINE(llvm-else-after-return,readability-else-after-return)
  CHECK_THROWS_AS(State(init_privs[1],
                        leaf_privs[1],
                        identity_privs[1],
                        key_packages[1],
                        welcome,
                        std::nullopt,
                        {}),
                  InvalidParameterError);

  auto incorrect_tree = TreeKEMPublicKey(suite);
  incorrect_tree.add_leaf(key_packages[1].leaf_node);
  // NOLINTNEXTLINE(llvm-else-after-return,readability-else-after-return)
  CHECK_THROWS_AS(State(init_privs[1],
                        leaf_privs[1],
                        identity_privs[1],
                        key_packages[1],
                        welcome,
                        incorrect_tree,
                        {}),
                  InvalidParameterError);

  auto second0 = State{ init_privs[1],
                        leaf_privs[1],
                        identity_privs[1],
                        key_packages[1],
                        welcome,
                        first1.tree(),
                        {} };
  REQUIRE(first1 == second0);

  auto group = std::vector<State>{ first1, second0 };
  verify_group_functionality(group);
}

TEST_CASE_FIXTURE(StateTest, "Two Person with PSK")
{
  const auto psk_id = from_ascii("external psk");
  const auto psk_secret = from_ascii("super secret");
  const auto psks = std::map<bytes, bytes>{ { psk_id, psk_secret } };

  // Initialize the creator's state
  auto first0 = State{ group_id,
                       suite,
                       leaf_privs[0],
                       identity_privs[0],
                       key_packages[0].leaf_node,
                       {} };

  // Install the PSK on the creator
  first0.add_external_psk(psk_id, psk_secret);

  // Create a Commit over Add and PSK proposals
  auto add = first0.add_proposal(key_packages[1]);
  auto psk = first0.pre_shared_key_proposal(psk_id);
  auto [commit, welcome, first1_] = first0.commit(
    fresh_secret(), CommitOpts{ { add, psk }, true, false, {} }, {});
  silence_unused(commit);
  auto first1 = first1_;

  // Initialize the second participant from the Welcome
  auto second0 = State{
    init_privs[1], leaf_privs[1], identity_privs[1], key_packages[1], welcome,
    std::nullopt,  psks
  };
  REQUIRE(first1 == second0);
}

TEST_CASE_FIXTURE(StateTest, "External Join")
{
  // Initialize the creator's state
  auto first0 = State{ group_id,
                       suite,
                       leaf_privs[0],
                       identity_privs[0],
                       key_packages[0].leaf_node,
                       {} };
  auto group_info = first0.group_info(true);

  // Initialize the second participant as an external joiner
  auto [commit, second1] = State::external_join(fresh_secret(),
                                                identity_privs[1],
                                                key_packages[1],
                                                group_info,
                                                std::nullopt,
                                                {},
                                                std::nullopt,
                                                {});

  // Creator processes the commit
  auto first1 = opt::get(first0.handle(commit));

  auto group = std::vector<State>{ first1, second1 };
  verify_group_functionality(group);
}

TEST_CASE_FIXTURE(StateTest, "External Join with External Tree")
{
  // Initialize the creator's state
  auto first0 = State{ group_id,
                       suite,
                       leaf_privs[0],
                       identity_privs[0],
                       key_packages[0].leaf_node,
                       {} };
  auto group_info = first0.group_info(false);
  auto tree = first0.tree();

  // Initialize the second participant as an external joiner
  auto [commit, second1] = State::external_join(fresh_secret(),
                                                identity_privs[1],
                                                key_packages[1],
                                                group_info,
                                                tree,
                                                {},
                                                std::nullopt,
                                                {});

  // Creator processes the commit
  auto first1 = opt::get(first0.handle(commit));

  auto group = std::vector<State>{ first1, second1 };
  verify_group_functionality(group);
}

TEST_CASE_FIXTURE(StateTest, "External Join with PSK")
{
  // Initialize the creator's state
  auto first0 = State{ group_id,
                       suite,
                       leaf_privs[0],
                       identity_privs[0],
                       key_packages[0].leaf_node,
                       {} };
  auto group_info = first0.group_info(true);

  // Inject a PSK
  auto psk_id = from_ascii("pre shared key");
  auto psk_secret = random_bytes(suite.secret_size());
  first0.add_external_psk(psk_id, psk_secret);

  auto psks = std::map<bytes, bytes>{};
  psks.insert_or_assign(psk_id, psk_secret);

  // Initialize the second participant as an external joiner
  auto [commit, second1] = State::external_join(fresh_secret(),
                                                identity_privs[1],
                                                key_packages[1],
                                                group_info,
                                                std::nullopt,
                                                {},
                                                std::nullopt,
                                                psks);

  // Creator processes the commit
  auto first1 = opt::get(first0.handle(commit));

  auto group = std::vector<State>{ first1, second1 };
  verify_group_functionality(group);
}

TEST_CASE_FIXTURE(StateTest, "External Join with Eviction of Prior Appearance")
{
  // Initialize the creator's state
  auto first0 = State{ group_id,
                       suite,
                       leaf_privs[0],
                       identity_privs[0],
                       key_packages[0].leaf_node,
                       {} };

  // Add the second participant
  auto add = first0.add_proposal(key_packages[1]);
  auto [commit1, welcome1, first1] =
    first0.commit(fresh_secret(), CommitOpts{ { add }, true, false, {} }, {});
  silence_unused(commit1);
  auto second1 = State{ init_privs[1],
                        leaf_privs[1],
                        identity_privs[1],
                        key_packages[1],
                        welcome1,
                        std::nullopt,
                        {} };

  auto group1 = std::vector<State>{ first1, second1 };
  verify_group_functionality(group1);

  // First participant resyncs
  auto group_info = first1.group_info(true);
  auto [commit2, first2_] = State::external_join(fresh_secret(),
                                                 identity_privs[2],
                                                 key_packages[2],
                                                 group_info,
                                                 std::nullopt,
                                                 {},
                                                 LeafIndex{ 0 },
                                                 {});
  auto first2 = first2_;
  auto second2 = opt::get(second1.handle(commit2));

  // Check that the group is coherent
  auto group2 = std::vector<State>{ first2, second2 };
  verify_group_functionality(group2);

  // Check that the old appeareance is gone
  REQUIRE(first2.roster().size() == 2);
}

TEST_CASE_FIXTURE(StateTest, "SFrame Parameter Negotiation")
{
  // Set the SFrame parameters for the group
  auto specified_params = SFrameParameters{ 1, 8 };
  auto group_extensions = ExtensionList{};
  group_extensions.add(specified_params);

  // Create two clients that support the SFrame extension
  auto [init0, leaf0, id0, kp0] = make_client();
  kp0.leaf_node.capabilities.extensions.push_back(SFrameParameters::type);
  kp0.leaf_node.sign(suite, id0, std::nullopt);
  kp0.sign(id0);

  auto [init1, leaf1, id1, kp1] = make_client();
  kp1.leaf_node.capabilities.extensions.push_back(SFrameParameters::type);
  kp1.leaf_node.sign(suite, id1, std::nullopt);
  kp1.sign(id1);

  // Create the initial state of the group
  auto first0 =
    State{ group_id, suite, leaf0, id0, kp0.leaf_node, group_extensions };

  // Add the second member
  auto add = first0.add_proposal(kp1);
  auto [commit, welcome, first1_] =
    first0.commit(fresh_secret(), CommitOpts{ { add }, true, false, {} }, {});
  auto first1 = first1_;
  silence_unused(commit);

  auto second0 = State{ init1, leaf1, id1, kp1, welcome, std::nullopt, {} };
  REQUIRE(first1 == second0);

  auto group = std::vector<State>{ first1, second0 };
  verify_group_functionality(group);

  // Check that both participants have the  correct SFrame parameters
  auto first_params = first1.extensions().find<SFrameParameters>();
  auto second_params = second0.extensions().find<SFrameParameters>();
  REQUIRE(first_params);
  REQUIRE(second_params);
  REQUIRE(opt::get(first_params) == specified_params);
  REQUIRE(opt::get(first_params) == opt::get(second_params));
}

TEST_CASE_FIXTURE(StateTest, "Enforce Required Capabilities")
{
  // Require some capabilities that don't exist
  auto exotic_extension = uint16_t(0xffff);
  auto exotic_proposal = uint16_t(0xfffe);
  auto required_capabilities =
    RequiredCapabilitiesExtension{ { exotic_extension }, { exotic_proposal } };
  auto group_extensions = ExtensionList{};
  group_extensions.add(required_capabilities);

  auto extended_capabilities = Capabilities::create_default();
  extended_capabilities.extensions.push_back(exotic_extension);
  extended_capabilities.proposals.push_back(exotic_proposal);

  // One client that supports the required capabilities, and two that do
  auto [init_no, leaf_no_, id_no_, kp_no_] = make_client();
  silence_unused(init_no);
  auto leaf_no = leaf_no_;
  auto id_no = id_no_;
  auto kp_no = kp_no_;

  auto [init_yes, leaf_yes, id_yes, kp_yes] = make_client();
  kp_yes.leaf_node.set_capabilities(extended_capabilities);
  kp_yes.leaf_node.sign(suite, id_yes, std::nullopt);
  kp_yes.sign(id_yes);

  auto [init_yes_2, leaf_yes_2, id_yes_2, kp_yes_2] = make_client();
  kp_yes_2.leaf_node.set_capabilities(extended_capabilities);
  kp_yes_2.leaf_node.sign(suite, id_yes_2, std::nullopt);
  kp_yes_2.sign(id_yes_2);

  // Creating a group with a first member that doesn't support the
  // required capabilities should fail.
  // NOLINTNEXTLINE(llvm-else-after-return,readability-else-after-return)
  REQUIRE_THROWS(State{
    group_id, suite, leaf_no, id_no, kp_no.leaf_node, group_extensions });

  // State should refuse to create an Add for a new member that doesn't
  // support the required capabilities for the group.
  auto state = State{ group_id,         suite,           leaf_yes, id_yes,
                      kp_yes.leaf_node, group_extensions };
  // NOLINTNEXTLINE(llvm-else-after-return,readability-else-after-return)
  REQUIRE_THROWS(state.add_proposal(kp_no));

  // When State receives an add proposal for a new member that doesn't
  // support the required capabilities for the group, it should reject
  // it.
  //
  // TODO(RLB) We do not test this check right now, since it requires
  // either (a) configuring State to generate an invalid Add, or (b)
  // synthesizing one.

  // When a client is added who does support the required extensions, it
  // should work.
  state.handle(state.add(kp_yes_2, msg_opts));
}

TEST_CASE_FIXTURE(StateTest, "Add Multiple Members")
{
  // Initialize the creator's state
  states.emplace_back(group_id,
                      suite,
                      leaf_privs[0],
                      identity_privs[0],
                      key_packages[0].leaf_node,
                      ExtensionList{});

  // Create and process an Add proposal for each new participant
  auto adds = std::vector<Proposal>{};
  for (size_t i = 1; i < group_size; i += 1) {
    adds.push_back(states[0].add_proposal(key_packages[i]));
  }

  // Create a Commit that adds everybody
  auto [commit, welcome, new_state] =
    states[0].commit(fresh_secret(), CommitOpts{ adds, true, false, {} }, {});
  silence_unused(commit);
  states[0] = new_state;

  // Initialize the new joiners from the welcome
  for (size_t i = 1; i < group_size; i += 1) {
    states.push_back({ init_privs[i],
                       leaf_privs[i],
                       identity_privs[i],
                       key_packages[i],
                       welcome,
                       std::nullopt,
                       {} });
  }

  verify_group_functionality(states);
}

TEST_CASE_FIXTURE(StateTest, "Full Size Group")
{
  // Initialize the creator's state
  states.emplace_back(group_id,
                      suite,
                      leaf_privs[0],
                      identity_privs[0],
                      key_packages[0].leaf_node,
                      ExtensionList{});

  // Each participant invites the next
  for (size_t i = 1; i < group_size; i += 1) {
    auto sender = i - 1;

    auto add = states[sender].add_proposal(key_packages[i]);
    auto [commit, welcome, new_state] = states[sender].commit(
      fresh_secret(), CommitOpts{ { add }, true, false, {} }, {});
    for (size_t j = 0; j < states.size(); j += 1) {
      if (j == sender) {
        states[j] = new_state;
      } else {
        states[j] = opt::get(states[j].handle(commit));
      }
    }

    states.push_back({ init_privs[i],
                       leaf_privs[i],
                       identity_privs[i],
                       key_packages[i],
                       welcome,
                       std::nullopt,
                       {} });

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
    states.emplace_back(group_id,
                        suite,
                        leaf_privs[0],
                        identity_privs[0],
                        key_packages[0].leaf_node,
                        ExtensionList{});

    auto adds = std::vector<Proposal>{};
    for (size_t i = 1; i < group_size; i += 1) {
      adds.push_back(states[0].add_proposal(key_packages[i]));
    }

    auto [commit, welcome, new_state] =
      states[0].commit(fresh_secret(), CommitOpts{ adds, true, false, {} }, {});
    silence_unused(commit);
    states[0] = new_state;
    for (size_t i = 1; i < group_size; i += 1) {
      states.push_back({ init_privs[i],
                         leaf_privs[i],
                         identity_privs[i],
                         key_packages[i],
                         welcome,
                         std::nullopt,
                         {} });
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
    auto [commit, welcome, new_state] = states[i].commit(new_leaf, {}, {});
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

TEST_CASE_FIXTURE(RunningGroupTest, "Update Everyone in a Group")
{
  for (size_t i = 0; i < group_size; i += 1) {
    auto committer_index = (i + 1) % group_size;
    auto& updater = states.at(i);
    auto& committer = states.at(committer_index);

    auto update_priv = HPKEPrivateKey::generate(suite);
    auto update = updater.update(std::move(update_priv), {}, {});

    committer.handle(update);
    auto [commit, welcome, new_state] =
      committer.commit(fresh_secret(), {}, {});
    silence_unused(welcome);

    for (auto& state : states) {
      if (state.index().val == committer_index) {
        state = new_state;
      } else {
        state.handle(update);
        state = opt::get(state.handle(commit));
      }
    }

    check_consistency();
  }
}

TEST_CASE_FIXTURE(RunningGroupTest, "Add a PSK from Everyone in a Group")
{
  for (uint32_t i = 0; i < group_size; i += 1) {
    auto psk_id = tls::marshal(i);
    auto psk_secret = suite.derive_secret(psk_id, "psk secret");
    states[i].add_external_psk(psk_id, psk_secret);

    auto psk = states[i].pre_shared_key_proposal(psk_id);
    auto [commit, welcome, new_state] = states[i].commit(
      fresh_secret(), CommitOpts{ { psk }, false, false, {} }, {});
    silence_unused(welcome);

    for (auto& state : states) {
      if (state.index().val == i) {
        state = new_state;
      } else {
        state.add_external_psk(psk_id, psk_secret);
        state = opt::get(state.handle(commit));
      }
    }

    check_consistency();
  }
}

TEST_CASE_FIXTURE(RunningGroupTest, "Remove Members from a Group")
{
  for (uint32_t i = uint32_t(group_size) - 2; i > 0; i -= 1) {
    auto remove = states[i].remove_proposal(LeafIndex{ i + 1 });
    auto [commit, welcome, new_state] = states[i].commit(
      fresh_secret(), CommitOpts{ { remove }, false, false, {} }, {});
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
    return stdx::transform<Credential>(
      kps, [](const auto& leaf) { return leaf.credential; });
  };

  // remove member at position 1
  auto remove_1 = states[0].remove_proposal(RosterIndex{ 1 });
  auto [commit_1, welcome_1, new_state_1_] = states[0].commit(
    fresh_secret(), CommitOpts{ { remove_1 }, true, false, {} }, {});
  auto new_state_1 = new_state_1_;
  silence_unused(welcome_1);
  silence_unused(commit_1);
  // roster should be 0, 2, 3, 4
  auto expected_creds = std::vector<Credential>{
    key_packages[0].leaf_node.credential,
    key_packages[2].leaf_node.credential,
    key_packages[3].leaf_node.credential,
    key_packages[4].leaf_node.credential,
  };
  REQUIRE(expected_creds == get_creds(new_state_1.roster()));

  // remove member at position 2
  auto remove_2 = new_state_1.remove_proposal(RosterIndex{ 2 });
  auto [commit_2, welcome_2, new_state_2_] = new_state_1.commit(
    fresh_secret(), CommitOpts{ { remove_2 }, true, false, {} }, {});
  auto new_state_2 = new_state_2_;
  silence_unused(welcome_2);
  // roster should be 0, 2, 4
  expected_creds = std::vector<Credential>{
    key_packages[0].leaf_node.credential,
    key_packages[2].leaf_node.credential,
    key_packages[4].leaf_node.credential,
  };

  REQUIRE(expected_creds == get_creds(new_state_2.roster()));

  // handle remove by remaining clients and verify the roster
  for (int i = 2; i < static_cast<int>(group_size); i += 1) {
    if (i == 3) {
      // skip since we removed
      continue;
    }

    states[i] = opt::get(states[i].handle(commit_1));
    states[i] = opt::get(states[i].handle(commit_2));
    REQUIRE(expected_creds == get_creds(states[i].roster()));
  }
}

class RelatedGroupTest : public RunningGroupTest
{
protected:
  std::vector<HPKEPrivateKey> new_init_privs;
  std::vector<HPKEPrivateKey> new_leaf_privs;
  std::vector<SignaturePrivateKey> new_identity_privs;
  std::vector<KeyPackage> new_key_packages;

  RelatedGroupTest()
  {
    for (size_t i = 0; i < group_size; i += 1) {
      auto [init_priv, leaf_priv, identity_priv, key_package] = make_client();
      new_init_privs.push_back(init_priv);
      new_leaf_privs.push_back(leaf_priv);
      new_identity_privs.push_back(identity_priv);
      new_key_packages.push_back(key_package);
    }
  }
};

TEST_CASE_FIXTURE(RelatedGroupTest, "Branch the group")
{
  // Note the epoch authenticator before we branch
  auto original_epoch_authenticator = states[0].epoch_authenticator();

  // Member 0 generates a Branch welcome
  auto new_states = std::vector<State>{};

  auto branch_key_packages = std::vector<KeyPackage>(
    new_key_packages.begin() + 1, new_key_packages.end());
  auto [new_state_0, welcome] =
    states[0].create_branch(from_ascii("branched group"),
                            new_leaf_privs[0],
                            new_identity_privs[0],
                            new_key_packages[0].leaf_node,
                            {},
                            branch_key_packages,
                            random_bytes(suite.secret_size()),
                            {});

  new_states.push_back(std::move(new_state_0));
  auto tree = new_states[0].tree();

  // The other members process the welcome
  for (uint32_t i = 1; i < group_size; i++) {
    auto new_state = states[i].handle_branch(new_init_privs[i],
                                             new_leaf_privs[i],
                                             new_identity_privs[i],
                                             new_key_packages[i],
                                             welcome,
                                             tree);
    new_states.push_back(new_state);
  }

  // Verify that the old group is unperturbed
  verify_group_functionality(states);
  for (const auto& state : states) {
    REQUIRE(state.epoch_authenticator() == original_epoch_authenticator);
  }

  // Verify that the new group works
  verify_group_functionality(new_states);
  for (const auto& state : new_states) {
    REQUIRE(state == new_states[0]);
    REQUIRE(state.epoch_authenticator() != original_epoch_authenticator);
  }
}

TEST_CASE_FIXTURE(RelatedGroupTest, "Reinitialize the group")
{
  // Member 0 proposes reinitialization with a new group ID
  auto new_group_id = from_ascii("reinitialized group");
  auto reinit_proposal =
    states[0].reinit(new_group_id, ProtocolVersion::mls10, suite, {}, {});
  for (auto& state : states) {
    state.handle(reinit_proposal);
  }

  // Member 1 generates a ReInit Commit
  auto leaf_secret = random_bytes(suite.secret_size());
  auto [tombstone_1, reinit_commit] =
    states[1].reinit_commit(leaf_secret, {}, {});

  // The other members process the ReInit Commit
  auto tombstones = std::vector<State::Tombstone>{};
  for (uint32_t i = 0; i < group_size; i++) {
    if (i == 1) {
      tombstones.push_back(tombstone_1);
      continue;
    }

    auto tombstone = states[i].handle_reinit_commit(reinit_commit);
    tombstones.push_back(tombstone);
  }

  for (const auto& tombstone : tombstones) {
    REQUIRE(tombstone == tombstones[0]);
  }

  // Member 2 generates a Welcome message
  auto reinit_key_packages = std::vector<KeyPackage>{};
  for (uint32_t i = 0; i < group_size; i++) {
    if (i == 2) {
      continue;
    }

    reinit_key_packages.push_back(new_key_packages[i]);
  }

  auto [new_state_2, welcome] =
    tombstones[2].create_welcome(new_leaf_privs[2],
                                 new_identity_privs[2],
                                 new_key_packages[2].leaf_node,
                                 reinit_key_packages,
                                 random_bytes(suite.secret_size()),
                                 {});
  auto tree = new_state_2.tree();

  // The other members process the Welcome
  auto new_states = std::vector<State>{};
  for (uint32_t i = 0; i < group_size; i++) {
    if (i == 2) {
      new_states.push_back(new_state_2);
      continue;
    }

    auto new_state = tombstones[i].handle_welcome(new_init_privs[i],
                                                  new_leaf_privs[i],
                                                  new_identity_privs[i],
                                                  new_key_packages[i],
                                                  welcome,
                                                  tree);
    new_states.push_back(new_state);
  }

  // Verify that the new group works
  verify_group_functionality(new_states);
  for (const auto& state : new_states) {
    REQUIRE(state == new_states[0]);
  }
}
