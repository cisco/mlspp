#include <catch2/catch_all.hpp>
#include <hpke/random.h>
#include <mls/common.h>
#include <mls/state.h>
#include <mls_ds/tree_follower.h>

using namespace MLS_NAMESPACE;
using namespace MLS_NAMESPACE::mls_ds;

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

TEST_CASE_METHOD(StateTest, "Two Person")
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

TEST_CASE_METHOD(StateTest, "Two Person with New Member Add")
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

TEST_CASE_METHOD(StateTest, "Two Person with External Proposal")
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

TEST_CASE_METHOD(StateTest, "Two Person with custom extensions")
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

TEST_CASE_METHOD(StateTest, "Two Person with external tree for welcome")
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

TEST_CASE_METHOD(StateTest, "Two Person with PSK")
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

TEST_CASE_METHOD(StateTest, "Two Person with Replacement")
{
  // Initialize the creator's state
  auto first0 = State{ group_id,
                       suite,
                       leaf_privs[0],
                       identity_privs[0],
                       key_packages[0].leaf_node,
                       {} };

  // Handle the Add proposal and create a Commit
  const auto add1 = first0.add_proposal(key_packages[1]);
  const auto [commit1, welcome1, first1_] =
    first0.commit(fresh_secret(), CommitOpts{ { add1 }, true, false, {} }, {});
  silence_unused(commit1);
  auto first1 = first1_;

  // Initialize the second participant from the Welcome
  auto second1 = State{ init_privs[1],
                        leaf_privs[1],
                        identity_privs[1],
                        key_packages[1],
                        welcome1,
                        std::nullopt,
                        {} };
  REQUIRE(first1 == second1);

  // Create a new appearance of the first member
  const auto [init_priv, leaf_priv, _identity_priv, key_package_] =
    make_client();
  const auto identity_priv = identity_privs[0];
  auto key_package = key_package_;
  key_package.leaf_node.signature_key = identity_priv.public_key;
  key_package.leaf_node.sign(suite, identity_priv, std::nullopt);
  key_package.sign(identity_priv);

  // Create a commit replacing the first member
  const auto remove2 = second1.remove_proposal(LeafIndex{ 0 });
  const auto add2 = second1.add_proposal(key_package);
  const auto [commit2, welcome2, second2_] = second1.commit(
    fresh_secret(), CommitOpts{ { add2, remove2 }, true, false, {} }, {});
  auto second2 = second2_;
  silence_unused(commit2);

  // Initialize the new first member from the Welcome
  const auto first2 =
    State{ init_priv,    leaf_priv, identity_priv, key_package, welcome2,
           std::nullopt, {} };
  REQUIRE(first2 == second2);

  auto group = std::vector<State>{ first2, second2 };
  verify_group_functionality(group);
}

TEST_CASE_METHOD(StateTest, "Light client can participate")
{
  // Initialize the creator's state
  auto first0 = State{ group_id,
                       suite,
                       leaf_privs[0],
                       identity_privs[0],
                       key_packages[0].leaf_node,
                       {} };

  // Add the second participant
  auto add1 = first0.add_proposal(key_packages[1]);
  auto [commit1, welcome1, first1_] =
    first0.commit(fresh_secret(), CommitOpts{ { add1 }, true, false, {} }, {});
  silence_unused(commit1);
  auto first1 = first1_;

  // Initialize the second participant from the Welcome.  Note that the second
  // participant is always a full client, because the membership proofs cover
  // the whole tree.
  auto second1 = State{ init_privs[1],
                        leaf_privs[1],
                        identity_privs[1],
                        key_packages[1],
                        welcome1,
                        std::nullopt,
                        {} };

  REQUIRE(second1.is_full_client());
  REQUIRE(first1 == second1);

  // Add the third participant
  auto add2 = first0.add_proposal(key_packages[2]);
  auto [commit2, welcome2, first2_] =
    first1.commit(fresh_secret(), CommitOpts{ { add2 }, false, false, {} }, {});
  auto first2 = first2_;
  const auto annotated_welcome = AnnotatedWelcome::from(
    welcome2, first2.tree(), LeafIndex{ 0 }, LeafIndex{ 2 });

  // Handle the Commit at the second participant
  auto second2 = opt::get(second1.handle(commit2));

  // Initialize the third participant as a light client, by only including
  // membership proofs in the Welcome, not the full tree
  auto third2 = State{ init_privs[2],
                       leaf_privs[2],
                       identity_privs[2],
                       key_packages[2],
                       annotated_welcome.welcome,
                       annotated_welcome.tree(),
                       {} };
  REQUIRE_FALSE(third2.is_full_client());

  REQUIRE(first2 == second2);
  REQUIRE(first2 == third2);

  // Create another commit and handle it at the second client
  auto [commit3, welcome3, first3_] = first2.commit(fresh_secret(), {}, {});
  silence_unused(welcome3);
  auto first3 = first3_;
  auto second3 = opt::get(second2.handle(commit3));

  // Verify that the light client refuses to process it on its own
  REQUIRE_THROWS(third2.handle(commit3));

  // Convert the Commit to an AnnotatedCommit
  auto annotated_commit = AnnotatedCommit::from(
    third2.index(), {}, commit3, first2.tree(), first3.tree());

  // Verify that the light client can process the commit with a commit map
  auto third3 = third2.handle(annotated_commit);

  REQUIRE(first3 == second3);
  REQUIRE(first3 == third3);

  // Upgrade the third client to be a full client
  third3.upgrade_to_full_client(first3.tree());
  REQUIRE(third3.is_full_client());

  // Verify that all three clients can now process a normal Commit
  auto [commit4, welcome4, first4_] = first3.commit(fresh_secret(), {}, {});
  silence_unused(welcome4);
  auto first4 = first4_;
  auto second4 = opt::get(second3.handle(commit4));
  auto third4 = opt::get(third3.handle(commit4));

  REQUIRE(first4 == second4);
  REQUIRE(first4 == third4);
}

TEST_CASE_METHOD(StateTest, "Light client can rejoin")
{
  // Initialize the creator's state
  auto first0 = State{ group_id,
                       suite,
                       leaf_privs[0],
                       identity_privs[0],
                       key_packages[0].leaf_node,
                       {} };

  // Add the second and third participants
  auto add1a = first0.add_proposal(key_packages[1]);
  auto add1b = first0.add_proposal(key_packages[2]);
  auto [commit1, welcome1, first1_] = first0.commit(
    fresh_secret(), CommitOpts{ { add1a, add1b }, true, false, {} }, {});
  silence_unused(commit1);
  auto first1 = first1_;

  auto third1 = State{ init_privs[2],
                       leaf_privs[2],
                       identity_privs[2],
                       key_packages[2],
                       welcome1,
                       std::nullopt,
                       {} };

  REQUIRE(first1 == third1);

  // Remove the second participant and re-add them in the same commit
  auto remove2 = first1.remove_proposal(LeafIndex{ 1 });
  auto add2 = first1.add_proposal(key_packages[1]);
  auto [commit2, welcome2, first2_] = first1.commit(
    fresh_secret(), CommitOpts{ { remove2, add2 }, false, false, {} }, {});
  silence_unused(welcome2);
  auto first2 = first2_;

  auto third2 = opt::get(third1.handle(commit2));

  REQUIRE(first2 == third2);

  // Second participant (re-)joins as a light client
  const auto annotated_welcome_2 = AnnotatedWelcome::from(
    welcome2, first2.tree(), LeafIndex{ 0 }, LeafIndex{ 1 });

  auto second2 = State{ init_privs[1],
                        leaf_privs[1],
                        identity_privs[1],
                        key_packages[1],
                        annotated_welcome_2.welcome,
                        annotated_welcome_2.tree(),
                        {} };

  REQUIRE(first2 == second2);
  REQUIRE_FALSE(second2.is_full_client());
}

TEST_CASE_METHOD(StateTest, "Light client can upgrade after several commits")
{
  // Initialize the first two users
  auto first0 = State{ group_id,
                       suite,
                       leaf_privs[0],
                       identity_privs[0],
                       key_packages[0].leaf_node,
                       {} };

  auto add1 = first0.add_proposal(key_packages[1]);
  auto [commit1, welcome1, first1_] =
    first0.commit(fresh_secret(), CommitOpts{ { add1 }, true, false, {} }, {});
  silence_unused(commit1);
  auto first1 = first1_;

  auto second1 = State{ init_privs[1],
                        leaf_privs[1],
                        identity_privs[1],
                        key_packages[1],
                        welcome1,
                        std::nullopt,
                        {} };

  REQUIRE(second1.is_full_client());
  REQUIRE(first1 == second1);

  // Add the third participant as a light client, remembering the tree at this
  // point.
  auto add2 = first0.add_proposal(key_packages[2]);
  auto [commit2, welcome2, first2_] =
    first1.commit(fresh_secret(), CommitOpts{ { add2 }, false, false, {} }, {});
  auto first2 = first2_;
  const auto annotated_welcome = AnnotatedWelcome::from(
    welcome2, first2.tree(), LeafIndex{ 0 }, LeafIndex{ 2 });

  auto second2 = opt::get(second1.handle(commit2));

  auto third2 = State{ init_privs[2],
                       leaf_privs[2],
                       identity_privs[2],
                       key_packages[2],
                       annotated_welcome.welcome,
                       annotated_welcome.tree(),
                       {} };
  REQUIRE_FALSE(third2.is_full_client());

  REQUIRE(first2 == second2);
  REQUIRE(first2 == third2);

  const auto tree2 = first2.tree();

  // Client 1 makes a bunch of commits, and the other two members follow along.
  auto first = first2;
  auto second = second2;
  auto third = third2;

  auto commits = std::vector<MLSMessage>{};
  const auto n_commits = size_t(5);
  for (auto i = size_t(0); i < n_commits; i++) {
    const auto [commit, welcome, next_first] =
      first.commit(fresh_secret(), {}, {});
    silence_unused(welcome);
    const auto annotated_commit = AnnotatedCommit::from(
      third.index(), {}, commit, first.tree(), next_first.tree());

    commits.push_back(commit);

    first = next_first;
    second = opt::get(second.handle(commit));
    third = third.handle(annotated_commit);

    REQUIRE(first == second);
    REQUIRE(first == third);
  }

  // Client 3 finally finishes downloading the tree, fast-forwards it using the
  // commit queue, and upgrades to being a full client.
  auto follower = TreeFollower(tree2);
  for (const auto& commit : commits) {
    follower.update(commit, {});
  }

  third.upgrade_to_full_client(follower.tree());
  REQUIRE(third.is_full_client());

  REQUIRE(first == second);
  REQUIRE(first == third);
}

TEST_CASE_METHOD(StateTest, "Light client can handle an external commit")
{
  // Initialize the first two users
  auto first0 = State{ group_id,
                       suite,
                       leaf_privs[0],
                       identity_privs[0],
                       key_packages[0].leaf_node,
                       {} };

  auto add1 = first0.add_proposal(key_packages[1]);
  auto [commit1, welcome1, first1_] =
    first0.commit(fresh_secret(), CommitOpts{ { add1 }, true, false, {} }, {});
  silence_unused(commit1);
  auto first1 = first1_;

  auto second1 = State{ init_privs[1],
                        leaf_privs[1],
                        identity_privs[1],
                        key_packages[1],
                        welcome1,
                        std::nullopt,
                        {} };

  REQUIRE(second1.is_full_client());
  REQUIRE(first1 == second1);

  // Add the third participant as a light client
  auto add2 = first0.add_proposal(key_packages[2]);
  auto [commit2, welcome2, first2_] =
    first1.commit(fresh_secret(), CommitOpts{ { add2 }, false, false, {} }, {});
  auto first2 = first2_;
  const auto annotated_welcome = AnnotatedWelcome::from(
    welcome2, first2.tree(), LeafIndex{ 0 }, LeafIndex{ 2 });

  auto second2 = opt::get(second1.handle(commit2));

  auto third2 = State{ init_privs[2],
                       leaf_privs[2],
                       identity_privs[2],
                       key_packages[2],
                       annotated_welcome.welcome,
                       annotated_welcome.tree(),
                       {} };
  REQUIRE_FALSE(third2.is_full_client());

  REQUIRE(first2 == second2);
  REQUIRE(first2 == third2);

  // The fourth participant joins via an external commit
  const auto group_info = first2.group_info(true);
  const auto [commit3, fourth3] = State::external_join(fresh_secret(),
                                                       identity_privs[3],
                                                       key_packages[3],
                                                       group_info,
                                                       std::nullopt,
                                                       {},
                                                       std::nullopt,
                                                       {});

  // Process the commit at the normal clients
  const auto first3 = opt::get(first2.handle(commit3));
  const auto second3 = opt::get(second2.handle(commit3));

  // Annotate the commit and handle it at the third client
  const auto annotated_commit = AnnotatedCommit::from(
    third2.index(), {}, commit3, first2.tree(), first3.tree());
  const auto third3 = third2.handle(annotated_commit);

  REQUIRE(first3 == second3);
  REQUIRE(first3 == third3);
  REQUIRE(first3 == fourth3);
}

TEST_CASE_METHOD(StateTest, "External Join")
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

TEST_CASE_METHOD(StateTest, "External Join with External Tree")
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

TEST_CASE_METHOD(StateTest, "External Join with PSK")
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

TEST_CASE_METHOD(StateTest, "External Join with Eviction of Prior Appearance")
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

TEST_CASE_METHOD(StateTest, "SFrame Parameter Negotiation")
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

TEST_CASE_METHOD(StateTest, "Enforce Required Capabilities")
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

TEST_CASE_METHOD(StateTest, "Add Multiple Members")
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

TEST_CASE_METHOD(StateTest, "Full Size Group")
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

TEST_CASE_METHOD(RunningGroupTest, "Update Everyone via Empty Commit")
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

TEST_CASE_METHOD(RunningGroupTest, "Update Everyone in a Group")
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

TEST_CASE_METHOD(RunningGroupTest, "Add a PSK from Everyone in a Group")
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

TEST_CASE_METHOD(RunningGroupTest, "Remove Members from a Group")
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

TEST_CASE_METHOD(RunningGroupTest, "Roster Updates")
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

TEST_CASE_METHOD(RelatedGroupTest, "Branch the group")
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

TEST_CASE_METHOD(RelatedGroupTest, "Reinitialize the group")
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

TEST_CASE_METHOD(StateTest, "Parent Hash with Empty Left Subtree")
{
  // Create a group with 4 members
  auto state_0 = State(group_id,
                       suite,
                       leaf_privs[0],
                       identity_privs[0],
                       key_packages[0].leaf_node,
                       ExtensionList{});

  const auto adds = std::vector{
    state_0.add_proposal(key_packages[1]),
    state_0.add_proposal(key_packages[2]),
    state_0.add_proposal(key_packages[3]),
  };

  auto [_commit0, welcome0, new_state_0] =
    state_0.commit(fresh_secret(), CommitOpts{ adds, true, false, {} }, {});
  silence_unused(_commit0);
  state_0 = new_state_0;

  auto state_2 = State(init_privs[2],
                       leaf_privs[2],
                       identity_privs[2],
                       key_packages[2],
                       welcome0,
                       std::nullopt,
                       {});
  // Member @2 removes the members on the left side of the tree
  const auto removes = std::vector{
    state_2.remove_proposal(LeafIndex{ 0 }),
    state_2.remove_proposal(LeafIndex{ 1 }),
  };

  auto [commit2, welcome2, new_state_2] =
    state_2.commit(fresh_secret(), CommitOpts{ removes, true, false, {} }, {});
  silence_unused(commit2);
  silence_unused(welcome2);
  state_2 = new_state_2;

  // Member @2 should have a valid tree, even though its filtered direct path no
  // longer goes to the root.
  REQUIRE(state_2.tree().parent_hash_valid());
}

class ExternalSenderTest : public StateTest
{
protected:
  const SignaturePrivateKey external_sig_priv =
    SignaturePrivateKey::generate(suite);
  const Credential external_sender_cred = Credential::basic({ 0 });
  const bytes psk_id = from_ascii("psk ID");
  ExtensionList group_extensions;

  ExternalSenderTest()
  {
    group_extensions.add(ExternalSendersExtension{ {
      { external_sig_priv.public_key, external_sender_cred },
    } });

    // Initialize the creator's state
    states.emplace_back(group_id,
                        suite,
                        leaf_privs[0],
                        identity_privs[0],
                        key_packages[0].leaf_node,
                        group_extensions);

    // Add a second member so that we can test removal proposal
    auto add = states[0].add_proposal(key_packages[1]);
    auto [commit, welcome, new_state] = states[0].commit(
      fresh_secret(), CommitOpts{ { add }, true, false, {} }, {});
    states[0] = new_state;

    silence_unused(commit);

    states.push_back({ init_privs[1],
                       leaf_privs[1],
                       identity_privs[1],
                       key_packages[1],
                       welcome,
                       std::nullopt,
                       {} });
  }

  PublicMessage GenerateExternalSenderProposal(const Proposal& proposal)
  {
    auto group_context = states[0].group_context();

    auto proposal_content = GroupContent{ group_context.group_id,
                                          group_context.epoch,
                                          { ExternalSenderIndex{ 0 } },
                                          {},
                                          proposal };

    auto content_auth_original =
      AuthenticatedContent::sign(WireFormat::mls_public_message,
                                 proposal_content,
                                 suite,
                                 external_sig_priv,
                                 group_context);

    return PublicMessage::protect(
      content_auth_original, suite, std::nullopt, group_context);
  }
};

TEST_CASE_METHOD(ExternalSenderTest,
                 "Allows Expected Proposals from External Sender")
{
  // For expected proposals, we ensure that calling State::handle with the
  // proposal does not throw an exception.

  // Add
  auto add_proposal = Proposal{ Add{ key_packages[2] } };
  auto ext_add_message = GenerateExternalSenderProposal(add_proposal);

  REQUIRE(!states[0].handle(ext_add_message).has_value());

  // Remove
  auto remove_proposal = Proposal{ Remove{ LeafIndex{ 1 } } };
  auto ext_remove_message = GenerateExternalSenderProposal(remove_proposal);

  REQUIRE(!states[0].handle(ext_remove_message).has_value());

  // PSK
  auto group_context = states[0].group_context();
  auto psk_proposal =
    Proposal{ PreSharedKey{ ResumptionPSK{ ResumptionPSKUsage::application,
                                           group_context.group_id,
                                           group_context.epoch },
                            random_bytes(suite.secret_size()) } };
  auto ext_psk_message = GenerateExternalSenderProposal(psk_proposal);

  REQUIRE(!states[0].handle(ext_psk_message).has_value());

  // ReInit
  auto updated_extensions = group_extensions;
  updated_extensions.add(CustomExtension{ 0xa0 });

  auto reinit_proposal = Proposal{ ReInit{ group_context.group_id,
                                           ProtocolVersion::mls10,
                                           group_context.cipher_suite,
                                           updated_extensions } };
  auto ext_reinit_message = GenerateExternalSenderProposal(reinit_proposal);

  REQUIRE(!states[0].handle(ext_reinit_message).has_value());

  // GroupContextExtensions

  auto group_context_proposal =
    Proposal{ GroupContextExtensions{ updated_extensions } };
  auto ext_group_context_message =
    GenerateExternalSenderProposal(group_context_proposal);

  REQUIRE(!states[0].handle(ext_group_context_message).has_value());
}

TEST_CASE_METHOD(ExternalSenderTest,
                 "Refuses Unexpected Proposals from External Sender")
{
  // For unexpected proposals, we ensure that calling State::handle with the
  // throws the expected exception.

  // The proposals throw bad_optional_access since the validation calls
  // opt::get(sender) on a nullopt sender

  // Update
  auto update_proposal = Proposal{ Update{ key_packages[1].leaf_node } };
  auto ext_update_message = GenerateExternalSenderProposal(update_proposal);

  REQUIRE_THROWS_WITH(states[0].handle(ext_update_message),
                      "Invalid external proposal");

  // ExternalInit
  auto group_info = states[0].group_info(false);
  auto maybe_external_pub = group_info.extensions.find<ExternalPubExtension>();

  REQUIRE(maybe_external_pub.has_value());

  const auto& external_pub = opt::get(maybe_external_pub).external_pub;

  auto [kem_output, force_init_secret] =
    KeyScheduleEpoch::external_init(suite, external_pub);
  silence_unused(force_init_secret);

  auto external_init_proposal = Proposal{ ExternalInit{ kem_output } };
  auto external_init_message =
    GenerateExternalSenderProposal(external_init_proposal);

  REQUIRE_THROWS_WITH(states[0].handle(external_init_message),
                      "Invalid external proposal");
}
