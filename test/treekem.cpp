#include <doctest/doctest.h>
#include <hpke/random.h>
#include <mls/common.h>
#include <mls/treekem.h>
#include <mls_vectors/mls_vectors.h>

using namespace mls;
using namespace mls_vectors;

class TreeKEMTest
{
protected:
  const CipherSuite suite{ CipherSuite::ID::P256_AES128GCM_SHA256_P256 };

  std::tuple<HPKEPrivateKey, SignaturePrivateKey, KeyPackage> new_key_package()
  {
    auto init_priv = HPKEPrivateKey::generate(suite);
    auto sig_priv = SignaturePrivateKey::generate(suite);
    auto cred = Credential::basic({ 0, 1, 2, 3 }, suite, sig_priv.public_key);
    auto kp =
      KeyPackage{ suite, init_priv.public_key, cred, sig_priv, std::nullopt };
    return std::make_tuple(init_priv, sig_priv, kp);
  }
};

TEST_CASE_FIXTURE(TreeKEMTest, "ParentNode Equality")
{
  auto initA = HPKEPrivateKey::generate(suite);
  auto initB = HPKEPrivateKey::generate(suite);

  auto nodeA =
    ParentNode{ initA.public_key, { LeafIndex(1), LeafIndex(2) }, { 3, 4 } };
  auto nodeB =
    ParentNode{ initB.public_key, { LeafIndex(5), LeafIndex(6) }, { 7, 8 } };

  REQUIRE(nodeA == nodeA);
  REQUIRE(nodeB == nodeB);
  REQUIRE(nodeA != nodeB);
}

TEST_CASE_FIXTURE(TreeKEMTest, "Node public key")
{
  auto parent_priv = HPKEPrivateKey::generate(suite);
  auto parent = Node{ ParentNode{ parent_priv.public_key, {}, {} } };
  REQUIRE(parent.public_key() == parent_priv.public_key);

  auto [leaf_priv, sig_priv, kp] = new_key_package();
  silence_unused(sig_priv);

  auto leaf = Node{ kp };
  REQUIRE(leaf.public_key() == leaf_priv.public_key);
}

TEST_CASE_FIXTURE(TreeKEMTest, "Optional node hashes")
{
  const auto [init_priv, sig_priv, kp] = new_key_package();
  silence_unused(sig_priv);

  auto node_index = NodeIndex{ 7 };
  auto child_hash = bytes{ 0, 1, 2, 3, 4 };

  auto parent = ParentNode{ init_priv.public_key, {}, {} };
  auto opt_parent = OptionalNode{ Node{ parent }, {} };
  REQUIRE_THROWS_AS(opt_parent.set_tree_hash(suite, node_index),
                    var::bad_variant_access);

  opt_parent.set_tree_hash(suite, node_index, child_hash, child_hash);
  REQUIRE_FALSE(opt_parent.hash.empty());

  auto opt_leaf = OptionalNode{ Node{ kp }, {} };
  REQUIRE_THROWS_AS(
    opt_leaf.set_tree_hash(suite, node_index, child_hash, child_hash),
    var::bad_variant_access);

  opt_leaf.set_tree_hash(suite, node_index);
  REQUIRE_FALSE(opt_leaf.hash.empty());
}

TEST_CASE_FIXTURE(TreeKEMTest, "TreeKEM Private Key")
{
  const auto size = LeafCount{ 5 };
  const auto index = LeafIndex{ 2 };
  const auto intersect = NodeIndex{ 3 };
  const auto random = random_bytes(32);
  const auto random2 = random_bytes(32);
  const auto priv = HPKEPrivateKey::derive(suite, random);
  const auto hash_size = suite.digest().hash_size;

  // create() populates the direct path
  auto priv_create = TreeKEMPrivateKey::create(suite, size, index, random);
  REQUIRE(priv_create.path_secrets.find(NodeIndex(4)) !=
          priv_create.path_secrets.end());
  REQUIRE(priv_create.path_secrets.find(NodeIndex(5)) !=
          priv_create.path_secrets.end());
  REQUIRE(priv_create.path_secrets.find(NodeIndex(3)) !=
          priv_create.path_secrets.end());
  REQUIRE(priv_create.path_secrets.find(NodeIndex(7)) !=
          priv_create.path_secrets.end());
  REQUIRE(priv_create.update_secret.size() == hash_size);

  // joiner() populates the leaf and the path above the ancestor,
  // but not the direct path in the middle
  auto priv_joiner =
    TreeKEMPrivateKey::joiner(suite, size, index, priv, intersect, random);
  REQUIRE(priv_joiner.private_key(NodeIndex(4)));
  REQUIRE(priv_joiner.path_secrets.find(NodeIndex(3)) !=
          priv_joiner.path_secrets.end());
  REQUIRE(priv_joiner.path_secrets.find(NodeIndex(7)) !=
          priv_joiner.path_secrets.end());
  REQUIRE(priv_joiner.path_secrets.find(NodeIndex(5)) ==
          priv_joiner.path_secrets.end());
  REQUIRE(priv_joiner.update_secret.size() == hash_size);
  auto last_update_secret = priv_joiner.update_secret;

  // set_leaf_secret() properly sets the leaf secret
  priv_joiner.set_leaf_secret(random2);
  REQUIRE(priv_joiner.path_secrets.find(NodeIndex(index))->second == random2);
  REQUIRE(priv_joiner.update_secret.size() == hash_size);
  REQUIRE(priv_joiner.update_secret == last_update_secret);

  // shared_path_secret() finds the correct ancestor
  auto [overlap, overlap_secret, found] =
    priv_joiner.shared_path_secret(LeafIndex(0));
  REQUIRE(found);
  REQUIRE(overlap == NodeIndex(3));
  REQUIRE(overlap_secret == priv_joiner.path_secrets[overlap]);

  // private_key() generates and caches a private key where a path secret
  // exists, and returns nullopt where one doesn't
  auto priv_yes = priv_joiner.private_key(NodeIndex(3));
  REQUIRE(priv_yes);
  REQUIRE(priv_joiner.private_key_cache.find(NodeIndex(3)) !=
          priv_joiner.private_key_cache.end());

  auto priv_no = priv_joiner.private_key(NodeIndex(1));
  REQUIRE_FALSE(priv_no);
}

//        _
//    _
//  X   _
// X X _ X X
TEST_CASE_FIXTURE(TreeKEMTest, "TreeKEM Public Key")
{
  const auto size = LeafCount{ 5 };
  const auto removed = LeafIndex{ 2 };
  const auto root = tree_math::root(size);
  const auto root_resolution =
    std::vector<NodeIndex>{ NodeIndex{ 1 }, NodeIndex{ 6 }, NodeIndex{ 8 } };

  // Construct a full tree using add_leaf and merge
  auto pub = TreeKEMPublicKey{ suite };
  for (uint32_t i = 0; i < size.val; i++) {
    // Add a leaf
    auto [init_priv, sig_priv, kp_before] = new_key_package();
    silence_unused(init_priv);

    auto index = LeafIndex(i);
    auto curr_size = LeafCount(i + 1);

    auto add_index = pub.add_leaf(kp_before);
    REQUIRE(add_index == index);

    auto found = pub.find(kp_before);
    REQUIRE(found);
    REQUIRE(found == index);

    auto found_kp = pub.key_package(index);
    REQUIRE(found_kp);
    REQUIRE(found_kp == kp_before);

    // Manually construct a direct path to populate nodes above the new leaf
    auto path = UpdatePath{ kp_before, {} };
    auto dp = tree_math::dirpath(NodeIndex(index), curr_size);
    while (path.nodes.size() < dp.size()) {
      auto node_pub = HPKEPrivateKey::generate(suite).public_key;
      path.nodes.push_back({ node_pub, {} });
    }

    auto opts = KeyPackageOpts{};
    opts.extensions.add(ParentHashExtension{ from_ascii("bogus parent hash") });
    path.leaf_key_package.sign(sig_priv, opts);

    // Merge the direct path (ignoring parent hash validity)
    pub.merge(index, path);

    auto kp_after = path.leaf_key_package;
    found = pub.find(kp_after);
    REQUIRE(found);
    REQUIRE(found == index);
    for (const auto& dpn : dp) {
      REQUIRE(pub.node_at(dpn).node);
    }

    found_kp = pub.key_package(index);
    REQUIRE(found_kp);
    REQUIRE(found_kp == kp_after);
  }

  // Remove a node and verify that the resolution comes out right
  pub.blank_path(removed);
  REQUIRE_FALSE(pub.key_package(removed));
  REQUIRE(root_resolution == pub.resolve(root));
}

TEST_CASE_FIXTURE(TreeKEMTest, "TreeKEM encap/decap")
{
  const auto size = LeafCount{ 10 };

  auto pub = TreeKEMPublicKey{ suite };
  auto privs = std::vector<TreeKEMPrivateKey>{};
  auto sig_privs = std::vector<SignaturePrivateKey>{};

  // Add the first member
  auto [init_priv_0, sig_priv_0, kp0] = new_key_package();
  sig_privs.push_back(sig_priv_0);

  auto index_0 = pub.add_leaf(kp0);
  REQUIRE(index_0 == LeafIndex{ 0 });

  auto priv = TreeKEMPrivateKey::solo(suite, index_0, init_priv_0);
  privs.push_back(priv);
  REQUIRE(priv.consistent(pub));

  for (uint32_t i = 0; i < size.val - 2; i++) {
    auto adder = LeafIndex{ i };
    auto joiner = LeafIndex{ i + 1 };
    auto context = bytes{ uint8_t(i) };
    auto [init_priv, sig_priv, kp] = new_key_package();
    silence_unused(init_priv);
    sig_privs.push_back(sig_priv);

    // Add the new joiner
    auto index = pub.add_leaf(kp);
    REQUIRE(index == joiner);

    auto leaf_secret = random_bytes(32);
    auto [new_adder_priv, path] = pub.encap(
      adder, context, leaf_secret, sig_privs.back(), {}, std::nullopt);
    privs[i] = new_adder_priv;
    REQUIRE(pub.parent_hash_valid(adder, path));

    pub.merge(adder, path);
    REQUIRE(privs[i].consistent(pub));

    auto [overlap, path_secret, ok] = privs[i].shared_path_secret(joiner);
    REQUIRE(ok);

    // New joiner initializes their private key
    auto joiner_priv = TreeKEMPrivateKey::joiner(
      suite, pub.size(), joiner, init_priv, overlap, path_secret);
    privs.push_back(joiner_priv);
    REQUIRE(privs[i + 1].consistent(privs[i]));
    REQUIRE(privs[i + 1].consistent(pub));

    // Other members update via decap()
    for (uint32_t j = 0; j < i; j++) {
      privs[j].decap(adder, pub, context, path, {});
      REQUIRE(privs[j].consistent(privs[i]));
      REQUIRE(privs[j].consistent(pub));
    }
  }
}

TEST_CASE("TreeKEM Interop")
{
  for (auto suite : all_supported_suites) {
    auto tv = TreeKEMTestVector::create(suite, 10);
    tv.initialize_trees();
    REQUIRE(tv.verify() == std::nullopt);
  }
}
