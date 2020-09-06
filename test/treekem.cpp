#include "test_vectors.h"
#include <doctest/doctest.h>
#include <mls/common.h>
#include <mls/treekem.h>

using namespace mls;

class TreeKEMTest
{
protected:
  const CipherSuite suite{ CipherSuite::ID::P256_AES128GCM_SHA256_P256 };

  const TreeKEMTestVectors tv;

  TreeKEMTest()
    : tv(TestLoader<TreeKEMTestVectors>::get())
  {}

  std::tuple<bytes, HPKEPrivateKey, SignaturePrivateKey, KeyPackage>
  new_key_package()
  {
    auto init_secret = random_bytes(32);
    auto init_priv = HPKEPrivateKey::derive(suite, init_secret);
    auto sig_priv = SignaturePrivateKey::generate(suite);
    auto cred = Credential::basic({ 0, 1, 2, 3 }, sig_priv.public_key);
    auto kp = KeyPackage{ suite, init_priv.public_key, cred, sig_priv };
    return std::make_tuple(init_secret, init_priv, sig_priv, kp);
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

  auto [leaf_secret, leaf_priv, sig_priv, kp] = new_key_package();
  silence_unused(leaf_secret);
  silence_unused(sig_priv);

  auto leaf = Node{ kp };
  REQUIRE(leaf.public_key() == leaf_priv.public_key);
}

TEST_CASE_FIXTURE(TreeKEMTest, "Optional node hashes")
{
  const auto [init_secret, init_priv, sig_priv, kp] = new_key_package();
  silence_unused(init_secret);
  silence_unused(sig_priv);

  auto node_index = NodeIndex{ 7 };
  auto child_hash = bytes{ 0, 1, 2, 3, 4 };

  auto parent = ParentNode{ init_priv.public_key, {}, {} };
  auto opt_parent = OptionalNode{ Node{ parent }, {} };
  REQUIRE_THROWS_AS(opt_parent.set_leaf_hash(suite, node_index),
                    std::bad_variant_access);

  opt_parent.set_parent_hash(suite, node_index, child_hash, child_hash);
  REQUIRE_FALSE(opt_parent.hash.empty());

  auto opt_leaf = OptionalNode{ Node{ kp }, {} };
  REQUIRE_THROWS_AS(
    opt_leaf.set_parent_hash(suite, node_index, child_hash, child_hash),
    std::bad_variant_access);

  opt_leaf.set_leaf_hash(suite, node_index);
  REQUIRE_FALSE(opt_leaf.hash.empty());
}

TEST_CASE_FIXTURE(TreeKEMTest, "TreeKEM Private Key")
{
  const auto size = LeafCount{ 5 };
  const auto index = LeafIndex{ 2 };
  const auto intersect = NodeIndex{ 3 };
  const auto random = random_bytes(32);
  const auto random2 = random_bytes(32);

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

  // joiner() populates the leaf and the path above the ancestor,
  // but not the direct path in the middle
  auto priv_joiner =
    TreeKEMPrivateKey::joiner(suite, size, index, random, intersect, random);
  REQUIRE(priv_joiner.path_secrets.find(NodeIndex(4)) !=
          priv_joiner.path_secrets.end());
  REQUIRE(priv_joiner.path_secrets.find(NodeIndex(3)) !=
          priv_joiner.path_secrets.end());
  REQUIRE(priv_joiner.path_secrets.find(NodeIndex(7)) !=
          priv_joiner.path_secrets.end());
  REQUIRE(priv_joiner.path_secrets.find(NodeIndex(5)) ==
          priv_joiner.path_secrets.end());

  // set_leaf_secret() properly sets the leaf secret
  priv_joiner.set_leaf_secret(random2);
  REQUIRE(priv_joiner.path_secrets.find(NodeIndex(index))->second == random2);

  // shared_path_secret() finds the correct ancestor
  auto [overlap, overlap_secret, found] =
    priv_joiner.shared_path_secret(LeafIndex(0));
  REQUIRE(found);
  REQUIRE(overlap == NodeIndex(3));
  REQUIRE(overlap_secret == priv_joiner.path_secrets[overlap]);

  // private_key() generates and caches a private key where a path secret
  // exists, and returns nullopt where one doesn't
  auto priv_yes = priv_joiner.private_key(NodeIndex(3));
  REQUIRE(priv_yes.has_value());
  REQUIRE(priv_joiner.private_key_cache.find(NodeIndex(3)) !=
          priv_joiner.private_key_cache.end());

  auto priv_no = priv_joiner.private_key(NodeIndex(1));
  REQUIRE_FALSE(priv_no.has_value());
}

//        _
//    _
//  X   _
// X X _ X X
TEST_CASE_FIXTURE(TreeKEMTest, "TreeKEM Public Key")
{
  const auto size = LeafCount{ 5 };
  const auto removed = LeafIndex{ 2 };
  const auto root = tree_math::root(NodeCount(size));
  const auto root_resolution =
    std::vector<NodeIndex>{ NodeIndex{ 1 }, NodeIndex{ 6 }, NodeIndex{ 8 } };

  // Construct a full tree using add_leaf and merge
  auto pub = TreeKEMPublicKey{ suite };
  for (uint32_t i = 0; i < size.val; i++) {
    // Construct a key package and a direct path
    auto [init_secret_add, init_priv_add, sig_priv_add, kp_add] =
      new_key_package();
    silence_unused(init_secret_add);
    silence_unused(init_priv_add);
    silence_unused(sig_priv_add);

    auto [init_secret_path, init_priv_path, sig_priv_path, kp_path] =
      new_key_package();
    silence_unused(init_secret_path);
    silence_unused(init_priv_path);
    silence_unused(sig_priv_path);

    auto index = LeafIndex(i);
    auto curr_size = LeafCount(i + 1);

    auto path = DirectPath{ kp_path, {} };
    auto dp = tree_math::dirpath(NodeIndex(index), NodeCount(curr_size));
    while (path.nodes.size() < dp.size()) {
      auto node_pub = HPKEPrivateKey::generate(suite).public_key;
      path.nodes.push_back({ node_pub, {} });
    }

    // Add the key package as a leaf
    auto add_index = pub.add_leaf(kp_add);
    REQUIRE(add_index == index);

    auto found = pub.find(kp_add);
    REQUIRE(found.has_value());
    REQUIRE(found.value() == index);

    auto found_kp = pub.key_package(index);
    REQUIRE(found_kp.has_value());
    REQUIRE(found_kp.value() == kp_add);

    // Merge the direct path
    pub.merge(index, path);
    found = pub.find(kp_path);
    REQUIRE(found.has_value());
    REQUIRE(found.value() == index);
    for (const auto dpn : dp) {
      REQUIRE(pub.node_at(dpn).node.has_value());
    }

    found_kp = pub.key_package(index);
    REQUIRE(found_kp.has_value());
    REQUIRE(found_kp.value() == kp_path);
  }

  // Remove a node and verify that the resolution comes out right
  pub.blank_path(removed);
  REQUIRE_FALSE(pub.key_package(removed).has_value());
  REQUIRE(root_resolution == pub.resolve(root));
}

TEST_CASE_FIXTURE(TreeKEMTest, "TreeKEM encap/decap")
{
  const auto size = LeafCount{ 10 };

  auto pub = TreeKEMPublicKey{ suite };
  auto privs = std::vector<TreeKEMPrivateKey>{};
  auto sig_privs = std::vector<SignaturePrivateKey>{};

  // Add the first member
  auto [init_secret_0, init_priv_0, sig_priv_0, kp0] = new_key_package();
  silence_unused(init_priv_0);
  sig_privs.push_back(sig_priv_0);

  auto index_0 = pub.add_leaf(kp0);
  REQUIRE(index_0 == LeafIndex{ 0 });

  auto priv =
    TreeKEMPrivateKey::create(suite, pub.size(), index_0, init_secret_0);
  privs.push_back(priv);
  REQUIRE(priv.consistent(pub));

  for (uint32_t i = 0; i < size.val - 2; i++) {
    auto adder = LeafIndex{ i };
    auto joiner = LeafIndex{ i + 1 };
    auto context = bytes{ uint8_t(i) };
    auto [init_secret, init_priv, sig_priv, kp] = new_key_package();
    silence_unused(init_priv);
    sig_privs.push_back(sig_priv);

    // Add the new joiner
    auto index = pub.add_leaf(kp);
    REQUIRE(index == joiner);

    auto leaf_secret = random_bytes(32);
    auto [new_adder_priv, path] =
      pub.encap(adder, context, leaf_secret, sig_privs.back(), std::nullopt);
    privs[i] = new_adder_priv;
    // TODO(RLB) verify parent_hash_valid

    pub.merge(adder, path);
    REQUIRE(privs[i].consistent(pub));

    auto [overlap, path_secret, ok] = privs[i].shared_path_secret(joiner);
    REQUIRE(ok);

    // New joiner initializes their private key
    auto joiner_priv = TreeKEMPrivateKey::joiner(
      suite, pub.size(), joiner, init_secret, overlap, path_secret);
    privs.push_back(joiner_priv);
    REQUIRE(privs[i + 1].consistent(privs[i]));
    REQUIRE(privs[i + 1].consistent(pub));

    // Other members update via decap()
    for (uint32_t j = 0; j < i; j++) {
      privs[j].decap(adder, pub, context, path);
      REQUIRE(privs[j].consistent(privs[i]));
      REQUIRE(privs[j].consistent(pub));
    }
  }
}

TEST_CASE_FIXTURE(TreeKEMTest, "TreeKEM Interop")
{
  for (size_t i = 0; i < tv.cases.size(); ++i) {
    const auto& tc = tv.cases[i];

    TreeKEMPublicKey tree{ tc.cipher_suite };

    // Add the leaves
    uint32_t tci = 0;
    auto n_leaves = tv.leaf_secrets.size();
    for (uint32_t j = 0; j < n_leaves; ++j, ++tci) {
      auto context = bytes{ uint8_t(i), uint8_t(j) };
      auto init_priv =
        HPKEPrivateKey::derive(tc.cipher_suite, tv.init_secrets[j].data);
      auto sig_priv =
        SignaturePrivateKey::derive(tc.cipher_suite, tv.init_secrets[j].data);
      auto cred = Credential::basic(context, sig_priv.public_key);
      auto kp =
        KeyPackage{ tc.cipher_suite, init_priv.public_key, cred, sig_priv };

      auto index = tree.add_leaf(kp);
      tree.encap(
        index, context, tv.leaf_secrets[j].data, sig_priv, std::nullopt);

      REQUIRE(tc.trees[tci] == tree);
    }

    // Blank out even-numbered leaves
    for (uint32_t j = 0; j < n_leaves; j += 2, ++tci) {
      tree.blank_path(LeafIndex{ j });
      REQUIRE(tc.trees[tci] == tree);
    }
  }
}
