#include "common.h"
#include "test_vectors.h"
#include "treekem.h"

#include <gtest/gtest.h>

using namespace mls;

class TreeKEMTest : public ::testing::Test
{
protected:
  const CipherSuite suite = CipherSuite::P256_SHA256_AES128GCM;
  const SignatureScheme scheme = SignatureScheme::Ed25519;

  const TreeKEMTestVectors tv;

  TreeKEMTest()
    : tv(TestLoader<TreeKEMTestVectors>::get())
  {}

  std::tuple<bytes, HPKEPrivateKey, SignaturePrivateKey, KeyPackage>
  new_key_package()
  {
    auto init_secret = random_bytes(32);
    auto init_priv = HPKEPrivateKey::derive(suite, init_secret);
    auto sig_priv = SignaturePrivateKey::generate(scheme);
    auto cred = Credential::basic({ 0, 1, 2, 3 }, sig_priv.public_key());
    auto kp = KeyPackage{ suite, init_priv.public_key(), cred, sig_priv };
    return std::make_tuple(init_secret, init_priv, sig_priv, kp);
  }
};

TEST_F(TreeKEMTest, ParentNodeEquals)
{
  auto initA = HPKEPrivateKey::generate(suite);
  auto initB = HPKEPrivateKey::generate(suite);

  auto nodeA =
    ParentNode{ initA.public_key(), { LeafIndex(1), LeafIndex(2) }, { 3, 4 } };
  auto nodeB =
    ParentNode{ initB.public_key(), { LeafIndex(5), LeafIndex(6) }, { 7, 8 } };

  ASSERT_EQ(nodeA, nodeA);
  ASSERT_EQ(nodeB, nodeB);
  ASSERT_NE(nodeA, nodeB);
}

TEST_F(TreeKEMTest, NodePublicKey)
{
  auto parent_priv = HPKEPrivateKey::generate(suite);
  auto parent = Node{ ParentNode{ parent_priv.public_key(), {}, {} } };
  ASSERT_EQ(parent.public_key(), parent_priv.public_key());

  auto [leaf_secret, leaf_priv, sig_priv, kp] = new_key_package();
  silence_unused(leaf_secret);
  silence_unused(sig_priv);

  auto leaf = Node{ kp };
  ASSERT_EQ(leaf.public_key(), leaf_priv.public_key());
}

TEST_F(TreeKEMTest, OptionalNodeHashes)
{
  const auto [init_secret, init_priv, sig_priv, kp] = new_key_package();
  silence_unused(init_secret);
  silence_unused(sig_priv);

  auto node_index = NodeIndex{ 7 };
  auto child_hash = bytes{ 0, 1, 2, 3, 4 };

  auto parent = ParentNode{ init_priv.public_key(), {}, {} };
  auto opt_parent = OptionalNode{ Node{ parent } };
  ASSERT_THROW(opt_parent.set_leaf_hash(suite, node_index),
               std::bad_variant_access);

  opt_parent.set_parent_hash(suite, node_index, child_hash, child_hash);
  ASSERT_FALSE(opt_parent.hash.empty());

  auto opt_leaf = OptionalNode{ Node{ kp } };
  ASSERT_THROW(
    opt_leaf.set_parent_hash(suite, node_index, child_hash, child_hash),
    std::bad_variant_access);

  opt_leaf.set_leaf_hash(suite, node_index);
  ASSERT_FALSE(opt_leaf.hash.empty());
}

TEST_F(TreeKEMTest, TreeKEMPrivateKey)
{
  const auto size = LeafCount{ 5 };
  const auto index = LeafIndex{ 2 };
  const auto intersect = NodeIndex{ 3 };
  const auto random = random_bytes(32);
  const auto random2 = random_bytes(32);

  // create() populates the direct path
  auto priv_create = TreeKEMPrivateKey::create(suite, size, index, random);
  ASSERT_NE(priv_create.path_secrets.find(NodeIndex(4)),
            priv_create.path_secrets.end());
  ASSERT_NE(priv_create.path_secrets.find(NodeIndex(5)),
            priv_create.path_secrets.end());
  ASSERT_NE(priv_create.path_secrets.find(NodeIndex(3)),
            priv_create.path_secrets.end());
  ASSERT_NE(priv_create.path_secrets.find(NodeIndex(7)),
            priv_create.path_secrets.end());

  // joiner() populates the leaf and the path above the ancestor,
  // but not the direct path in the middle
  auto priv_joiner =
    TreeKEMPrivateKey::joiner(suite, size, index, random, intersect, random);
  ASSERT_NE(priv_joiner.path_secrets.find(NodeIndex(4)),
            priv_joiner.path_secrets.end());
  ASSERT_NE(priv_joiner.path_secrets.find(NodeIndex(3)),
            priv_joiner.path_secrets.end());
  ASSERT_NE(priv_joiner.path_secrets.find(NodeIndex(7)),
            priv_joiner.path_secrets.end());
  ASSERT_EQ(priv_joiner.path_secrets.find(NodeIndex(5)),
            priv_joiner.path_secrets.end());

  // set_leaf_secret() properly sets the leaf secret
  priv_joiner.set_leaf_secret(random2);
  ASSERT_EQ(priv_joiner.path_secrets.find(NodeIndex(index))->second, random2);

  // shared_path_secret() finds the correct ancestor
  auto [overlap, overlap_secret, found] =
    priv_joiner.shared_path_secret(LeafIndex(0));
  ASSERT_TRUE(found);
  ASSERT_EQ(overlap, NodeIndex(3));
  ASSERT_EQ(overlap_secret, priv_joiner.path_secrets[overlap]);

  // private_key() generates and caches a private key where a path secret
  // exists, and returns nullopt where one doesn't
  auto priv_yes = priv_joiner.private_key(NodeIndex(3));
  ASSERT_TRUE(priv_yes.has_value());
  ASSERT_NE(priv_joiner.private_key_cache.find(NodeIndex(3)),
            priv_joiner.private_key_cache.end());

  auto priv_no = priv_joiner.private_key(NodeIndex(1));
  ASSERT_FALSE(priv_no.has_value());
}

//        _
//    _
//  X   _
// X X _ X X
TEST_F(TreeKEMTest, TreeKEMPublicKey)
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
      auto node_pub = HPKEPrivateKey::generate(suite).public_key();
      path.nodes.push_back({ node_pub, {} });
    }

    // Add the key package as a leaf
    auto add_index = pub.add_leaf(kp_add);
    ASSERT_EQ(add_index, index);

    auto found = pub.find(kp_add);
    ASSERT_TRUE(found.has_value());
    ASSERT_EQ(found.value(), index);

    auto found_kp = pub.key_package(index);
    ASSERT_TRUE(found_kp.has_value());
    ASSERT_EQ(found_kp.value(), kp_add);

    // Merge the direct path
    pub.merge(index, path);
    found = pub.find(kp_path);
    ASSERT_TRUE(found.has_value());
    ASSERT_EQ(found.value(), index);
    for (const auto dpn : dp) {
      ASSERT_TRUE(pub.node_at(dpn).node.has_value());
    }

    found_kp = pub.key_package(index);
    ASSERT_TRUE(found_kp.has_value());
    ASSERT_EQ(found_kp.value(), kp_path);
  }

  // Remove a node and verify that the resolution comes out right
  pub.blank_path(removed);
  ASSERT_FALSE(pub.key_package(removed).has_value());
  ASSERT_EQ(root_resolution, pub.resolve(root));
}

TEST_F(TreeKEMTest, EncapDecap)
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
  ASSERT_EQ(index_0, LeafIndex{ 0 });

  auto priv =
    TreeKEMPrivateKey::create(suite, pub.size(), index_0, init_secret_0);
  privs.push_back(priv);
  ASSERT_TRUE(priv.consistent(pub));

  for (uint32_t i = 0; i < size.val - 2; i++) {
    auto adder = LeafIndex{ i };
    auto joiner = LeafIndex{ i + 1 };
    auto context = bytes{ uint8_t(i) };
    auto [init_secret, init_priv, sig_priv, kp] = new_key_package();
    silence_unused(init_priv);
    sig_privs.push_back(sig_priv);

    // Add the new joiner
    auto index = pub.add_leaf(kp);
    ASSERT_EQ(index, joiner);

    auto leaf_secret = random_bytes(32);
    auto [new_adder_priv, path] =
      pub.encap(adder, context, leaf_secret, sig_privs.back(), std::nullopt);
    privs[i] = new_adder_priv;
    // TODO verify parent_hash_valid

    pub.merge(adder, path);
    ASSERT_TRUE(privs[i].consistent(pub));

    auto [overlap, path_secret, ok] = privs[i].shared_path_secret(joiner);
    ASSERT_TRUE(ok);

    // New joiner initializes their private key
    auto joiner_priv = TreeKEMPrivateKey::joiner(
      suite, pub.size(), joiner, init_secret, overlap, path_secret);
    privs.push_back(joiner_priv);
    ASSERT_TRUE(privs[i + 1].consistent(privs[i]));
    ASSERT_TRUE(privs[i + 1].consistent(pub));

    // Other members update via decap()
    for (uint32_t j = 0; j < i; j++) {
      privs[j].decap(adder, pub, context, path);
      ASSERT_TRUE(privs[j].consistent(privs[i]));
      ASSERT_TRUE(privs[j].consistent(pub));
    }
  }
}

TEST_F(TreeKEMTest, Interop)
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
      auto sig_priv = SignaturePrivateKey::derive(tc.signature_scheme,
                                                  tv.init_secrets[j].data);
      auto cred = Credential::basic(context, sig_priv.public_key());
      auto kp =
        KeyPackage{ tc.cipher_suite, init_priv.public_key(), cred, sig_priv };

      auto index = tree.add_leaf(kp);
      tree.encap(
        index, context, tv.leaf_secrets[j].data, sig_priv, std::nullopt);

      ASSERT_EQ(tc.trees[tci], tree);
    }

    // Blank out even-numbered leaves
    for (uint32_t j = 0; j < n_leaves; j += 2, ++tci) {
      tree.blank_path(LeafIndex{ j });
      ASSERT_EQ(tc.trees[tci], tree);
    }
  }
}
