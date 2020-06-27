#include "common.h"
#include "treekem.h"

#include <gtest/gtest.h>

using namespace mls;

TEST(TreeKEMTest, ParentNodeEquals)
{
  const CipherSuite suite = CipherSuite::P256_SHA256_AES128GCM;
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

TEST(TreeKEMTest, NodePublicKey)
{
  const CipherSuite suite = CipherSuite::P256_SHA256_AES128GCM;
  auto initA = HPKEPrivateKey::generate(suite);
  auto initB = HPKEPrivateKey::generate(suite);

  auto parent = Node{ ParentNode{ initA.public_key(), {}, {} } };
  ASSERT_EQ(parent.public_key(), initA.public_key());

  const SignatureScheme scheme = SignatureScheme::Ed25519;
  auto identity_priv = SignaturePrivateKey::generate(scheme);
  auto cred = Credential::basic({ 0, 1, 2, 3 }, identity_priv.public_key());
  auto leaf =
    Node{ KeyPackage{ suite, initB.public_key(), identity_priv, cred } };
  ASSERT_EQ(leaf.public_key(), initB.public_key());
}

TEST(TreeKEMTest, OptionalNodeHashes)
{
  const CipherSuite suite = CipherSuite::P256_SHA256_AES128GCM;
  const SignatureScheme scheme = SignatureScheme::Ed25519;
  auto init_priv = HPKEPrivateKey::generate(suite);
  auto sig_priv = SignaturePrivateKey::generate(scheme);
  auto cred = Credential::basic({ 0, 1, 2, 3 }, sig_priv.public_key());

  auto node_index = NodeIndex(7);
  auto hash = bytes{ 0, 1, 2, 3, 4 };

  auto parent = ParentNode{ init_priv.public_key(), {}, {} };
  auto opt_parent = OptionalNode{ Node{ parent } };
  ASSERT_THROW(opt_parent.set_leaf_hash(suite, node_index),
               std::bad_variant_access);

  opt_parent.set_parent_hash(suite, node_index, hash, hash);
  ASSERT_FALSE(opt_parent.hash.empty());

  auto leaf = KeyPackage{ suite, init_priv.public_key(), sig_priv, cred };
  auto opt_leaf = OptionalNode{ Node{ leaf } };
  ASSERT_THROW(opt_leaf.set_parent_hash(suite, node_index, hash, hash),
               std::bad_variant_access);

  opt_leaf.set_leaf_hash(suite, node_index);
  ASSERT_FALSE(opt_leaf.hash.empty());
}

TEST(TreeKEMTest, TreeKEMPrivateKey)
{
  const CipherSuite suite = CipherSuite::P256_SHA256_AES128GCM;
  const LeafCount size{ 5 };
  const LeafIndex index{ 2 };
  const NodeIndex intersect{ 3 };
  const bytes random = random_bytes(32);
  const bytes random2 = random_bytes(32);

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

TEST(TreeKEMTest, TreeKEMPublicKey)
{
  const CipherSuite suite = CipherSuite::P256_SHA256_AES128GCM;
  const SignatureScheme scheme = SignatureScheme::Ed25519;
  const LeafCount size{ 5 };

  // Construct a full tree using add_leaf and merge
  auto pub = TreeKEMPublicKey{ suite };
  for (uint32_t i = 0; i < size.val; i++) {
    // Construct a key package and a direct path
    auto init_priv_add = HPKEPrivateKey::generate(suite);
    auto init_priv_path = HPKEPrivateKey::generate(suite);
    auto sig_priv = SignaturePrivateKey::generate(scheme);
    auto cred = Credential::basic({ 0, 1, 2, 3 }, sig_priv.public_key());
    auto index = LeafIndex(i);
    auto size = LeafCount(i + 1);

    auto kp_add =
      KeyPackage{ suite, init_priv_add.public_key(), sig_priv, cred };
    auto kp_path =
      KeyPackage{ suite, init_priv_path.public_key(), sig_priv, cred };
    auto path = DirectPath{ kp_path, {} };
    auto dp = tree_math::dirpath(NodeIndex(index), NodeCount(size));
    while (path.nodes.size() < dp.size()) {
      auto node_pub = HPKEPrivateKey::generate(suite).public_key();
      path.nodes.push_back({ node_pub, {} });
    }

    // Add the key package as a leaf
    pub.add_leaf(kp_add);
    auto found = pub.find(kp_add);
    ASSERT_TRUE(found.has_value());
    ASSERT_EQ(found.value(), index);

    auto found_kp = pub.key_package(index);
    ASSERT_TRUE(found_kp.has_value());
    ASSERT_EQ(found_kp.value(), kp_add);

    std::cout << "~~~ after add ~~~" << std::endl << pub << std::endl;

    // Merge the direct path
    pub.merge(index, path);
    found = pub.find(kp_path);
    ASSERT_TRUE(found.has_value());
    ASSERT_EQ(found.value(), index);

    found_kp = pub.key_package(index);
    ASSERT_TRUE(found_kp.has_value());
    ASSERT_EQ(found_kp.value(), kp_path);

    std::cout << "~~~ after merge ~~~" << std::endl << pub << std::endl;
  }

  // add_leaf
  // update_leaf
  // blank_path
  // merge
  // set_hash_all
  // root_hash
  // resolve
  // find
  // key_package
}

TEST(TreeKEMTest, EncapDecap)
{
  // TODO
}
