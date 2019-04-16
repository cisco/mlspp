#include "messages.h"
#include "ratchet_tree.h"
#include "test_vectors.h"
#include "tls_syntax.h"
#include <gtest/gtest.h>

using namespace mls;

class RatchetTreeTest : public ::testing::Test
{
protected:
  const CipherSuite suite = CipherSuite::P256_SHA256_AES128GCM;

  const bytes secretA = from_hex("00010203");
  const bytes secretB = from_hex("04050607");
  const bytes secretC = from_hex("08090a0b");
  const bytes secretD = from_hex("0c0d0e0f");

  const bytes secretAn = from_hex(
    "6454ab64c6af8091859b13da01f6154820fef5f1b17d7c2b8b242d03b7bd5fc3");
  const bytes secretAB = from_hex(
    "2ccbf0bd1209c2f7b4095726897aa8487b723492f19b7f6c3e4a415df79d00d0");
  const bytes secretCD = from_hex(
    "293926d4d12149366ff84fabeb3d699558e39f333a116baf6a60a2588e1c601a");
  const bytes secretABC = from_hex(
    "31ce14ca8317bf564b12706367b8423ed69a520fad6c0acd2608da65d0bb2916");
  const bytes secretABCD = from_hex(
    "43793000dbf64b8606bfcd75c23b57f3096053eafdf182357fd013fbf8b9834a");

  // Manually computed via a Python script
  const bytes hashA = from_hex(
    "971c7d829997b7dd79bc9c2450aeba2aa63c26bba2488091c45f9b4240be569b");
  const bytes hashB = from_hex(
    "c46ca31e392ccd3b0d232bd43b7a40e8b755825d46359c3f089343f7c25f8414");
  const bytes hashC = from_hex(
    "2c9c435697ed4b30cce1991107c2a841675789982b3415bbaf17e9265b1355ff");
  const bytes hashD = from_hex(
    "c24512dbd37d0c8f00054a8e135141db57fcc48478e881fef8316910e5f6797b");
  const bytes hashAB = from_hex(
    "610c949d5e73aca1d138ca4b74523fc8974e1734f94364d56de10094fcbc59b2");
  const bytes hashCD = from_hex(
    "a280eeb4461a33cec3b3a01c0a8f2da5cc25764c0a2415a850931ce7dc4831d9");
  const bytes hashABC = from_hex(
    "146e80ab5bb121b357e928083d894538a640d17303a3633e622bb0355417e309");
  const bytes hashABCD = from_hex(
    "4564f8ae24f7f13a88aa1bf40d93bbbb88f84e03e217dec36128c631d5246888");

  const TreeTestVectors& tv;

  RatchetTreeTest()
    : tv(TestLoader<TreeTestVectors>::get())
  {}

  void interop(const TreeTestVectors::TestCase& tc, CipherSuite test_suite)
  {
    test::TestRatchetTree tree{ test_suite };

    // Add the leaves
    int tci = 0;
    for (uint32_t i = 0; i < tv.leaf_secrets.size(); ++i, ++tci) {
      tree.add_leaf(LeafIndex{ i }, tv.leaf_secrets[i]);
      tree.set_path(LeafIndex{ i }, tv.leaf_secrets[i]);

      auto vec = tc[tci];
      auto nodes = tree.nodes();
      ASSERT_EQ(vec.size(), nodes.size());

      for (int j = 0; j < vec.size(); ++j) {
        ASSERT_EQ(vec[j].hash, nodes[j].hash());
        ASSERT_EQ(!!vec[j].secret, !nodes[j].blank());
        if (!nodes[j].blank()) {
          ASSERT_EQ(vec[j].secret.value(), nodes[j]->secret().value());
          ASSERT_EQ(vec[j].public_key.value(),
                    nodes[j]->public_key().to_bytes());
        }
      }
    }
  }
};

TEST_F(RatchetTreeTest, Interop)
{
  interop(tv.case_p256, CipherSuite::P256_SHA256_AES128GCM);
  interop(tv.case_x25519, CipherSuite::X25519_SHA256_AES128GCM);
}

TEST_F(RatchetTreeTest, OneMember)
{
  RatchetTree tree{ suite, secretA };
  ASSERT_EQ(tree.size(), 1);
  ASSERT_EQ(tree.root_secret(), secretAn);
}

TEST_F(RatchetTreeTest, MultipleMembers)
{
  RatchetTree tree{ suite, { secretA, secretB, secretC, secretD } };
  ASSERT_EQ(tree.size(), 4);
  ASSERT_EQ(tree.root_secret(), secretABCD);
}

TEST_F(RatchetTreeTest, ByExtension)
{
  RatchetTree tree{ suite };

  // Add A
  tree.add_leaf(LeafIndex{ 0 }, secretA);
  ASSERT_EQ(tree.root_secret(), secretAn);
  ASSERT_EQ(tree.root_hash(), hashA);

  // Add B
  tree.add_leaf(LeafIndex{ 1 }, secretB);
  tree.set_path(LeafIndex{ 1 }, secretB);

  ASSERT_EQ(tree.size(), 2);
  ASSERT_EQ(tree.root_secret(), secretAB);
  ASSERT_EQ(tree.root_hash(), hashAB);

  RatchetTree directAB{ suite, { secretA, secretB } };
  ASSERT_EQ(tree, directAB);

  // Add C
  tree.add_leaf(LeafIndex{ 2 }, secretC);
  tree.set_path(LeafIndex{ 2 }, secretC);

  ASSERT_EQ(tree.size(), 3);
  ASSERT_EQ(tree.root_secret(), secretABC);
  ASSERT_EQ(tree.root_hash(), hashABC);

  RatchetTree directABC{ suite, { secretA, secretB, secretC } };
  ASSERT_EQ(tree, directABC);

  // Add D
  tree.add_leaf(LeafIndex{ 3 }, secretD);
  tree.set_path(LeafIndex{ 3 }, secretD);

  ASSERT_EQ(tree.size(), 4);
  ASSERT_EQ(tree.root_secret(), secretABCD);
  ASSERT_EQ(tree.root_hash(), hashABCD);

  RatchetTree direct{ suite, { secretA, secretB, secretC, secretD } };
  ASSERT_EQ(tree, direct);
}

TEST_F(RatchetTreeTest, BySerialization)
{
  RatchetTree before{ suite, { secretA, secretB, secretC, secretD } };
  RatchetTree after{ suite };

  tls::unmarshal(tls::marshal(before), after);
  ASSERT_EQ(before, after);
}

TEST_F(RatchetTreeTest, BySerializationWithBlanks)
{
  RatchetTree before{ suite, { secretA, secretB, secretC, secretD } };
  RatchetTree after{ suite };

  before.blank_path(LeafIndex{ 1 });
  tls::unmarshal(tls::marshal(before), after);
  ASSERT_EQ(before, after);
}

TEST_F(RatchetTreeTest, EncryptDecrypt)
{
  size_t size = 5;

  // trees[i] represents a tree with a private key for only leaf i
  std::vector<RatchetTree> trees(size, { suite });
  for (LeafIndex i{ 0 }; i.val < size; i.val += 1) {
    auto secret = random_bytes(32);
    auto priv = DHPrivateKey::node_derive(suite, secret);
    auto pub = priv.public_key();

    for (uint32_t j = 0; j < size; j += 1) {
      if (i.val == j) {
        trees[j].add_leaf(i, secret);
      } else {
        trees[j].add_leaf(i, pub);
      }
    }
  }

  for (uint32_t i = 0; i < size; ++i) {
    EXPECT_EQ(trees[i], trees[0]);
    ASSERT_EQ(trees[i].size(), size);
    ASSERT_TRUE(trees[i].check_invariant(LeafIndex{ i }));
  }

  // Verify that each member can encrypt and be decrypted by the
  // other members
  for (LeafIndex i{ 0 }; i.val < size; i.val += 1) {
    auto secret = random_bytes(32);
    auto ct = trees[i.val].encrypt(i, secret);

    for (int j = 0; j < size; ++j) {
      if (i.val == j) {
        trees[j].set_path(i, secret);
      } else {
        auto info = trees[j].decrypt(i, ct);
        trees[j].merge_path(i, info);
      }
    }

    for (uint32_t j = 0; j < size; ++j) {
      ASSERT_EQ(trees[i.val], trees[j]);
      ASSERT_TRUE(trees[j].check_invariant(LeafIndex{ j }));
    }
  }
}
