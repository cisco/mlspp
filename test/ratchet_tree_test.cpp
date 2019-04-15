#include "messages.h"
#include "ratchet_tree.h"
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
};

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
  RatchetTree tree{ suite, secretA };

  tree.add_leaf(LeafIndex{ 1 }, secretB);
  tree.set_path(LeafIndex{ 1 }, secretB);

  ASSERT_EQ(tree.size(), 2);
  ASSERT_EQ(tree.root_secret(), secretAB);
  RatchetTree directAB{ suite, { secretA, secretB } };
  ASSERT_EQ(tree, directAB);

  tree.add_leaf(LeafIndex{ 2 }, secretC);
  tree.set_path(LeafIndex{ 2 }, secretC);

  ASSERT_EQ(tree.size(), 3);
  ASSERT_EQ(tree.root_secret(), secretABC);

  tree.add_leaf(LeafIndex{ 3 }, secretD);
  tree.set_path(LeafIndex{ 3 }, secretD);

  ASSERT_EQ(tree.size(), 4);
  ASSERT_EQ(tree.root_secret(), secretABCD);

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
