#include "messages.h"
#include "ratchet_tree.h"
#include "tls_syntax.h"
#include <gtest/gtest.h>

using namespace mls;

class RatchetTreeTest : public ::testing::Test
{
protected:
  const CipherSuite ciphersuite = CipherSuite::P256_SHA256_AES128GCM;

  const bytes secretA = from_hex("00010203");
  const bytes secretB = from_hex("04050607");
  const bytes secretC = from_hex("08090a0b");
  const bytes secretD = from_hex("0c0d0e0f");
  const bytes secretAB = from_hex(
    "c6d44cf418f610e3fe9e1d9294ff43def81c6cdcad6cbb1820cff48d3aa4355d");
  const bytes secretCD = from_hex(
    "71b92110bf135c85581c8a128f6a19c0f6aca752b0c6c91e3571899cf09b145d");
  const bytes secretABC = from_hex(
    "e0e6e3c1c64422cc76229d0c35ba817a281f8fc4014faa3e9152428a08a73ab3");
  const bytes secretABCD = from_hex(
    "4e05f3b9649335c332f8a99cbaa56e637f3dc99a446f7f6af0f92ea7756717e0");
};

TEST_F(RatchetTreeTest, OneMember)
{
  RatchetTree tree{ ciphersuite, secretA };
  ASSERT_EQ(tree.size(), 1);
  ASSERT_EQ(tree.root_secret(), secretA);
}

TEST_F(RatchetTreeTest, MultipleMembers)
{
  RatchetTree tree{ ciphersuite, { secretA, secretB, secretC, secretD } };
  ASSERT_EQ(tree.size(), 4);
  ASSERT_EQ(tree.root_secret(), secretABCD);
}

TEST_F(RatchetTreeTest, ByExtension)
{
  RatchetTree tree{ ciphersuite, secretA };

  tree.add_leaf(1, secretB);
  tree.set_path(1, secretB);

  ASSERT_EQ(tree.size(), 2);
  ASSERT_EQ(tree.root_secret(), secretAB);

  tree.add_leaf(2, secretC);
  tree.set_path(2, secretC);

  ASSERT_EQ(tree.size(), 3);
  ASSERT_EQ(tree.root_secret(), secretABC);

  tree.add_leaf(3, secretD);
  tree.set_path(3, secretD);

  ASSERT_EQ(tree.size(), 4);
  ASSERT_EQ(tree.root_secret(), secretABCD);

  RatchetTree direct{ ciphersuite, { secretA, secretB, secretC, secretD } };
  ASSERT_EQ(tree, direct);
}

TEST_F(RatchetTreeTest, BySerialization)
{
  RatchetTree before{ ciphersuite, { secretA, secretB, secretC, secretD } };
  RatchetTree after{ ciphersuite };

  tls::unmarshal(tls::marshal(before), after);
  ASSERT_EQ(before, after);
}

TEST_F(RatchetTreeTest, BySerializationWithBlanks)
{
  RatchetTree before{ ciphersuite, { secretA, secretB, secretC, secretD } };
  RatchetTree after{ ciphersuite };

  before.blank_path(1);
  tls::unmarshal(tls::marshal(before), after);
  ASSERT_EQ(before, after);
}

TEST_F(RatchetTreeTest, EncryptDecrypt)
{
  size_t size = 5;

  // trees[i] represents a tree with a private key for only leaf i
  std::vector<RatchetTree> trees(size, { ciphersuite });
  for (int i = 0; i < size; ++i) {
    auto secret = random_bytes(32);
    auto priv = DHPrivateKey::derive(ciphersuite, secret);
    auto pub = priv.public_key();

    for (int j = 0; j < size; ++j) {
      if (i == j) {
        trees[j].add_leaf(i, secret);
      } else {
        trees[j].add_leaf(i, pub);
      }
    }
  }

  for (int i = 0; i < size; ++i) {
    ASSERT_EQ(trees[i].size(), size);
    ASSERT_TRUE(trees[i].check_invariant(i));
  }

  // Verify that each member can encrypt and be decrypted by the
  // other members
  for (int i = 0; i < size; ++i) {
    auto secret = random_bytes(32);
    auto ct = trees[i].encrypt(i, secret);

    for (int j = 0; j < size; ++j) {
      if (i == j) {
        trees[j].set_path(i, secret);
      } else {
        auto info = trees[j].decrypt(i, ct);
        trees[j].merge_path(i, info);
      }
    }

    for (int j = 0; j < size; ++j) {
      ASSERT_EQ(trees[i], trees[j]);
      ASSERT_TRUE(trees[j].check_invariant(j));
    }
  }
}
