#include "messages.h"
#include "ratchet_tree.h"
#include "tls_syntax.h"
#include <gtest/gtest.h>

#include <iostream>

using namespace mls;

class RatchetTreeTest : public ::testing::Test
{
protected:
  const CipherSuite suite = CipherSuite::P256_SHA256_AES128GCM;

  const bytes secretA = from_hex("00010203");
  const bytes secretB = from_hex("04050607");
  const bytes secretC = from_hex("08090a0b");
  const bytes secretD = from_hex("0c0d0e0f");

  bytes secretAn;
  bytes secretAB;
  bytes secretCD;
  bytes secretABC;
  bytes secretABCD;

  RatchetTreeTest()
  {
    auto secretA0n = hkdf_expand_label(suite, secretA, "node", {}, 32);
    secretAn = secretA0n;

    auto secretB1p = hkdf_expand_label(suite, secretB, "path", {}, 32);
    auto secretB1n = hkdf_expand_label(suite, secretB1p, "node", {}, 32);
    secretAB = secretB1n;

    auto secretD1p = hkdf_expand_label(suite, secretD, "path", {}, 32);
    auto secretD1n = hkdf_expand_label(suite, secretD1p, "node", {}, 32);
    secretCD = secretD1n;

    auto secretC1p = hkdf_expand_label(suite, secretC, "path", {}, 32);
    auto secretC1n = hkdf_expand_label(suite, secretC1p, "node", {}, 32);
    secretABC = secretC1n;

    auto secretD2p = hkdf_expand_label(suite, secretD1p, "path", {}, 32);
    auto secretD2n = hkdf_expand_label(suite, secretD2p, "node", {}, 32);
    secretABCD = secretD2n;

    std::cout << "B1p: " << secretB1p << std::endl;
    std::cout << "B1n: " << secretB1n << std::endl;
    std::cout << "C1p: " << secretC1p << std::endl;
    std::cout << "C1n: " << secretC1n << std::endl;
    std::cout << "D1p: " << secretD1p << std::endl;
    std::cout << "D1n: " << secretD1n << std::endl;
    std::cout << "D2p: " << secretD2p << std::endl;
    std::cout << "D2n: " << secretD2n << std::endl;
  }
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

  tree.add_leaf(1, secretB);
  tree.set_path(1, secretB);

  std::cout << "rootAB: " << tree.root_secret() << std::endl;
  ASSERT_EQ(tree.size(), 2);
  ASSERT_EQ(tree.root_secret(), secretAB);
  RatchetTree directAB{ suite, { secretA, secretB } };
  ASSERT_EQ(tree, directAB);

  tree.add_leaf(2, secretC);
  tree.set_path(2, secretC);

  std::cout << "rootABC: " << tree.root_secret() << std::endl;
  ASSERT_EQ(tree.size(), 3);
  ASSERT_EQ(tree.root_secret(), secretABC);

  tree.add_leaf(3, secretD);
  tree.set_path(3, secretD);

  std::cout << "rootABCD: " << tree.root_secret() << std::endl;
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

  before.blank_path(1);
  tls::unmarshal(tls::marshal(before), after);
  ASSERT_EQ(before, after);
}

TEST_F(RatchetTreeTest, EncryptDecrypt)
{
  size_t size = 5;

  // trees[i] represents a tree with a private key for only leaf i
  std::vector<RatchetTree> trees(size, { suite });
  for (int i = 0; i < size; ++i) {
    auto secret = random_bytes(32);
    auto node_secret = hkdf_expand_label(suite, secret, "node", {}, 32);
    auto priv = DHPrivateKey::derive(suite, node_secret);
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
    EXPECT_EQ(trees[i], trees[0]);
    ASSERT_EQ(trees[i].size(), size);
    ASSERT_TRUE(trees[i].check_invariant(i));
  }

  // Verify that each member can encrypt and be decrypted by the
  // other members
  for (int i = 0; i < size; ++i) {
    auto secret = random_bytes(32);
    auto ct = trees[i].encrypt(i, secret);
    std::cout << "src: " << trees[i] << std::endl;

    for (int j = 0; j < size; ++j) {
      if (i == j) {
        trees[j].set_path(i, secret);
      } else {
        std::cout << "dst: " << trees[j] << std::endl;
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
