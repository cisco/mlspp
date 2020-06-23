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
  // TODO make a leaf node and access its public key
  // TODO mkae a parent node and access its public key
}

TEST(TreeKEMTest, OptionalNodeHashes)
{
  // TODO make a leaf node and access its public key
  // TODO mkae a parent node and access its public key
}
